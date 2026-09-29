/*
This module selects buffered or paged storage from one regular-file handle.
The paged form reads small windows at u64 offsets.
The handle keeps the opened source stable when its pathname changes.
Metadata checks reject detected source changes before or after each read.
Staged writes stream logical spans without loading the complete source.
*/
use std::collections::{HashSet, VecDeque};
use std::ffi::c_int;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/*
Buffered storage accepts sources through 64 MiB.
Each paged read uses at most 64 KiB of owned memory.
Each logical splice removes and inserts at most 64 MiB.
One live layout uses at most 65 MiB and 4,096 spans.
O_NONBLOCK lets open return before a FIFO supplies a writer.
The metadata check then rejects every nonregular source.

SEEK_DATA and SEEK_HOLE identify allocated source extents for sparse staging.
*/
pub(crate) const BUFFERED_FILE_LIMIT: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_READ_BYTES: usize = 64 * 1024;
const BLOCK_BYTES: usize = 64 * 1024 * 1024;
const EDIT_HISTORY_LIMIT: usize = 256;
const EDIT_HISTORY_BYTES: usize = 130 * 1024 * 1024;
const CHANGED_BYTES_LIMIT: usize = 65 * 1024 * 1024;
const CHANGED_RANGES_LIMIT: usize = 4096;
const O_NONBLOCK: i32 = 0o4000;
const SEEK_DATA: c_int = 3;
const SEEK_HOLE: c_int = 4;
const ENXIO: i32 = 6;
const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;
const EOPNOTSUPP: i32 = 95;

/*
Linux exposes sparse-file extents through lseek on the owned source descriptor.
The project target uses a signed 64-bit off_t, which matches the supported file-offset range.
Extent visibility depends on the source filesystem and its SEEK_DATA and SEEK_HOLE implementation.
Unsupported extent queries use a bounded scan that leaves all-zero chunks sparse.
Other query failures keep their operating-system errors.
*/
unsafe extern "C" {
    fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64;
}

/*
Logical spans refer to immutable source bytes or immutable changed bytes.
Source spans keep u64 offsets into the opened descriptor.
Memory spans share one allocation when a logical edit splits their range.
The layout length describes the current view without changing the source stamp.
*/
#[derive(Clone)]
enum DataSpan {
    Source {
        start: u64,
        len: u64,
    },
    Memory {
        bytes: Arc<[u8]>,
        start: usize,
        len: usize,
    },
}

/*
These methods provide checked span lengths and slices for splice planning.
Each slice keeps the same immutable backing storage and adjusts its start.
*/
impl DataSpan {
    /*
    This method returns the logical length of either span kind.
    Memory lengths convert exactly because usize fits in u64 on this target.
    */
    fn len(&self) -> u64 {
        match self {
            Self::Source { len, .. } => *len,
            Self::Memory { len, .. } => *len as u64,
        }
    }

    /*
    This method creates a checked subrange of one span.
    The caller supplies a contained range from the logical layout walk.
    A failure leaves the source span and current layout unchanged.
    */
    fn slice(&self, start: u64, len: u64) -> io::Result<Self> {
        match self {
            Self::Source { start: source, .. } => Ok(Self::Source {
                start: source.checked_add(start).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "The source span exceeds the address range.",
                    )
                })?,
                len,
            }),
            Self::Memory {
                bytes,
                start: memory,
                ..
            } => {
                let start = usize::try_from(start)
                    .ok()
                    .and_then(|start| memory.checked_add(start))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "The memory span exceeds the address range.",
                        )
                    })?;
                let len = usize::try_from(len).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "The memory span exceeds the address range.",
                    )
                })?;
                Ok(Self::Memory {
                    bytes: Arc::clone(bytes),
                    start,
                    len,
                })
            }
        }
    }
}

/*
One layout orders all source and memory spans in their current logical sequence.
Splice planning creates a complete replacement layout before state changes.
*/
#[derive(Clone)]
struct Layout {
    spans: Vec<DataSpan>,
    len: u64,
}

/*
The edit cursor stores all Hex position state for one operation boundary.
Undo restores the before cursor, and redo restores the after cursor.
The u64 fields retain positions above the process address range.
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PagedEditCursor {
    pub(crate) offset: u64,
    pub(crate) top: u64,
    pub(crate) low_nibble: bool,
}

/*
One history record stores the layout that is not currently active.
Undo and redo swap this alternate layout with the current layout.
Hex grouping retains the first cursor and updates the final cursor.
*/
struct EditRecord {
    alternate: Layout,
    before_cursor: PagedEditCursor,
    after_cursor: PagedEditCursor,
    hex_group: bool,
    group_start: u64,
    group_len: usize,
}

/*
The source stamp records native identity, length, and nanosecond Linux change times.
The modification time identifies data updates.
The change time also identifies metadata updates and restored modification times.
These checks cannot exclude every concurrent writer on Linux.
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceStamp {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/*
These methods capture and compare the metadata fields used for source validation.
A mismatch stops the read lifecycle and requires a new open.
*/
impl SourceStamp {
    /*
    This conversion captures one metadata sample from the owned descriptor.
    Later reads compare a new sample with these exact fields.
    */
    pub(crate) fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    /*
    This check gives length changes specific errors.
    A time change reports a general external source change.
    The caller must reopen the source before another read.
    */
    pub(crate) fn validate(self, current: Self) -> io::Result<()> {
        if current.device != self.device || current.inode != self.inode {
            return Err(io::Error::other(
                "The source identity changed. Reopen the source.",
            ));
        }
        if current.len < self.len {
            return Err(io::Error::other(
                "The source shrank outside the viewer. Reopen the source.",
            ));
        }
        if current.len > self.len {
            return Err(io::Error::other(
                "The source grew outside the viewer. Reopen the source.",
            ));
        }
        if current.modified_seconds != self.modified_seconds
            || current.modified_nanoseconds != self.modified_nanoseconds
            || current.changed_seconds != self.changed_seconds
            || current.changed_nanoseconds != self.changed_nanoseconds
        {
            return Err(io::Error::other(
                "The source changed outside the viewer. Reopen the source.",
            ));
        }
        Ok(())
    }
}

/*
OpenedSource returns one storage form from one opened descriptor.
Small sources publish their complete bytes only after source validation.
Buffered sources retain the read descriptor so Save can verify the accepted identity.
The retained source stamp binds buffered Compare validation to the accepted bytes.
Large sources keep the same descriptor for bounded reads.
*/
pub(crate) enum OpenedSource {
    Buffered {
        data: Vec<u8>,
        file: File,
        stamp: SourceStamp,
    },
    Paged(PagedFile),
}

/*
A read window owns its bytes independently from the source and later windows.
The start field keeps the u64 logical position with the bounded byte buffer.
*/
#[derive(Debug)]
pub(crate) struct ReadWindow {
    pub(crate) start: u64,
    pub(crate) bytes: Box<[u8]>,
}

/*
PagedFile owns one read-only descriptor, its native path, and open-time metadata.
Its layout maps the current logical bytes to source and memory spans.
The history owns alternate layouts while edit mode is active.
The component stores no display text or pathname conversion.
*/
pub(crate) struct PagedFile {
    file: File,
    path: PathBuf,
    stamp: SourceStamp,
    layout: Layout,
    editing: bool,
    undo_history: VecDeque<EditRecord>,
    redo_history: VecDeque<EditRecord>,
    history_bytes: usize,
}

/*
These methods open, validate, classify, read, and stage one owned regular-file descriptor.
All published data passes source validation before and after its source operation.
*/
impl PagedFile {
    /*
    Open receives a native Path and passes the path directly to Linux.
    O_NONBLOCK prevents a nonregular FIFO from delaying source validation.
    A successful result owns one regular-file descriptor and one source stamp.
    */
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The source is not a regular file.",
            ));
        }
        let stamp = SourceStamp::from_metadata(&metadata);
        let spans = (stamp.len != 0)
            .then_some(DataSpan::Source {
                start: 0,
                len: stamp.len,
            })
            .into_iter()
            .collect();
        let layout = Layout {
            spans,
            len: stamp.len,
        };
        let history_bytes = Self::layouts_cost(std::iter::once(&layout))?;
        Ok(Self {
            file,
            path: path.to_owned(),
            stamp,
            layout,
            editing: false,
            undo_history: VecDeque::new(),
            redo_history: VecDeque::new(),
            history_bytes,
        })
    }

    /*
    Length reports the current logical length after any in-memory splice.
    The source stamp keeps the separate captured file length for validation.
    */
    pub(crate) fn len(&self) -> u64 {
        self.layout.len
    }

    /*
    This check compares another open descriptor with the captured source stamp.
    Save preparation uses the result before it copies metadata or publishes bytes.
    */
    pub(crate) fn validate_descriptor(&self, file: &File) -> io::Result<()> {
        self.stamp
            .validate(SourceStamp::from_metadata(&file.metadata()?))
    }

    /*
    This identity check confirms that a reopened publication owns the prepared staging inode.
    It does not accept pathname text or infer identity from file contents.
    */
    pub(crate) fn has_identity(&self, device: u64, inode: u64) -> io::Result<bool> {
        let metadata = self.file.metadata()?;
        Ok(metadata.dev() == device && metadata.ino() == inode)
    }

    /*
    Validation compares the native pathname and descriptor with the opened identity.
    The pathname check reports replacement before descriptor metadata changes.
    A replacement pathname cannot redirect the descriptor to another source.
    */
    pub(crate) fn validate(&self) -> io::Result<()> {
        let path_metadata = fs::metadata(&self.path)?;
        if !path_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The source path is not a regular file. Reopen the source.",
            ));
        }
        let current = SourceStamp::from_metadata(&path_metadata);
        if current.device != self.stamp.device || current.inode != self.stamp.inode {
            return Err(io::Error::other(
                "The source path identifies a different file. Reopen the source.",
            ));
        }
        self.stamp
            .validate(SourceStamp::from_metadata(&self.file.metadata()?))?;
        Ok(())
    }

    /*
    This conversion reads a selected small source from the descriptor used for classification.
    Bounded sequential reads preserve short-content Linux virtual regular files.
    The extra byte detects growth beyond the buffered limit without a file-sized allocation.
    Source validation completes before the byte buffer, read descriptor, and source stamp become available.
    */
    fn into_buffered(mut self) -> io::Result<OpenedSource> {
        let limit = usize::try_from(BUFFERED_FILE_LIMIT).unwrap();
        let expected = usize::try_from(self.stamp.len).unwrap_or(limit).min(limit);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected)
            .map_err(|_| io::Error::other("Cannot allocate the buffered source."))?;

        let mut chunk = [0_u8; MAX_READ_BYTES];
        loop {
            let remaining = limit.saturating_add(1).saturating_sub(bytes.len());
            if remaining == 0 {
                break;
            }
            let request = remaining.min(chunk.len());
            match self.file.read(&mut chunk[..request]) {
                Ok(0) => break,
                Ok(count) => {
                    bytes
                        .try_reserve_exact(count)
                        .map_err(|_| io::Error::other("Cannot allocate the buffered source."))?;
                    bytes.extend_from_slice(&chunk[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if bytes.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "The source exceeds the 64 MiB buffered limit during opening.",
            ));
        }

        self.validate()?;
        Ok(OpenedSource::Buffered {
            data: bytes,
            file: self.file,
            stamp: self.stamp,
        })
    }

    /*
    This read rejects invalid limits and logical offsets before memory allocation.
    A valid request is clipped at logical EOF and receives one fallibly allocated buffer.
    The layout walk combines source and immutable memory spans into that buffer.
    The 64 KiB cap makes the clipped length exact in u64 and usize.
    The final validation prevents publication of a detected stale window.
    */
    pub(crate) fn read_window(&self, start: u64, len: usize) -> io::Result<ReadWindow> {
        if len > MAX_READ_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "A read window cannot exceed 64 KiB.",
            ));
        }

        self.validate()?;
        let available = self.layout.len.checked_sub(start).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The read offset is past the file end.",
            )
        })?;
        let allocation_len = available.min(len as u64) as usize;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(allocation_len)
            .map_err(|_| io::Error::other("Cannot allocate the read window."))?;
        bytes.resize(allocation_len, 0);
        self.read_merged_unchecked_at(start, &mut bytes)?;
        self.validate()?;

        Ok(ReadWindow {
            start,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /*
    This helper fills one validated logical range from its ordered spans.
    Source spans use positioned descriptor reads without changing the shared file offset.
    Memory spans copy the selected bytes from their immutable shared allocation.
    Checked layout arithmetic prevents a wrapped logical range.
    */
    fn read_merged_unchecked_at(&self, start: u64, output: &mut [u8]) -> io::Result<()> {
        /*
        First, calculate and check the complete requested logical range.
        The range check protects all later usize conversions and output slices.
        */
        let end = start.checked_add(output.len() as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The read range exceeds the address range.",
            )
        })?;
        if end > self.layout.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "The read range extends past the file end.",
            ));
        }

        /*
        Next, walk the ordered spans and copy each overlap to its output position.
        The logical cursor connects each span boundary to the next span.
        */
        let mut logical = 0_u64;
        for span in &self.layout.spans {
            let span_end = logical.checked_add(span.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The logical layout exceeds the address range.",
                )
            })?;
            let overlap_start = logical.max(start);
            let overlap_end = span_end.min(end);
            if overlap_start < overlap_end {
                let span_offset = overlap_start - logical;
                let target = usize::try_from(overlap_start - start).unwrap();
                let len = usize::try_from(overlap_end - overlap_start).unwrap();
                match span {
                    DataSpan::Source { start: source, .. } => {
                        let source = source.checked_add(span_offset).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "The source read exceeds the address range.",
                            )
                        })?;
                        self.file
                            .read_exact_at(&mut output[target..target + len], source)?;
                    }
                    DataSpan::Memory {
                        bytes,
                        start: memory,
                        ..
                    } => {
                        let source = memory
                            .checked_add(usize::try_from(span_offset).unwrap())
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "The memory read exceeds the address range.",
                                )
                            })?;
                        let source_end = source.checked_add(len).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "The memory read exceeds the address range.",
                            )
                        })?;
                        let selected = bytes.get(source..source_end).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "The memory span is outside its allocation.",
                            )
                        })?;
                        output[target..target + len].copy_from_slice(selected);
                    }
                }
            }
            logical = span_end;
            if logical >= end {
                break;
            }
        }
        Ok(())
    }

    /*
    This check proves that each logical span fits its backing source or memory allocation.
    It also proves that the ordered span lengths equal the recorded logical length.
    The signed ceiling keeps every later Linux file offset representable.
    A failure occurs before the staging file changes.
    */
    fn validate_staged_layout(&self) -> io::Result<()> {
        if self.layout.len > i64::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The staged file length exceeds the supported Linux file-offset range.",
            ));
        }

        let mut logical = 0_u64;
        for span in &self.layout.spans {
            match span {
                DataSpan::Source { start, len } => {
                    start
                        .checked_add(*len)
                        .filter(|end| *end <= self.stamp.len)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "A source span is outside the captured source.",
                            )
                        })?;
                }
                DataSpan::Memory { bytes, start, len } => {
                    start
                        .checked_add(*len)
                        .filter(|end| *end <= bytes.len())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "A memory span is outside its allocation.",
                            )
                        })?;
                }
            }
            logical = logical.checked_add(span.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The staged layout exceeds the address range.",
                )
            })?;
        }
        if logical != self.layout.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The staged layout length is inconsistent.",
            ));
        }
        Ok(())
    }

    /*
    This helper asks Linux for the next source data or hole offset.
    Positioned reads do not use the shared offset changed by lseek.
    The caller handles ENXIO only where Linux defines the result as normal completion.
    */
    fn seek_extent(&self, offset: u64, whence: c_int) -> io::Result<u64> {
        let offset = i64::try_from(offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The source extent exceeds the supported Linux file-offset range.",
            )
        })?;
        // SAFETY: The owned file keeps the descriptor valid for this call.
        let result = unsafe { lseek(self.file.as_raw_fd(), offset, whence) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as u64)
        }
    }

    /*
    This helper copies one source range to its mapped logical destination.
    The fixed stack buffer keeps every source read and destination write at 64 KiB or less.
    All-zero chunks stay sparse even when a filesystem reports coarse data extents.
    Standard exact positioned I/O handles interruptions and incomplete operations.
    */
    fn copy_source_extent(
        &self,
        output: &File,
        mut source: u64,
        mut destination: u64,
        end: u64,
    ) -> io::Result<()> {
        let mut chunk = [0_u8; MAX_READ_BYTES];
        while source < end {
            let count = usize::try_from((end - source).min(MAX_READ_BYTES as u64)).unwrap();
            self.file.read_exact_at(&mut chunk[..count], source)?;
            if chunk[..count].iter().any(|byte| *byte != 0) {
                output.write_all_at(&chunk[..count], destination)?;
            }
            source = source.checked_add(count as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The source extent exceeds the address range.",
                )
            })?;
            destination = destination.checked_add(count as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The staged destination exceeds the address range.",
                )
            })?;
        }
        Ok(())
    }

    /*
    This fallback scans one source span when its filesystem does not expose sparse extents.
    The fixed buffer bounds memory and each positioned read to 64 KiB.
    All-zero chunks need no write because the fresh staging file already contains a hole.
    Nonzero chunks preserve exact bytes and complete writes.
    */
    fn write_source_span_bounded(
        &self,
        output: &File,
        source: u64,
        len: u64,
        destination: u64,
    ) -> io::Result<()> {
        let end = source.checked_add(len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The source span exceeds the address range.",
            )
        })?;
        self.copy_source_extent(output, source, destination, end)
    }

    /*
    These Linux errors mean that the descriptor or filesystem lacks usable extent queries.
    The staging writer can then preserve bytes through the bounded zero-aware scan.
    Other errors identify actual query failures and must remain unchanged.
    */
    fn extent_query_is_unsupported(error: &io::Error) -> bool {
        matches!(error.raw_os_error(), Some(EINVAL | ENOSYS | EOPNOTSUPP))
    }

    /*
    This helper maps allocated parts of one source span into the staging file.
    SEEK_DATA skips source holes, and SEEK_HOLE bounds each copied data extent.
    ENXIO from SEEK_DATA means that the source span has no more allocated data.
    An unsupported query selects the bounded zero-aware scan for the complete span.
    Every accepted extent result must move forward to prevent an endless walk.
    */
    fn write_source_span_with<F>(
        &self,
        output: &File,
        source_start: u64,
        len: u64,
        logical_start: u64,
        mut seek: F,
    ) -> io::Result<()>
    where
        F: FnMut(u64, c_int) -> io::Result<u64>,
    {
        let source_end = source_start.checked_add(len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The source span exceeds the address range.",
            )
        })?;
        let mut search = source_start;
        while search < source_end {
            let data = match seek(search, SEEK_DATA) {
                Ok(data) => data,
                Err(error) if error.raw_os_error() == Some(ENXIO) => break,
                Err(error) if Self::extent_query_is_unsupported(&error) => {
                    return self.write_source_span_bounded(
                        output,
                        source_start,
                        len,
                        logical_start,
                    );
                }
                Err(error) => return Err(error),
            };
            if data < search {
                return Err(io::Error::other(
                    "The source extent query did not move forward.",
                ));
            }
            if data >= source_end {
                break;
            }

            let hole = match seek(data, SEEK_HOLE) {
                Ok(hole) => hole,
                Err(error) if Self::extent_query_is_unsupported(&error) => {
                    return self.write_source_span_bounded(
                        output,
                        source_start,
                        len,
                        logical_start,
                    );
                }
                Err(error) => return Err(error),
            };
            if hole <= data {
                return Err(io::Error::other(
                    "The source hole query did not move forward.",
                ));
            }
            let extent_end = hole.min(source_end);
            let destination = logical_start
                .checked_add(data - source_start)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "The staged destination exceeds the address range.",
                    )
                })?;
            self.copy_source_extent(output, data, destination, extent_end)?;
            search = extent_end;
        }
        Ok(())
    }

    /*
    This helper writes one immutable memory span into its exact logical destination.
    Memory bytes always override a source hole, including an all-zero replacement.
    Each positioned write stays within the shared allocation and the 64 KiB operation bound.
    */
    fn write_memory_span(output: &File, bytes: &[u8], mut destination: u64) -> io::Result<()> {
        for chunk in bytes.chunks(MAX_READ_BYTES) {
            output.write_all_at(chunk, destination)?;
            destination = destination.checked_add(chunk.len() as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The staged destination exceeds the address range.",
                )
            })?;
        }
        Ok(())
    }

    /*
    This helper streams the current logical layout with one extent-query function.
    The caller supplies a fresh, empty regular file that does not identify the source.
    Validation and range checks occur before the first output change.
    The final source check prevents publication of bytes from a detected changed source.
    The method cannot change edit layouts, history, cursors, grouping, or the source stamp.
    */
    fn write_staged_with<F>(&self, output: &File, mut seek: F) -> io::Result<()>
    where
        F: FnMut(u64, c_int) -> io::Result<u64>,
    {
        /*
        First, reject invalid staging identities and contents before any truncation or write.
        Descriptor identity checks do not depend on a pathname or text conversion.
        */
        let output_metadata = output.metadata()?;
        if !output_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The staging output is not a regular file.",
            ));
        }
        if output_metadata.dev() == self.stamp.device && output_metadata.ino() == self.stamp.inode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The staging output identifies the source file.",
            ));
        }
        if output_metadata.len() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "The staging output is not empty.",
            ));
        }
        self.validate_staged_layout()?;
        self.validate()?;

        /*
        Next, set the final length so skipped source holes and trailing holes stay sparse.
        The span walk maps source extents and memory bytes to checked logical positions.
        */
        output.set_len(self.layout.len)?;
        let mut logical = 0_u64;
        for span in &self.layout.spans {
            match span {
                DataSpan::Source { start, len } => {
                    self.write_source_span_with(output, *start, *len, logical, &mut seek)?;
                }
                DataSpan::Memory { bytes, start, len } => {
                    let end = start.checked_add(*len).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "The memory span exceeds the address range.",
                        )
                    })?;
                    let selected = bytes.get(*start..end).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "The memory span is outside its allocation.",
                        )
                    })?;
                    Self::write_memory_span(output, selected, logical)?;
                }
            }
            logical = logical.checked_add(span.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The staged layout exceeds the address range.",
                )
            })?;
        }

        /*
        Finally, flush the complete staging file before the second source validation.
        A failure leaves only the private output with possible partial bytes.
        */
        output.sync_all()?;
        self.validate()
    }

    /*
    This public component operation supplies real Linux queries to the staging helper.
    Guarded publication code can use the completed private file without a full source copy.
    */
    pub(crate) fn write_staged(&self, output: &File) -> io::Result<()> {
        self.write_staged_with(output, |offset, whence| self.seek_extent(offset, whence))
    }

    /*
    This operation streams the captured original source into an independent empty staging file.
    Sparse extents and the bounded fallback use the same source-copy path as logical staging.
    The edit layout and both history stacks remain unchanged.
    */
    pub(crate) fn write_original(&self, output: &File) -> io::Result<()> {
        let output_metadata = output.metadata()?;
        if !output_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The staging output is not a regular file.",
            ));
        }
        if output_metadata.dev() == self.stamp.device && output_metadata.ino() == self.stamp.inode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The staging output identifies the source file.",
            ));
        }
        if output_metadata.len() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "The staging output is not empty.",
            ));
        }
        self.validate()?;
        output.set_len(self.stamp.len)?;
        self.write_source_span_with(output, 0, self.stamp.len, 0, |offset, whence| {
            self.seek_extent(offset, whence)
        })?;
        output.sync_all()?;
        self.validate()
    }

    /*
    This verifier compares the captured source with one prepared backup in bounded chunks.
    It validates source identity around the complete comparison and rejects partial backup data.
    */
    pub(crate) fn verify_original(&self, backup: &File) -> io::Result<()> {
        let metadata = backup.metadata()?;
        if !metadata.is_file() || metadata.len() != self.stamp.len {
            return Err(io::Error::other(
                "The staged backup does not match the original source length.",
            ));
        }
        self.validate()?;
        let mut source = [0_u8; MAX_READ_BYTES];
        let mut staged = [0_u8; MAX_READ_BYTES];
        let mut offset = 0_u64;
        while offset < self.stamp.len {
            let count =
                usize::try_from((self.stamp.len - offset).min(MAX_READ_BYTES as u64)).unwrap();
            self.file.read_exact_at(&mut source[..count], offset)?;
            backup.read_exact_at(&mut staged[..count], offset)?;
            if source[..count] != staged[..count] {
                return Err(io::Error::other(
                    "The staged backup does not match the original source bytes.",
                ));
            }
            offset += count as u64;
        }
        self.validate()
    }

    /*
    This verifier compares one prepared logical file with the current span layout.
    Fixed buffers keep both reads bounded while memory and source spans share one comparison path.
    */
    pub(crate) fn verify_staged(&self, staged: &File) -> io::Result<()> {
        let metadata = staged.metadata()?;
        if !metadata.is_file() || metadata.len() != self.layout.len {
            return Err(io::Error::other(
                "The staged file does not match the logical source length.",
            ));
        }
        self.validate()?;
        let mut expected = [0_u8; MAX_READ_BYTES];
        let mut actual = [0_u8; MAX_READ_BYTES];
        let mut offset = 0_u64;
        while offset < self.layout.len {
            let count =
                usize::try_from((self.layout.len - offset).min(MAX_READ_BYTES as u64)).unwrap();
            self.read_merged_unchecked_at(offset, &mut expected[..count])?;
            staged.read_exact_at(&mut actual[..count], offset)?;
            if expected[..count] != actual[..count] {
                return Err(io::Error::other(
                    "The staged file does not match the logical source bytes.",
                ));
            }
            offset += count as u64;
        }
        self.validate()
    }

    /*
    This comparison detects an edit that leaves the complete logical range unchanged.
    It uses one bounded stack buffer and reads each logical section in sequence.
    Source validation surrounds the full comparison before a no-op result is published.
    */
    fn range_matches(&self, start: u64, expected: &[u8]) -> io::Result<bool> {
        self.validate()?;
        let mut compared = 0_usize;
        let mut chunk = [0_u8; MAX_READ_BYTES];
        while compared < expected.len() {
            let count = (expected.len() - compared).min(chunk.len());
            let offset = start.checked_add(compared as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The comparison range exceeds the address range.",
                )
            })?;
            self.read_merged_unchecked_at(offset, &mut chunk[..count])?;
            if chunk[..count] != expected[compared..compared + count] {
                self.validate()?;
                return Ok(false);
            }
            compared += count;
        }
        self.validate()?;
        Ok(true)
    }

    /*
    This helper can replace changed bytes with their original source span.
    The optimization reads at most one 64 KiB source window.
    Other replacements receive one immutable memory allocation.
    */
    fn replacement_span(
        &self,
        start: u64,
        remove_len: u64,
        replacement: &[u8],
    ) -> io::Result<Option<DataSpan>> {
        if replacement.is_empty() {
            return Ok(None);
        }
        if replacement.len() <= MAX_READ_BYTES
            && remove_len == replacement.len() as u64
            && start
                .checked_add(replacement.len() as u64)
                .is_some_and(|end| end <= self.stamp.len)
        {
            let mut source = vec![0_u8; replacement.len()];
            self.validate()?;
            self.file.read_exact_at(&mut source, start)?;
            self.validate()?;
            if source == replacement {
                return Ok(Some(DataSpan::Source {
                    start,
                    len: replacement.len() as u64,
                }));
            }
        }
        Ok(Some(DataSpan::Memory {
            bytes: Arc::from(replacement),
            start: 0,
            len: replacement.len(),
        }))
    }

    /*
    This normalization appends one nonempty span to a planned layout.
    It joins contiguous source offsets and adjacent slices of one memory allocation.
    Other spans keep their independent order and backing storage.
    */
    fn push_span(spans: &mut Vec<DataSpan>, span: DataSpan) -> io::Result<()> {
        if span.len() == 0 {
            return Ok(());
        }
        match (spans.last_mut(), &span) {
            (
                Some(DataSpan::Source {
                    start: left,
                    len: left_len,
                }),
                DataSpan::Source {
                    start: right,
                    len: right_len,
                },
            ) if left.checked_add(*left_len) == Some(*right) => {
                *left_len = left_len.checked_add(*right_len).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "The source span exceeds the address range.",
                    )
                })?;
            }
            (
                Some(DataSpan::Memory {
                    bytes: left_bytes,
                    start: left,
                    len: left_len,
                }),
                DataSpan::Memory {
                    bytes: right_bytes,
                    start: right,
                    len: right_len,
                },
            ) if Arc::ptr_eq(left_bytes, right_bytes)
                && left.checked_add(*left_len) == Some(*right) =>
            {
                *left_len = left_len.checked_add(*right_len).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "The memory span exceeds the address range.",
                    )
                })?;
            }
            _ => spans.push(span),
        }
        Ok(())
    }

    /*
    This layout walk appends one logical subrange to a planned span vector.
    It slices only overlapping spans and normalizes each resulting boundary.
    */
    fn extend_slice(
        spans: &mut Vec<DataSpan>,
        layout: &Layout,
        start: u64,
        end: u64,
    ) -> io::Result<()> {
        let mut logical = 0_u64;
        for span in &layout.spans {
            let span_end = logical.checked_add(span.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The logical layout exceeds the address range.",
                )
            })?;
            let overlap_start = logical.max(start);
            let overlap_end = span_end.min(end);
            if overlap_start < overlap_end {
                Self::push_span(
                    spans,
                    span.slice(overlap_start - logical, overlap_end - overlap_start)?,
                )?;
            }
            logical = span_end;
            if logical >= end {
                break;
            }
        }
        Ok(())
    }

    /*
    This planner builds prefix, replacement, and suffix spans without changing live state.
    It checks the removed range, Linux file-offset range, allocation, and span count.
    The caller checks the complete live memory cost before assignment.
    */
    fn plan_splice(
        layout: &Layout,
        start: u64,
        remove_len: u64,
        replacement: Option<DataSpan>,
        replacement_len: u64,
    ) -> io::Result<Layout> {
        /*
        First, check the removed range and calculate the new logical length.
        The signed ceiling preserves the supported Linux file-offset range.
        */
        let end = start
            .checked_add(remove_len)
            .filter(|end| *end <= layout.len)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The paged edit extends past the file end.",
                )
            })?;
        let len = layout
            .len
            .checked_sub(remove_len)
            .and_then(|len| len.checked_add(replacement_len))
            .filter(|len| *len <= i64::MAX as u64)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The edited file length exceeds the supported Linux file-offset range.",
                )
            })?;

        /*
        Next, allocate one complete candidate and append its three logical parts.
        Normalization occurs at each part boundary before the span-limit check.
        */
        let mut spans = Vec::new();
        spans
            .try_reserve(layout.spans.len().saturating_add(2))
            .map_err(|_| io::Error::other("Cannot allocate the paged edit layout."))?;
        Self::extend_slice(&mut spans, layout, 0, start)?;
        if let Some(span) = replacement {
            Self::push_span(&mut spans, span)?;
        }
        Self::extend_slice(&mut spans, layout, end, layout.len)?;
        if spans.len() > CHANGED_RANGES_LIMIT {
            return Err(io::Error::other(
                "Paged changes cannot exceed 4096 source or memory spans.",
            ));
        }
        Ok(Layout { spans, len })
    }

    /*
    This accounting combines current and alternate layouts for one history state.
    It counts every span vector capacity and each immutable allocation one time.
    Shared slices count their complete backing allocation instead of visible bytes.
    Fallible set reservation occurs before each new allocation identity is inserted.
    */
    fn layouts_cost<'a>(layouts: impl IntoIterator<Item = &'a Layout>) -> io::Result<usize> {
        let mut allocations = HashSet::new();
        let mut cost = 0_usize;
        for layout in layouts {
            let descriptors = layout
                .spans
                .capacity()
                .checked_mul(std::mem::size_of::<DataSpan>())
                .ok_or_else(|| io::Error::other("The paged edit memory cost is too large."))?;
            cost = cost
                .checked_add(descriptors)
                .ok_or_else(|| io::Error::other("The paged edit memory cost is too large."))?;
            for span in &layout.spans {
                if let DataSpan::Memory { bytes, .. } = span {
                    let identity = Arc::as_ptr(bytes) as *const u8 as usize;
                    if !allocations.contains(&identity) {
                        allocations.try_reserve(1).map_err(|_| {
                            io::Error::other("Cannot allocate the paged edit memory check.")
                        })?;
                    }
                    if allocations.insert(identity) {
                        cost = cost.checked_add(bytes.len()).ok_or_else(|| {
                            io::Error::other("The paged edit memory cost is too large.")
                        })?;
                    }
                }
            }
        }
        Ok(cost)
    }

    /*
    This check applies the 65 MiB bound to one proposed current layout.
    A failure leaves the current layout and both history stacks unchanged.
    */
    fn validate_live(planned: &Layout) -> io::Result<()> {
        if Self::layouts_cost(std::iter::once(planned))? > CHANGED_BYTES_LIMIT {
            return Err(io::Error::other(
                "Paged source and memory spans cannot exceed 65 MiB.",
            ));
        }
        Ok(())
    }

    /*
    A grouped second nibble replaces only the current layout in retained history.
    This function calculates its accepted total before the group record changes.
    */
    fn grouped_history_cost(&self, planned: &Layout) -> io::Result<usize> {
        Self::validate_live(planned)?;
        let cost = Self::layouts_cost(
            std::iter::once(planned)
                .chain(self.undo_history.iter().map(|record| &record.alternate))
                .chain(self.redo_history.iter().map(|record| &record.alternate)),
        )?;
        if cost > EDIT_HISTORY_BYTES {
            return Err(io::Error::other(
                "The paged edit exceeds the 130 MiB retained history limit.",
            ));
        }
        Ok(cost)
    }

    /*
    A new operation adds the current layout as one alternate undo layout.
    This planner reserves record storage and finds the smallest oldest-record eviction.
    Redo layouts are absent from the candidate because a real new operation clears redo.
    It returns the accepted byte cost so no fallible refresh follows mutation.
    */
    fn prepare_new_history(&mut self, planned: &Layout) -> io::Result<(usize, usize)> {
        Self::validate_live(planned)?;
        self.undo_history
            .try_reserve(1)
            .map_err(|_| io::Error::other("Cannot allocate the paged edit history."))?;
        for drop_count in 0..=self.undo_history.len() {
            let records = self.undo_history.len() - drop_count + 1;
            if records > EDIT_HISTORY_LIMIT {
                continue;
            }
            let cost = Self::layouts_cost(
                std::iter::once(planned)
                    .chain(std::iter::once(&self.layout))
                    .chain(
                        self.undo_history
                            .iter()
                            .skip(drop_count)
                            .map(|record| &record.alternate),
                    ),
            )?;
            if cost <= EDIT_HISTORY_BYTES {
                return Ok((drop_count, cost));
            }
        }
        Err(io::Error::other(
            "The paged edit exceeds the 130 MiB retained history limit.",
        ))
    }

    /*
    These queries expose edit mode and logical changes to the paged viewer.
    A source-only normalized layout means that no logical change remains.
    */
    pub(crate) fn editing(&self) -> bool {
        self.editing
    }

    /*
    This query compares the current layout with its normalized source baseline.
    Undo and cancellation use the same layout shape to report no remaining change.
    */
    pub(crate) fn has_changes(&self) -> bool {
        self.layout.len != self.stamp.len
            || self.layout.spans.len() != usize::from(self.stamp.len != 0)
            || self.layout.spans.first().is_some_and(
                |span| !matches!(span, DataSpan::Source { start: 0, len } if *len == self.stamp.len),
            )
    }

    /*
    Begin edit validates the stable source before it changes the mode flag.
    The existing source layout becomes the cancellation baseline.
    */
    pub(crate) fn begin_edit(&mut self) -> io::Result<()> {
        self.validate()?;
        self.editing = true;
        Ok(())
    }

    /*
    This method stops a pending two-nibble group at a user-action boundary.
    The current record remains a normal complete undo record.
    */
    pub(crate) fn end_hex_group(&mut self) {
        if let Some(record) = self.undo_history.back_mut() {
            record.hex_group = false;
        }
    }

    /*
    Fixed replacement is a small wrapper around the structural splice transaction.
    The paged Hex view uses this route for one-byte overtype.
    */
    pub(crate) fn replace_bytes(
        &mut self,
        start: u64,
        replacement: &[u8],
        before_cursor: PagedEditCursor,
        after_cursor: PagedEditCursor,
        hex_group: bool,
    ) -> io::Result<bool> {
        if replacement.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "A paged edit must replace at least one byte.",
            ));
        }
        self.splice_bytes(
            start,
            replacement.len() as u64,
            replacement,
            before_cursor,
            after_cursor,
            hex_group,
        )
    }

    /*
    This operation applies one replacement, insertion, or deletion to logical history.
    All range, allocation, span, live-memory, and history checks precede mutation.
    Equal-byte edits preserve history unless a second nibble completes its open group.
    */
    pub(crate) fn splice_bytes(
        &mut self,
        start: u64,
        remove_len: u64,
        replacement: &[u8],
        before_cursor: PagedEditCursor,
        after_cursor: PagedEditCursor,
        hex_group: bool,
    ) -> io::Result<bool> {
        /*
        First, require edit mode and reject oversized or invalid logical ranges.
        Source validation occurs before operation planning can publish new state.
        */
        if !self.editing {
            return Err(io::Error::other(
                "Start edit mode before you change the file.",
            ));
        }
        if remove_len > BLOCK_BYTES as u64 || replacement.len() > BLOCK_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "A paged file edit cannot exceed 64 MiB.",
            ));
        }
        let end = start.checked_add(remove_len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The paged edit exceeds the address range.",
            )
        })?;
        if end > self.layout.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The paged edit extends past the file end.",
            ));
        }
        let replacement_len = replacement.len() as u64;
        self.layout
            .len
            .checked_sub(remove_len)
            .and_then(|len| len.checked_add(replacement_len))
            .filter(|len| *len <= i64::MAX as u64)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The edited file length exceeds the supported Linux file-offset range.",
                )
            })?;
        self.validate()?;

        /*
        Next, detect a no-op before allocating a candidate layout.
        A matching second nibble closes its current record and advances its final cursor.
        Other no-ops retain both history branches and every cursor.
        */
        if remove_len == replacement_len && self.range_matches(start, replacement)? {
            if !hex_group
                && let Some(record) = self.undo_history.back_mut().filter(|record| {
                    record.hex_group
                        && record.group_start == start
                        && record.group_len == replacement.len()
                })
            {
                record.after_cursor = after_cursor;
                record.hex_group = false;
            }
            return Ok(false);
        }

        /*
        Next, create the complete candidate and identify a valid history plan.
        A real matching second nibble updates one existing record.
        Other real operations prepare one new record and remove the redo branch.
        */
        let replacement_span = self.replacement_span(start, remove_len, replacement)?;
        let planned = Self::plan_splice(
            &self.layout,
            start,
            remove_len,
            replacement_span,
            replacement_len,
        )?;
        let grouped = !hex_group
            && self.undo_history.back().is_some_and(|record| {
                record.hex_group
                    && record.group_start == start
                    && record.group_len == replacement.len()
                    && remove_len == replacement_len
            });
        if grouped {
            let history_bytes = self.grouped_history_cost(&planned)?;
            self.validate()?;
            self.layout = planned;
            let record = self.undo_history.back_mut().unwrap();
            record.after_cursor = after_cursor;
            record.hex_group = false;
            self.history_bytes = history_bytes;
            return Ok(true);
        }

        let (drop_count, history_bytes) = self.prepare_new_history(&planned)?;
        self.validate()?;

        /*
        Finally, apply the accepted plan with no remaining fallible operation.
        Redo clearing, oldest-record eviction, layout replacement, and record insertion commit together.
        */
        self.redo_history.clear();
        for _ in 0..drop_count {
            self.undo_history.pop_front();
        }
        let alternate = std::mem::replace(&mut self.layout, planned);
        self.undo_history.push_back(EditRecord {
            alternate,
            before_cursor,
            after_cursor,
            hex_group,
            group_start: start,
            group_len: replacement.len(),
        });
        self.history_bytes = history_bytes;
        Ok(true)
    }

    /*
    Undo validates the source and reserves the redo destination before mutation.
    It closes any nibble group, swaps one alternate layout, and returns the before cursor.
    The combined history cost does not change during this ownership transfer.
    */
    pub(crate) fn undo(&mut self) -> io::Result<Option<PagedEditCursor>> {
        self.validate()?;
        self.redo_history
            .try_reserve(1)
            .map_err(|_| io::Error::other("Cannot allocate the paged edit history."))?;
        let Some(mut record) = self.undo_history.pop_back() else {
            return Ok(None);
        };
        record.hex_group = false;
        std::mem::swap(&mut self.layout, &mut record.alternate);
        let cursor = record.before_cursor;
        self.redo_history.push_back(record);
        Ok(Some(cursor))
    }

    /*
    Redo validates the source and reserves the undo destination before mutation.
    It swaps one alternate layout and returns the recorded after cursor.
    The combined history cost stays at its accepted value.
    */
    pub(crate) fn redo(&mut self) -> io::Result<Option<PagedEditCursor>> {
        self.validate()?;
        self.undo_history
            .try_reserve(1)
            .map_err(|_| io::Error::other("Cannot allocate the paged edit history."))?;
        let Some(mut record) = self.redo_history.pop_back() else {
            return Ok(None);
        };
        std::mem::swap(&mut self.layout, &mut record.alternate);
        let cursor = record.after_cursor;
        self.undo_history.push_back(record);
        Ok(Some(cursor))
    }

    /*
    Cancellation restores one normalized source layout without source validation.
    The action stays available after source changes or history evictions.
    It clears both history branches and leaves the captured source stamp unchanged.
    */
    pub(crate) fn cancel_edit(&mut self) {
        let spans = (self.stamp.len != 0)
            .then_some(DataSpan::Source {
                start: 0,
                len: self.stamp.len,
            })
            .into_iter()
            .collect();
        self.layout = Layout {
            spans,
            len: self.stamp.len,
        };
        self.undo_history.clear();
        self.redo_history.clear();
        self.history_bytes = self.layout.spans.capacity() * std::mem::size_of::<DataSpan>();
        self.editing = false;
    }
}

/*
This entry point opens one regular file and selects its storage from captured metadata.
The buffered path retains the descriptor with its accepted bytes for later Save identity checks.
The paged path retains that descriptor for later visible-window reads.
*/
pub(crate) fn open_source(path: &Path) -> io::Result<OpenedSource> {
    let source = PagedFile::open(path)?;
    if source.len() > BUFFERED_FILE_LIMIT {
        source.validate()?;
        Ok(OpenedSource::Paged(source))
    } else {
        source.into_buffered()
    }
}

#[cfg(test)]
mod tests {
    /*
    These tests exercise the component through disposable regular files.
    Sparse fixtures cover high u64 positions without large memory use.
    Native-path and FIFO fixtures cover Linux path and source boundaries.
    */
    use super::{
        BLOCK_BYTES, BUFFERED_FILE_LIMIT, CHANGED_BYTES_LIMIT, CHANGED_RANGES_LIMIT, DataSpan,
        EDIT_HISTORY_BYTES, EDIT_HISTORY_LIMIT, EINVAL, EditRecord, Layout, MAX_READ_BYTES,
        OpenedSource, PagedEditCursor, PagedFile, SEEK_DATA, SourceStamp, open_source,
    };
    use std::ffi::CString;
    use std::fs::{self, File, FileTimes, OpenOptions};
    use std::io;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    /*
    The C function creates a FIFO without an added Cargo dependency.
    The production O_NONBLOCK open must let the related test finish immediately.
    */
    unsafe extern "C" {
        fn mkfifo(pathname: *const std::ffi::c_char, mode: u32) -> std::ffi::c_int;
    }

    /*
    Each fixture selects a process-local unique temporary directory.
    Drop removes all sparse files, native pathnames, and FIFOs in that directory.
    */
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    /*
    One fixture owns a unique disposable directory for its test lifetime.
    The path supplies all related file and FIFO names to later helpers.
    */
    struct Fixture {
        path: PathBuf,
    }

    /*
    These helpers create native test paths below one owned temporary directory.
    Drop later removes all files created through the fixture.
    */
    impl Fixture {
        /*
        This constructor creates one unique temporary directory for a test.
        A collision advances the process-local counter and tries another name.
        */
        fn new(label: &str) -> io::Result<Self> {
            let base = std::env::temp_dir();
            loop {
                let number = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "hview-paged-{label}-{}-{number}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self { path }),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
        }

        /*
        This helper joins one test filename to the owned fixture directory.
        It preserves the caller-supplied native filename component.
        */
        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    /*
    The Drop implementation removes the owned disposable directory.
    Cleanup errors cannot replace the test result that caused destruction.
    */
    impl Drop for Fixture {
        /*
        This cleanup removes the complete disposable fixture tree after each test.
        A prior test error does not replace its original result with a cleanup error.
        */
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /*
    This helper creates a sparse file and writes small markers at selected offsets.
    The resulting file exercises high positions while keeping memory and storage bounded.
    */
    fn sparse_file(path: &Path, len: u64, markers: &[(u64, &[u8])]) -> io::Result<()> {
        let file = OpenOptions::new().create_new(true).write(true).open(path)?;
        file.set_len(len)?;
        for (offset, bytes) in markers {
            file.write_all_at(bytes, *offset)?;
        }
        file.sync_all()
    }

    /*
    This helper creates one empty regular file for direct staging tests.
    Read access lets each test inspect selected output bytes through positioned I/O.
    The exclusive create operation keeps accidental reuse visible as a test error.
    */
    fn staging_file(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
    }

    /*
    One layout snapshot records logical length, span capacity, and backing identities.
    Staging tests use this value for the current layout and each alternate history layout.
    */
    #[derive(Debug, Eq, PartialEq)]
    struct LayoutSignature {
        len: u64,
        spans: Vec<(u8, u64, u64, usize)>,
        span_capacity: usize,
    }

    /*
    One record snapshot combines its alternate layout with cursor and grouping state.
    Separate undo and redo vectors preserve both history order and ownership details.
    */
    #[derive(Debug, Eq, PartialEq)]
    struct RecordSignature {
        alternate: LayoutSignature,
        before_cursor: PagedEditCursor,
        after_cursor: PagedEditCursor,
        hex_group: bool,
        group_start: u64,
        group_len: usize,
    }

    /*
    One edit snapshot records the state that a staging operation must not change.
    The snapshot includes the current layout, histories, mode, byte cost, and source stamp.
    */
    #[derive(Debug, Eq, PartialEq)]
    struct EditStateSignature {
        layout: LayoutSignature,
        editing: bool,
        undo: Vec<RecordSignature>,
        redo: Vec<RecordSignature>,
        history_bytes: usize,
        stamp: SourceStamp,
    }

    /*
    This helper captures one layout without copying source or memory bytes.
    Memory pointer identities show whether staging replaces a backing allocation.
    */
    fn layout_state_signature(layout: &Layout) -> LayoutSignature {
        LayoutSignature {
            len: layout.len,
            spans: layout_signature(layout),
            span_capacity: layout.spans.capacity(),
        }
    }

    /*
    This helper captures one history record and its complete alternate layout description.
    The returned value also keeps every cursor and nibble-group field.
    */
    fn record_state_signature(record: &EditRecord) -> RecordSignature {
        RecordSignature {
            alternate: layout_state_signature(&record.alternate),
            before_cursor: record.before_cursor,
            after_cursor: record.after_cursor,
            hex_group: record.hex_group,
            group_start: record.group_start,
            group_len: record.group_len,
        }
    }

    /*
    This helper captures one complete edit snapshot before a staging operation.
    Tests compare the returned value after success or failure.
    */
    fn edit_state_signature(source: &PagedFile) -> EditStateSignature {
        EditStateSignature {
            layout: layout_state_signature(&source.layout),
            editing: source.editing,
            undo: source
                .undo_history
                .iter()
                .map(record_state_signature)
                .collect(),
            redo: source
                .redo_history
                .iter()
                .map(record_state_signature)
                .collect(),
            history_bytes: source.history_bytes,
            stamp: source.stamp,
        }
    }

    /*
    This helper collects a complete logical view through normal bounded windows.
    Small tests use the result as a direct byte oracle after structural edits.
    */
    fn read_all(source: &PagedFile) -> io::Result<Vec<u8>> {
        let capacity = usize::try_from(source.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The test source is too large for a complete oracle.",
            )
        })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| io::Error::other("Cannot allocate the complete test source oracle."))?;
        let mut start = 0_u64;
        while start < source.len() {
            let window = source.read_window(start, MAX_READ_BYTES)?;
            start += window.bytes.len() as u64;
            bytes.extend_from_slice(&window.bytes);
        }
        Ok(bytes)
    }

    /*
    This helper describes span kind, start, length, and memory identity.
    Tests compare the description before and after rejected or no-op operations.
    */
    fn layout_signature(layout: &Layout) -> Vec<(u8, u64, u64, usize)> {
        layout
            .spans
            .iter()
            .map(|span| match span {
                DataSpan::Source { start, len } => (0, *start, *len, 0),
                DataSpan::Memory { bytes, start, len } => (
                    1,
                    *start as u64,
                    *len as u64,
                    Arc::as_ptr(bytes) as *const u8 as usize,
                ),
            })
            .collect()
    }

    /*
    This helper creates exact cursor values for history tests.
    The offset, viewport, and nibble fields remain visible in returned undo results.
    */
    fn cursor(offset: u64, top: u64, low_nibble: bool) -> PagedEditCursor {
        PagedEditCursor {
            offset,
            top,
            low_nibble,
        }
    }

    /*
    Existing logical-span tests use this history-aware splice adapter.
    The first call starts edit mode and each call records one independent operation.
    L03.2 tests call the full entry directly when cursor or grouping behavior matters.
    */
    fn splice(
        source: &mut PagedFile,
        start: u64,
        remove_len: u64,
        replacement: &[u8],
    ) -> io::Result<bool> {
        if !source.editing() {
            source.begin_edit()?;
        }
        let before = cursor(start, start, false);
        let after = cursor(start + replacement.len() as u64, start, false);
        source.splice_bytes(start, remove_len, replacement, before, after, false)
    }

    /*
    These staged writes cover unchanged bytes and each structural edit kind.
    One changed range crosses the 64 KiB boundary, and one insertion grows EOF.
    The output keeps exact bytes and length while the source keeps all edit state.
    A complete deletion also produces an empty staged file.
    */
    #[test]
    fn staged_writes_preserve_logical_bytes_lengths_and_edit_state() -> io::Result<()> {
        let fixture = Fixture::new("staged-logical")?;
        let source_path = fixture.file("source.bin");
        let original: Vec<u8> = (0..MAX_READ_BYTES * 2 + 37)
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(&source_path, &original)?;
        let mut source = PagedFile::open(&source_path)?;

        let unchanged_path = fixture.file("unchanged.stage");
        let unchanged = staging_file(&unchanged_path)?;
        source.write_staged(&unchanged)?;
        assert_eq!(fs::read(&unchanged_path)?, original);
        assert_eq!(unchanged.metadata()?.len(), original.len() as u64);

        let mut expected = original.clone();
        let replace_start = MAX_READ_BYTES - 4;
        assert!(splice(
            &mut source,
            replace_start as u64,
            9,
            b"replacement"
        )?);
        expected.splice(
            replace_start..replace_start + 9,
            b"replacement".iter().copied(),
        );
        let insert_at = expected.len();
        assert!(splice(&mut source, insert_at as u64, 0, b"tail")?);
        expected.extend_from_slice(b"tail");
        assert!(splice(&mut source, 7, 11, b"")?);
        expected.drain(7..18);

        let state = edit_state_signature(&source);
        let changed_path = fixture.file("changed.stage");
        let changed = staging_file(&changed_path)?;
        source.write_staged(&changed)?;
        assert_eq!(fs::read(&changed_path)?, expected);
        assert_eq!(changed.metadata()?.len(), expected.len() as u64);
        assert_eq!(edit_state_signature(&source), state);

        let deleted_path = fixture.file("deleted-source.bin");
        fs::write(&deleted_path, b"delete all bytes")?;
        let mut deleted = PagedFile::open(&deleted_path)?;
        let deleted_len = deleted.len();
        assert!(splice(&mut deleted, 0, deleted_len, b"")?);
        let empty_path = fixture.file("empty.stage");
        let empty = staging_file(&empty_path)?;
        deleted.write_staged(&empty)?;
        assert_eq!(empty.metadata()?.len(), 0);
        assert!(fs::read(&empty_path)?.is_empty());
        Ok(())
    }

    /*
    This injected unsupported query selects the production bounded scan deterministically.
    The source has separate zero and nonzero 64 KiB chunks plus one memory replacement.
    The output keeps exact bytes and uses little storage for skipped zero chunks.
    Another injected query error must keep its operating-system error and edit state.
    */
    #[test]
    fn unsupported_extent_queries_use_the_bounded_sparse_scan() -> io::Result<()> {
        let fixture = Fixture::new("staged-fallback")?;
        let source_path = fixture.file("source.bin");
        let len = MAX_READ_BYTES * 8;
        sparse_file(
            &source_path,
            len as u64,
            &[
                (MAX_READ_BYTES as u64 + 3, b"FIRST"),
                (MAX_READ_BYTES as u64 * 5 + 7, b"SECOND"),
                (len as u64 - 1, b"Z"),
            ],
        )?;
        let mut source = PagedFile::open(&source_path)?;
        let changed = MAX_READ_BYTES as u64 * 3 + 9;
        assert!(splice(&mut source, changed, 1, b"M")?);
        let state = edit_state_signature(&source);

        let output_path = fixture.file("fallback.stage");
        let output = staging_file(&output_path)?;
        source.write_staged_with(&output, |_, _| Err(io::Error::from_raw_os_error(EINVAL)))?;
        let mut expected = vec![0_u8; len];
        expected[MAX_READ_BYTES + 3..MAX_READ_BYTES + 8].copy_from_slice(b"FIRST");
        expected[MAX_READ_BYTES * 5 + 7..MAX_READ_BYTES * 5 + 13].copy_from_slice(b"SECOND");
        expected[len - 1] = b'Z';
        expected[changed as usize] = b'M';
        assert_eq!(fs::read(&output_path)?, expected);
        assert_eq!(output.metadata()?.len(), len as u64);
        assert!(output.metadata()?.blocks() * 512 < (MAX_READ_BYTES * 5) as u64);
        assert_eq!(edit_state_signature(&source), state);

        let error_path = fixture.file("query-error.stage");
        let error_output = staging_file(&error_path)?;
        let error = source
            .write_staged_with(&error_output, |_, _| Err(io::Error::from_raw_os_error(5)))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(edit_state_signature(&source), state);
        Ok(())
    }

    /*
    This real extent walk stages a sparse edited source above the 4 GiB boundary.
    Structural insertion and deletion shift later source spans to new logical positions.
    A memory byte inside a source hole becomes allocated output data.
    Selected reads prove the mapped bytes without a complete large-file allocation.
    */
    #[test]
    fn sparse_staging_maps_shifted_spans_above_four_gib() -> io::Result<()> {
        let fixture = Fixture::new("staged-sparse-high")?;
        let source_path = fixture.file("source.bin");
        let high = 4 * 1024 * 1024 * 1024_u64 + 123;
        let source_len = high + MAX_READ_BYTES as u64 * 2 + 1;
        sparse_file(
            &source_path,
            source_len,
            &[(0, b"HEAD"), (high, b"HIGH"), (source_len - 1, b"Z")],
        )?;
        let mut source = PagedFile::open(&source_path)?;
        let extent = source.seek_extent(0, SEEK_DATA)?;
        assert_eq!(extent, 0);

        assert!(splice(&mut source, 0, 0, b"I")?);
        assert!(splice(&mut source, 2, 2, b"")?);
        let changed_source = high - MAX_READ_BYTES as u64;
        let changed_logical = changed_source - 1;
        assert!(splice(&mut source, changed_logical, 1, b"M")?);
        let state = edit_state_signature(&source);

        let output_path = fixture.file("sparse.stage");
        let output = staging_file(&output_path)?;
        source.write_staged(&output)?;
        assert_eq!(output.metadata()?.len(), source_len - 1);
        let mut prefix = [0_u8; 3];
        output.read_exact_at(&mut prefix, 0)?;
        assert_eq!(&prefix, b"IHD");
        let mut changed_byte = [0_u8; 1];
        output.read_exact_at(&mut changed_byte, changed_logical)?;
        assert_eq!(&changed_byte, b"M");
        let mut high_marker = [0_u8; 4];
        output.read_exact_at(&mut high_marker, high - 1)?;
        assert_eq!(&high_marker, b"HIGH");
        let mut final_byte = [0_u8; 1];
        output.read_exact_at(&mut final_byte, source_len - 2)?;
        assert_eq!(&final_byte, b"Z");
        assert!(output.metadata()?.blocks() * 512 < 16 * 1024 * 1024);
        assert_eq!(edit_state_signature(&source), state);
        Ok(())
    }

    /*
    These failures cover source aliases, prior output bytes, and a read-only staging descriptor.
    Each error keeps the complete edit layout and history state.
    Alias and nonempty checks also keep every existing output byte unchanged.
    */
    #[test]
    fn staged_output_refusals_preserve_output_and_edit_state() -> io::Result<()> {
        let fixture = Fixture::new("staged-refusals")?;
        let source_path = fixture.file("source.bin");
        fs::write(&source_path, b"source bytes")?;
        let alias_path = fixture.file("alias.bin");
        fs::hard_link(&source_path, &alias_path)?;
        let mut source = PagedFile::open(&source_path)?;
        assert!(splice(&mut source, 1, 2, b"XY")?);
        let state = edit_state_signature(&source);

        let alias = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&alias_path)?;
        assert!(
            source
                .write_staged(&alias)
                .unwrap_err()
                .to_string()
                .contains("identifies")
        );
        assert_eq!(fs::read(&alias_path)?, b"source bytes");

        let occupied_path = fixture.file("occupied.stage");
        fs::write(&occupied_path, b"keep")?;
        let occupied = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&occupied_path)?;
        assert_eq!(
            source.write_staged(&occupied).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&occupied_path)?, b"keep");

        let directory = File::open(&fixture.path)?;
        assert_eq!(
            source.write_staged(&directory).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let read_only_path = fixture.file("read-only.stage");
        File::create(&read_only_path)?;
        let read_only = File::open(&read_only_path)?;
        source.validate()?;
        assert!(
            source
                .write_staged(&read_only)
                .unwrap_err()
                .raw_os_error()
                .is_some()
        );
        assert_eq!(read_only.metadata()?.len(), 0);
        assert_eq!(edit_state_signature(&source), state);
        Ok(())
    }

    /*
    Source replacement and truncation must fail before the staging output changes.
    Both cases keep the source stamp, logical spans, history records, and edit mode.
    The empty private outputs remain available for later cleanup by their caller.
    */
    #[test]
    fn source_changes_refuse_staging_without_edit_state_changes() -> io::Result<()> {
        let fixture = Fixture::new("staged-source-errors")?;
        let replaced_path = fixture.file("replaced.bin");
        let old_path = fixture.file("old.bin");
        fs::write(&replaced_path, b"original")?;
        let mut replaced = PagedFile::open(&replaced_path)?;
        assert!(splice(&mut replaced, 1, 1, b"X")?);
        let replaced_state = edit_state_signature(&replaced);
        fs::rename(&replaced_path, &old_path)?;
        fs::write(&replaced_path, b"replacement")?;
        let replaced_output_path = fixture.file("replaced.stage");
        let replaced_output = staging_file(&replaced_output_path)?;
        assert!(replaced.write_staged(&replaced_output).is_err());
        assert_eq!(replaced_output.metadata()?.len(), 0);
        assert_eq!(edit_state_signature(&replaced), replaced_state);

        let truncated_path = fixture.file("truncated.bin");
        fs::write(&truncated_path, b"abcdefgh")?;
        let mut truncated = PagedFile::open(&truncated_path)?;
        assert!(splice(&mut truncated, 2, 2, b"YZ")?);
        let truncated_state = edit_state_signature(&truncated);
        OpenOptions::new()
            .write(true)
            .open(&truncated_path)?
            .set_len(3)?;
        let truncated_output_path = fixture.file("truncated.stage");
        let truncated_output = staging_file(&truncated_output_path)?;
        assert!(truncated.write_staged(&truncated_output).is_err());
        assert_eq!(truncated_output.metadata()?.len(), 0);
        assert_eq!(edit_state_signature(&truncated), truncated_state);
        Ok(())
    }

    /*
    This query callback replaces the source pathname after initial validation.
    The retained descriptor still supplies complete original bytes to the staging file.
    Final validation rejects publication because the pathname now identifies another file.
    The completed private bytes and all edit state remain available for recovery.
    */
    #[test]
    fn final_source_validation_rejects_late_path_replacement() -> io::Result<()> {
        let fixture = Fixture::new("staged-late-replacement")?;
        let source_path = fixture.file("source.bin");
        let old_path = fixture.file("old.bin");
        fs::write(&source_path, b"abcdef")?;
        let mut source = PagedFile::open(&source_path)?;
        assert!(splice(&mut source, 1, 1, b"X")?);
        let state = edit_state_signature(&source);
        let output_path = fixture.file("late.stage");
        let output = staging_file(&output_path)?;
        let mut replaced = false;

        let error = source
            .write_staged_with(&output, |offset, whence| {
                if !replaced {
                    fs::rename(&source_path, &old_path)?;
                    fs::write(&source_path, b"uvwxyz")?;
                    replaced = true;
                }
                source.seek_extent(offset, whence)
            })
            .unwrap_err();
        assert!(error.to_string().contains("different"));
        assert_eq!(fs::read(&output_path)?, b"aXcdef");
        assert_eq!(edit_state_signature(&source), state);
        Ok(())
    }

    /*
    These checks exercise the public splice entry for replacement, insertion, and deletion.
    Restoration bytes map back to one normalized source span.
    Equal bytes preserve the exact current layout and return a no-op result.
    */
    #[test]
    fn logical_splices_replace_insert_delete_and_restore_source() -> io::Result<()> {
        let fixture = Fixture::new("logical-splices")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"0123456789")?;
        let mut source = PagedFile::open(&path)?;

        assert!(splice(&mut source, 2, 3, b"AB")?);
        assert_eq!(read_all(&source)?, b"01AB56789");
        let end = source.len();
        assert!(splice(&mut source, end, 0, b"XYZ")?);
        assert_eq!(read_all(&source)?, b"01AB56789XYZ");
        assert!(splice(&mut source, 4, 5, b"")?);
        assert_eq!(read_all(&source)?, b"01ABXYZ");

        let signature = layout_signature(&source.layout);
        assert!(!splice(&mut source, 2, 2, b"AB")?);
        assert_eq!(layout_signature(&source.layout), signature);

        let restore_path = fixture.file("restore.bin");
        fs::write(&restore_path, b"0123456789")?;
        let mut restored = PagedFile::open(&restore_path)?;
        assert!(splice(&mut restored, 2, 2, b"XY")?);
        assert_eq!(restored.layout.spans.len(), 3);
        assert!(splice(&mut restored, 2, 2, b"23")?);
        assert_eq!(read_all(&restored)?, b"0123456789");
        assert_eq!(restored.layout.spans.len(), 1);
        assert!(matches!(
            restored.layout.spans[0],
            DataSpan::Source { start: 0, len: 10 }
        ));
        Ok(())
    }

    /*
    Empty and EOF operations establish the valid structural boundaries.
    Insertion can add bytes to an empty view and can append at exact logical EOF.
    Past-EOF operations fail without changing the current bytes.
    */
    #[test]
    fn empty_and_eof_splices_keep_checked_boundaries() -> io::Result<()> {
        let fixture = Fixture::new("empty-splices")?;
        let path = fixture.file("source.bin");
        File::create(&path)?;
        let mut source = PagedFile::open(&path)?;

        assert!(!splice(&mut source, 0, 0, b"")?);
        assert!(splice(&mut source, 0, 0, b"abc")?);
        assert!(splice(&mut source, 3, 0, b"def")?);
        assert_eq!(read_all(&source)?, b"abcdef");
        assert!(splice(&mut source, 0, 6, b"")?);
        assert_eq!(source.len(), 0);
        assert!(source.layout.spans.is_empty());

        let signature = layout_signature(&source.layout);
        assert!(splice(&mut source, 1, 0, b"x").is_err());
        assert!(splice(&mut source, 0, 1, b"").is_err());
        assert_eq!(source.len(), 0);
        assert_eq!(layout_signature(&source.layout), signature);
        Ok(())
    }

    /*
    One changed range crosses the 64 KiB window boundary in the source.
    Bounded reads combine source, memory, and source bytes without missing data.
    Returned windows remain independent after a later edit and source closure.
    */
    #[test]
    fn mixed_spans_cross_window_boundaries_and_own_results() -> io::Result<()> {
        let fixture = Fixture::new("mixed-window")?;
        let path = fixture.file("source.bin");
        let original: Vec<u8> = (0..MAX_READ_BYTES + 32)
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(&path, &original)?;
        let mut source = PagedFile::open(&path)?;
        let start = MAX_READ_BYTES as u64 - 4;
        assert!(splice(&mut source, start, 8, b"changed!")?);

        let mut expected = original.clone();
        expected.splice(
            start as usize..start as usize + 8,
            b"changed!".iter().copied(),
        );
        let crossing = source.read_window(start - 4, 16)?;
        assert_eq!(
            &*crossing.bytes,
            &expected[start as usize - 4..start as usize + 12]
        );
        let prefix = source.read_window(0, 8)?;
        assert!(splice(&mut source, 1, 2, b"later")?);
        drop(source);
        assert_eq!(&*prefix.bytes, &original[..8]);
        Ok(())
    }

    /*
    Direct layout fixtures isolate span splitting and normalization from file I/O.
    Contiguous source spans merge by source offset.
    Adjacent memory slices merge only when both slices share one allocation.
    */
    #[test]
    fn source_and_shared_memory_slices_merge_only_when_contiguous() -> io::Result<()> {
        let shared: Arc<[u8]> = Arc::from(&b"abcdef"[..]);
        let mut spans = Vec::new();
        PagedFile::push_span(&mut spans, DataSpan::Source { start: 2, len: 3 })?;
        PagedFile::push_span(&mut spans, DataSpan::Source { start: 5, len: 4 })?;
        PagedFile::push_span(
            &mut spans,
            DataSpan::Memory {
                bytes: Arc::clone(&shared),
                start: 0,
                len: 2,
            },
        )?;
        PagedFile::push_span(
            &mut spans,
            DataSpan::Memory {
                bytes: Arc::clone(&shared),
                start: 2,
                len: 4,
            },
        )?;
        PagedFile::push_span(
            &mut spans,
            DataSpan::Memory {
                bytes: Arc::from(&b"x"[..]),
                start: 0,
                len: 1,
            },
        )?;

        assert_eq!(spans.len(), 3);
        assert!(matches!(spans[0], DataSpan::Source { start: 2, len: 7 }));
        assert!(matches!(
            spans[1],
            DataSpan::Memory {
                start: 0,
                len: 6,
                ..
            }
        ));

        let layout = Layout {
            spans: vec![DataSpan::Memory {
                bytes: Arc::clone(&shared),
                start: 0,
                len: 6,
            }],
            len: 6,
        };
        let mut slices = Vec::new();
        PagedFile::extend_slice(&mut slices, &layout, 1, 5)?;
        assert!(matches!(
            slices[0],
            DataSpan::Memory {
                start: 1,
                len: 4,
                ..
            }
        ));
        Ok(())
    }

    /*
    A deterministic edit sequence compares every logical result with Vec splice behavior.
    The sequence includes growth, shrinkage, replacement, and exact EOF insertion.
    */
    #[test]
    fn mixed_splice_sequence_matches_vec_oracle() -> io::Result<()> {
        let fixture = Fixture::new("splice-oracle")?;
        let path = fixture.file("source.bin");
        let original: Vec<u8> = (0_u8..80).collect();
        fs::write(&path, &original)?;
        let mut source = PagedFile::open(&path)?;
        let mut oracle = original;
        let operations: &[(usize, usize, &[u8])] = &[
            (10, 5, b"alpha"),
            (0, 0, b"HEAD"),
            (30, 9, b"x"),
            (3, 7, b"middle-range"),
            (usize::MAX, 0, b"TAIL"),
            (1, 12, b""),
        ];

        for &(start, remove, replacement) in operations {
            let start = start.min(oracle.len());
            let remove = remove.min(oracle.len() - start);
            assert!(splice(
                &mut source,
                start as u64,
                remove as u64,
                replacement,
            )?);
            oracle.splice(start..start + remove, replacement.iter().copied());
            assert_eq!(source.len(), oracle.len() as u64);
            assert_eq!(read_all(&source)?, oracle);
        }
        Ok(())
    }

    /*
    This helper creates many valid but noncontiguous source spans without file data.
    Numeric limit tests can use the layout planner without large fixture files.
    */
    fn nonmerging_source_layout(count: usize) -> Layout {
        let spans = (0..count)
            .map(|index| DataSpan::Source {
                start: if index.is_multiple_of(2) { 0 } else { 2 },
                len: 1,
            })
            .collect();
        Layout {
            spans,
            len: count as u64,
        }
    }

    /*
    Planner fixtures check wrapped ranges and the Linux signed file-offset ceiling.
    Each error occurs before a replacement layout can become current.
    */
    #[test]
    fn splice_planner_rejects_range_and_result_overflow() {
        let small = Layout {
            spans: vec![DataSpan::Source { start: 0, len: 4 }],
            len: 4,
        };
        assert!(PagedFile::plan_splice(&small, u64::MAX, 1, None, 0).is_err());
        assert!(PagedFile::plan_splice(&small, 3, 2, None, 0).is_err());

        let maximum = Layout {
            spans: vec![DataSpan::Source {
                start: 0,
                len: i64::MAX as u64,
            }],
            len: i64::MAX as u64,
        };
        assert!(
            PagedFile::plan_splice(
                &maximum,
                maximum.len,
                0,
                Some(DataSpan::Memory {
                    bytes: Arc::from(&b"x"[..]),
                    start: 0,
                    len: 1,
                }),
                1,
            )
            .is_err()
        );
    }

    /*
    The span planner accepts exactly 4,096 normalized spans and rejects one more.
    The failed plan cannot change either compact input layout.
    */
    #[test]
    fn span_count_limit_accepts_boundary_and_refuses_next_span() -> io::Result<()> {
        let accepted_source = nonmerging_source_layout(CHANGED_RANGES_LIMIT - 1);
        let accepted_signature = layout_signature(&accepted_source);
        let accepted = PagedFile::plan_splice(
            &accepted_source,
            1,
            0,
            Some(DataSpan::Memory {
                bytes: Arc::from(&b"x"[..]),
                start: 0,
                len: 1,
            }),
            1,
        )?;
        assert_eq!(accepted.spans.len(), CHANGED_RANGES_LIMIT);
        assert_eq!(layout_signature(&accepted_source), accepted_signature);

        let refused_source = nonmerging_source_layout(CHANGED_RANGES_LIMIT);
        let refused_signature = layout_signature(&refused_source);
        assert!(
            PagedFile::plan_splice(
                &refused_source,
                1,
                0,
                Some(DataSpan::Memory {
                    bytes: Arc::from(&b"x"[..]),
                    start: 0,
                    len: 1,
                }),
                1,
            )
            .is_err()
        );
        assert_eq!(layout_signature(&refused_source), refused_signature);
        Ok(())
    }

    /*
    This public refusal uses readable source spans from one small real file.
    A rejected 4,097th span preserves length, capacity, identities, and visible bytes.
    */
    #[test]
    fn public_span_limit_refusal_preserves_the_live_layout() -> io::Result<()> {
        let fixture = Fixture::new("public-span-limit")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"abc")?;
        let mut source = PagedFile::open(&path)?;
        source.layout = nonmerging_source_layout(CHANGED_RANGES_LIMIT);

        let length = source.len();
        let capacity = source.layout.spans.capacity();
        let signature = layout_signature(&source.layout);
        let bytes = source.read_window(0, 8)?.bytes;
        assert!(splice(&mut source, 1, 0, b"x").is_err());
        assert_eq!(source.len(), length);
        assert_eq!(source.layout.spans.capacity(), capacity);
        assert_eq!(layout_signature(&source.layout), signature);
        assert_eq!(source.read_window(0, 8)?.bytes, bytes);
        Ok(())
    }

    /*
    This accounting fixture uses two slices from one larger memory allocation.
    The cost includes the full shared allocation once and all vector capacity.
    */
    #[test]
    fn live_cost_counts_each_complete_allocation_once() -> io::Result<()> {
        let shared: Arc<[u8]> = vec![0_u8; 1024].into();
        let spans = vec![
            DataSpan::Memory {
                bytes: Arc::clone(&shared),
                start: 0,
                len: 1,
            },
            DataSpan::Source { start: 0, len: 1 },
            DataSpan::Memory {
                bytes: Arc::clone(&shared),
                start: 1023,
                len: 1,
            },
        ];
        let layout = Layout { spans, len: 3 };
        assert_eq!(
            PagedFile::layouts_cost(std::iter::once(&layout))?,
            layout.spans.capacity() * std::mem::size_of::<DataSpan>() + shared.len()
        );

        let descriptor = std::mem::size_of::<DataSpan>();
        let exact_len = CHANGED_BYTES_LIMIT - descriptor;
        let exact_spans = vec![DataSpan::Memory {
            bytes: vec![0_u8; exact_len].into(),
            start: 0,
            len: exact_len,
        }];
        let exact = Layout {
            spans: exact_spans,
            len: exact_len as u64,
        };
        assert_eq!(
            PagedFile::layouts_cost(std::iter::once(&exact))?,
            CHANGED_BYTES_LIMIT
        );
        drop(exact);

        let refused_spans = vec![DataSpan::Memory {
            bytes: vec![0_u8; exact_len + 1].into(),
            start: 0,
            len: exact_len + 1,
        }];
        let refused = Layout {
            spans: refused_spans,
            len: exact_len as u64 + 1,
        };
        assert!(PagedFile::layouts_cost(std::iter::once(&refused))? > CHANGED_BYTES_LIMIT);
        Ok(())
    }

    /*
    Public boundary checks accept exact 64 MiB operations and reject larger operations.
    A one-byte slice still owns its complete 64 MiB allocation after deletion.
    A later live-cost refusal preserves that byte, length, capacity, and span identity.
    */
    #[test]
    fn operation_and_live_memory_limits_preserve_state() -> io::Result<()> {
        let fixture = Fixture::new("edit-limits")?;
        let empty_path = fixture.file("empty.bin");
        File::create(&empty_path)?;
        let mut source = PagedFile::open(&empty_path)?;
        let replacement = vec![0x5a_u8; BLOCK_BYTES];
        assert!(splice(&mut source, 0, 0, &replacement)?);
        drop(replacement);
        assert_eq!(source.len(), BLOCK_BYTES as u64);
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x5a]);
        assert_eq!(
            &*source.read_window(BLOCK_BYTES as u64 - 1, 1)?.bytes,
            &[0x5a]
        );

        assert!(splice(&mut source, 0, BLOCK_BYTES as u64 - 1, b"",)?);
        assert_eq!(source.len(), 1);
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x5a]);
        let signature = layout_signature(&source.layout);
        let capacity = source.layout.spans.capacity();
        let undo_len = source.undo_history.len();
        let redo_len = source.redo_history.len();
        let history_bytes = source.history_bytes;
        let extra = vec![0x33_u8; 1024 * 1024];
        assert!(
            splice(&mut source, 1, 0, &extra)
                .unwrap_err()
                .to_string()
                .contains("65 MiB")
        );
        assert_eq!(source.len(), 1);
        assert_eq!(source.layout.spans.capacity(), capacity);
        assert_eq!(layout_signature(&source.layout), signature);
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x5a]);
        assert_eq!(source.undo_history.len(), undo_len);
        assert_eq!(source.redo_history.len(), redo_len);
        assert_eq!(source.history_bytes, history_bytes);

        let too_large = vec![0_u8; BLOCK_BYTES + 1];
        assert!(splice(&mut source, 0, 0, &too_large).is_err());
        assert!(splice(&mut source, 0, BLOCK_BYTES as u64 + 1, b"").is_err());
        assert_eq!(source.layout.spans.capacity(), capacity);
        assert_eq!(layout_signature(&source.layout), signature);
        assert_eq!(source.undo_history.len(), undo_len);
        assert_eq!(source.redo_history.len(), redo_len);
        assert_eq!(source.history_bytes, history_bytes);

        let removal_path = fixture.file("removal.bin");
        sparse_file(&removal_path, BLOCK_BYTES as u64 + 2, &[])?;
        let mut removal = PagedFile::open(&removal_path)?;
        assert!(splice(&mut removal, 0, BLOCK_BYTES as u64, b"")?);
        assert_eq!(removal.len(), 2);
        Ok(())
    }

    /*
    A sparse source keeps logical edits and reads above the 4 GiB boundary.
    The replacement changes only one bounded memory span near the high offset.
    Undo and redo return high cursor fields and restore the related high bytes.
    */
    #[test]
    fn logical_spans_keep_offsets_above_four_gib() -> io::Result<()> {
        let fixture = Fixture::new("high-edit")?;
        let path = fixture.file("source.bin");
        let high = 4 * 1024 * 1024 * 1024_u64 + 123;
        sparse_file(&path, high + 8, &[(high, b"original")])?;
        let mut source = PagedFile::open(&path)?;

        assert!(splice(&mut source, high + 1, 3, b"XYZ")?);
        assert_eq!(&*source.read_window(high, 8)?.bytes, b"oXYZinal");
        assert_eq!(source.len(), high + 8);
        assert_eq!(source.undo()?, Some(cursor(high + 1, high + 1, false)));
        assert_eq!(&*source.read_window(high, 8)?.bytes, b"original");
        assert_eq!(source.redo()?, Some(cursor(high + 4, high + 1, false)));
        assert_eq!(&*source.read_window(high, 8)?.bytes, b"oXYZinal");
        Ok(())
    }

    /*
    Source validation remains active when the requested logical bytes are in memory.
    Changed metadata and pathname replacement both stop a later mixed-view read.
    */
    #[test]
    fn source_changes_after_edits_stop_memory_reads() -> io::Result<()> {
        let fixture = Fixture::new("edited-source-change")?;
        let changed_path = fixture.file("changed.bin");
        fs::write(&changed_path, b"abcdef")?;
        let mut changed = PagedFile::open(&changed_path)?;
        assert!(splice(&mut changed, 1, 1, b"X")?);
        let file = OpenOptions::new().write(true).open(&changed_path)?;
        file.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))?;
        assert!(changed.read_window(1, 1).is_err());

        let replaced_path = fixture.file("replaced.bin");
        let old_path = fixture.file("old.bin");
        fs::write(&replaced_path, b"abcdef")?;
        let mut replaced = PagedFile::open(&replaced_path)?;
        assert!(splice(&mut replaced, 1, 1, b"Y")?);
        fs::rename(&replaced_path, &old_path)?;
        fs::write(&replaced_path, b"uvwxyz")?;
        assert!(replaced.read_window(1, 1).is_err());
        Ok(())
    }

    /*
    Structural history swaps complete layouts and returns exact cursor snapshots.
    The snapshots keep u64 values that are larger than the fixture file.
    Undo restores the original length, and redo restores the expanded length.
    */
    #[test]
    fn structural_history_restores_lengths_and_high_cursors() -> io::Result<()> {
        let fixture = Fixture::new("structural-history")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"abcdef")?;
        let mut source = PagedFile::open(&path)?;
        source.begin_edit()?;
        let before = cursor(u64::from(u32::MAX) + 17, u64::from(u32::MAX), true);
        let after = cursor(u64::MAX - 1, u64::MAX - 32, false);

        assert!(source.splice_bytes(1, 2, b"WXYZ", before, after, false)?);
        assert_eq!(read_all(&source)?, b"aWXYZdef");
        assert!(source.has_changes());
        assert_eq!(source.undo()?, Some(before));
        assert_eq!(read_all(&source)?, b"abcdef");
        assert!(!source.has_changes());
        assert_eq!(source.redo()?, Some(after));
        assert_eq!(read_all(&source)?, b"aWXYZdef");
        assert!(source.has_changes());
        Ok(())
    }

    /*
    Two real Hex nibbles update one record and retain its first and final cursors.
    A matching second nibble also closes the group without adding a record.
    An explicit group boundary makes the next nibble a separate operation.
    */
    #[test]
    fn hex_groups_handle_real_noop_and_interrupted_second_nibbles() -> io::Result<()> {
        let fixture = Fixture::new("hex-groups")?;
        let path = fixture.file("source.bin");
        fs::write(&path, [0x12])?;
        let mut source = PagedFile::open(&path)?;
        source.begin_edit()?;
        let first = cursor(0, 0, false);
        let middle = cursor(0, 0, true);
        let final_cursor = cursor(1, 0, false);

        assert!(source.replace_bytes(0, &[0xf2], first, middle, true)?);
        assert!(source.replace_bytes(0, &[0xf4], middle, final_cursor, false)?);
        assert_eq!(source.undo_history.len(), 1);
        assert_eq!(source.undo()?, Some(first));
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x12]);
        assert_eq!(source.redo()?, Some(final_cursor));
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0xf4]);

        source.cancel_edit();
        source.begin_edit()?;
        assert!(source.replace_bytes(0, &[0xf2], first, middle, true)?);
        assert!(!source.replace_bytes(0, &[0xf2], middle, final_cursor, false)?);
        assert_eq!(source.undo_history.len(), 1);
        assert_eq!(source.undo()?, Some(first));
        assert_eq!(source.redo()?, Some(final_cursor));

        source.cancel_edit();
        source.begin_edit()?;
        assert!(source.replace_bytes(0, &[0xa2], first, middle, true)?);
        source.end_hex_group();
        assert!(source.replace_bytes(0, &[0xa5], middle, final_cursor, false)?);
        assert_eq!(source.undo_history.len(), 2);
        assert_eq!(source.undo()?, Some(middle));
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0xa2]);
        assert_eq!(source.undo()?, Some(first));
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x12]);
        Ok(())
    }

    /*
    An ordinary no-op keeps the existing redo branch and consumes no record.
    A later real operation clears redo only after its complete plan succeeds.
    */
    #[test]
    fn noops_preserve_redo_and_real_operations_invalidate_it() -> io::Result<()> {
        let fixture = Fixture::new("redo-rules")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"abc")?;
        let mut source = PagedFile::open(&path)?;
        source.begin_edit()?;
        let initial = cursor(0, 0, false);
        let changed = cursor(1, 0, false);

        assert!(source.replace_bytes(0, b"x", initial, changed, false)?);
        assert_eq!(source.undo()?, Some(initial));
        let bytes = source.history_bytes;
        assert!(!source.replace_bytes(0, b"a", initial, changed, false)?);
        assert_eq!(source.redo_history.len(), 1);
        assert_eq!(source.history_bytes, bytes);
        assert!(source.replace_bytes(1, b"y", initial, changed, false)?);
        assert!(source.redo_history.is_empty());
        assert_eq!(&*source.read_window(0, 3)?.bytes, b"ayc");
        Ok(())
    }

    /*
    The record count keeps the newest 256 independent operations.
    Cancellation remains available after eviction and restores the source-only baseline.
    */
    #[test]
    fn record_limit_evicts_oldest_and_cancel_restores_source() -> io::Result<()> {
        let fixture = Fixture::new("record-limit")?;
        let path = fixture.file("source.bin");
        fs::write(&path, vec![0_u8; EDIT_HISTORY_LIMIT + 1])?;
        let mut source = PagedFile::open(&path)?;
        source.begin_edit()?;
        for index in 0..=EDIT_HISTORY_LIMIT {
            let position = index as u64;
            source.replace_bytes(
                position,
                &[1],
                cursor(position, 0, false),
                cursor(position + 1, 0, false),
                false,
            )?;
        }
        assert_eq!(source.undo_history.len(), EDIT_HISTORY_LIMIT);

        for _ in 0..EDIT_HISTORY_LIMIT {
            assert!(source.undo()?.is_some());
        }
        assert!(source.undo()?.is_none());
        assert_eq!(source.read_window(0, 2)?.bytes.as_ref(), &[1, 0]);

        source.cancel_edit();
        assert!(!source.editing());
        assert!(!source.has_changes());
        assert!(source.undo_history.is_empty());
        assert!(source.redo_history.is_empty());
        assert_eq!(source.read_window(0, 2)?.bytes.as_ref(), &[0, 0]);
        Ok(())
    }

    /*
    Three layouts fill the retained-history budget with separate allocations.
    A grouped replacement cannot evict records, so its added span cost fails atomically.
    The same non-grouped operation can evict the oldest record and then commit.
    */
    #[test]
    fn history_budget_refuses_groups_and_evicts_for_new_operations() -> io::Result<()> {
        let fixture = Fixture::new("history-budget")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"abc")?;
        let mut source = PagedFile::open(&path)?;
        source.begin_edit()?;
        let descriptor = std::mem::size_of::<DataSpan>();
        let large = 60 * 1024 * 1024;
        let old = EDIT_HISTORY_BYTES - large * 2 - descriptor * 3;

        source.layout = Layout {
            spans: vec![DataSpan::Memory {
                bytes: vec![0x11_u8; large].into(),
                start: 0,
                len: large,
            }],
            len: large as u64,
        };
        let old_layout = Layout {
            spans: vec![DataSpan::Memory {
                bytes: vec![0x22_u8; old].into(),
                start: 0,
                len: old,
            }],
            len: old as u64,
        };
        let group_layout = Layout {
            spans: vec![DataSpan::Memory {
                bytes: vec![0x33_u8; large].into(),
                start: 0,
                len: large,
            }],
            len: large as u64,
        };
        source.undo_history.push_back(EditRecord {
            alternate: old_layout,
            before_cursor: cursor(0, 0, false),
            after_cursor: cursor(0, 0, false),
            hex_group: false,
            group_start: 0,
            group_len: 1,
        });
        source.undo_history.push_back(EditRecord {
            alternate: group_layout,
            before_cursor: cursor(0, 0, false),
            after_cursor: cursor(0, 0, true),
            hex_group: true,
            group_start: 0,
            group_len: 1,
        });
        source.history_bytes = PagedFile::layouts_cost(
            std::iter::once(&source.layout)
                .chain(source.undo_history.iter().map(|record| &record.alternate)),
        )?;
        assert_eq!(source.history_bytes, EDIT_HISTORY_BYTES);

        let signature = layout_signature(&source.layout);
        let capacity = source.layout.spans.capacity();
        let cursors: Vec<_> = source
            .undo_history
            .iter()
            .map(|record| (record.before_cursor, record.after_cursor, record.hex_group))
            .collect();
        assert!(
            source
                .replace_bytes(0, &[0xfe], cursor(0, 0, true), cursor(1, 0, false), false,)
                .unwrap_err()
                .to_string()
                .contains("130 MiB")
        );
        assert_eq!(layout_signature(&source.layout), signature);
        assert_eq!(source.layout.spans.capacity(), capacity);
        assert_eq!(source.history_bytes, EDIT_HISTORY_BYTES);
        assert_eq!(
            source
                .undo_history
                .iter()
                .map(|record| (record.before_cursor, record.after_cursor, record.hex_group))
                .collect::<Vec<_>>(),
            cursors
        );

        source.end_hex_group();
        assert!(source.replace_bytes(
            0,
            &[0xfe],
            cursor(0, 0, false),
            cursor(1, 0, false),
            false,
        )?);
        assert!(source.history_bytes <= EDIT_HISTORY_BYTES);
        assert_eq!(source.undo_history.len(), 2);
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0xfe]);
        assert!(source.undo()?.is_some());
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x11]);
        assert!(source.undo()?.is_some());
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x33]);
        assert!(source.undo()?.is_none());
        Ok(())
    }

    /*
    A sliced memory span and its alternate layout share one 64 MiB allocation.
    History accounting counts that allocation once across both retained layouts.
    */
    #[test]
    fn shared_allocations_count_once_across_history() -> io::Result<()> {
        let fixture = Fixture::new("shared-history")?;
        let path = fixture.file("source.bin");
        File::create(&path)?;
        let mut source = PagedFile::open(&path)?;
        source.begin_edit()?;
        let replacement = vec![0x5a_u8; BLOCK_BYTES];
        let position = cursor(0, 0, false);
        source.splice_bytes(0, 0, &replacement, position, position, false)?;
        drop(replacement);
        source.splice_bytes(0, BLOCK_BYTES as u64 - 1, b"", position, position, false)?;

        let calculated = PagedFile::layouts_cost(
            std::iter::once(&source.layout)
                .chain(source.undo_history.iter().map(|record| &record.alternate))
                .chain(source.redo_history.iter().map(|record| &record.alternate)),
        )?;
        assert_eq!(source.history_bytes, calculated);
        assert!(calculated < CHANGED_BYTES_LIMIT);
        assert_eq!(&*source.read_window(0, 1)?.bytes, &[0x5a]);
        Ok(())
    }

    /*
    Source validation errors occur before undo or redo moves a record.
    Both failure paths retain layouts, history counts, cursors, groups, and byte cost.
    Cancellation clears edits but does not accept the changed source as a new baseline.
    */
    #[test]
    fn source_errors_preserve_undo_and_redo_state() -> io::Result<()> {
        let fixture = Fixture::new("history-source-errors")?;
        let undo_path = fixture.file("undo.bin");
        fs::write(&undo_path, b"abc")?;
        let mut undo_source = PagedFile::open(&undo_path)?;
        let undo_stamp = undo_source.stamp;
        undo_source.begin_edit()?;
        let before = cursor(0, 0, false);
        let after = cursor(1, 0, true);
        undo_source.replace_bytes(0, b"x", before, after, true)?;
        let undo_signature = layout_signature(&undo_source.layout);
        let undo_cost = undo_source.history_bytes;
        OpenOptions::new()
            .write(true)
            .open(&undo_path)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))?;
        assert!(undo_source.undo().is_err());
        assert_eq!(layout_signature(&undo_source.layout), undo_signature);
        assert_eq!(undo_source.undo_history.len(), 1);
        assert!(undo_source.undo_history.back().unwrap().hex_group);
        assert!(undo_source.redo_history.is_empty());
        assert_eq!(undo_source.history_bytes, undo_cost);
        undo_source.cancel_edit();
        assert!(!undo_source.editing());
        assert!(!undo_source.has_changes());
        assert!(undo_source.undo_history.is_empty());
        assert!(undo_source.redo_history.is_empty());
        assert_eq!(undo_source.stamp, undo_stamp);
        assert!(undo_source.read_window(0, 1).is_err());

        let redo_path = fixture.file("redo.bin");
        fs::write(&redo_path, b"abc")?;
        let mut redo_source = PagedFile::open(&redo_path)?;
        redo_source.begin_edit()?;
        redo_source.replace_bytes(0, b"x", before, after, false)?;
        assert_eq!(redo_source.undo()?, Some(before));
        let redo_signature = layout_signature(&redo_source.layout);
        let redo_cost = redo_source.history_bytes;
        OpenOptions::new()
            .write(true)
            .open(&redo_path)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))?;
        assert!(redo_source.redo().is_err());
        assert_eq!(layout_signature(&redo_source.layout), redo_signature);
        assert!(redo_source.undo_history.is_empty());
        assert_eq!(redo_source.redo_history.len(), 1);
        assert_eq!(redo_source.history_bytes, redo_cost);
        Ok(())
    }

    /*
    These checks establish empty-file behavior and all preallocation rejections.
    Zero-length reads are valid only at or before EOF.
    */
    #[test]
    fn empty_files_and_invalid_ranges_are_bounded() -> io::Result<()> {
        let fixture = Fixture::new("empty")?;
        let path = fixture.file("empty.bin");
        File::create(&path)?;
        let source = PagedFile::open(&path)?;

        assert_eq!(source.len(), 0);
        let at_eof = source.read_window(0, MAX_READ_BYTES)?;
        assert_eq!(at_eof.start, 0);
        assert!(at_eof.bytes.is_empty());
        assert_eq!(
            source.read_window(1, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            source.read_window(u64::MAX, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            source
                .read_window(0, MAX_READ_BYTES + 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            source.read_window(0, usize::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    These reads cover a complete window, a window boundary, a clipped tail, and exact EOF.
    The expected slices also check ordinary byte data.
    */
    #[test]
    fn ordinary_windows_clip_only_at_eof() -> io::Result<()> {
        let fixture = Fixture::new("ordinary")?;
        let path = fixture.file("ordinary.bin");
        let bytes: Vec<u8> = (0..(MAX_READ_BYTES * 2 + 37))
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(&path, &bytes)?;
        let source = PagedFile::open(&path)?;

        let complete = source.read_window(0, MAX_READ_BYTES)?;
        assert_eq!(&*complete.bytes, &bytes[..MAX_READ_BYTES]);
        let crossing = source.read_window((MAX_READ_BYTES - 8) as u64, 24)?;
        assert_eq!(
            &*crossing.bytes,
            &bytes[MAX_READ_BYTES - 8..MAX_READ_BYTES + 16]
        );
        let tail_start = bytes.len() - 5;
        let tail = source.read_window(tail_start as u64, MAX_READ_BYTES)?;
        assert_eq!(&*tail.bytes, &bytes[tail_start..]);
        let at_eof = source.read_window(bytes.len() as u64, 12)?;
        assert!(at_eof.bytes.is_empty());
        assert_eq!(
            source
                .read_window(bytes.len() as u64 + 1, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    Each returned Box owns its data after later reads and source closure.
    This check prevents a shared scratch buffer from replacing owned windows.
    */
    #[test]
    fn retained_windows_have_independent_ownership() -> io::Result<()> {
        let fixture = Fixture::new("ownership")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"first-second-third")?;
        let source = PagedFile::open(&path)?;

        let first = source.read_window(0, 5)?;
        let second = source.read_window(6, 6)?;
        let _later = source.read_window(13, 5)?;
        drop(source);

        assert_eq!(&*first.bytes, b"first");
        assert_eq!(&*second.bytes, b"second");
        Ok(())
    }

    /*
    Sparse files verify marker reads above the buffered-file threshold and above 4 GiB.
    Boundary and final markers confirm the first, middle, high, and last positions.
    */
    #[test]
    fn sparse_large_files_keep_u64_positions() -> io::Result<()> {
        let fixture = Fixture::new("large")?;
        let medium_path = fixture.file("above-64-mib.bin");
        let medium_len = 64 * 1024 * 1024 + 257;
        let medium_high_offset = 64 * 1024 * 1024_u64 + 123;
        sparse_file(
            &medium_path,
            medium_len,
            &[
                (0, b"HEAD"),
                (MAX_READ_BYTES as u64, b"EDGE"),
                (medium_high_offset, b"HIGH"),
                (medium_len - 1, b"Z"),
            ],
        )?;

        let medium = PagedFile::open(&medium_path)?;
        assert_eq!(&*medium.read_window(0, 4)?.bytes, b"HEAD");
        assert_eq!(
            &*medium.read_window(MAX_READ_BYTES as u64, 4)?.bytes,
            b"EDGE"
        );
        assert_eq!(&*medium.read_window(medium_high_offset, 4)?.bytes, b"HIGH");
        assert_eq!(&*medium.read_window(medium_len - 1, 8)?.bytes, b"Z");

        let large_path = fixture.file("above-4-gib.bin");
        let large_len = 4 * 1024 * 1024 * 1024_u64 + 4097;
        let high_offset = 4 * 1024 * 1024 * 1024_u64 + 123;
        sparse_file(
            &large_path,
            large_len,
            &[
                (0, b"HEAD"),
                (MAX_READ_BYTES as u64, b"EDGE"),
                (high_offset, b"HIGH"),
                (large_len - 1, b"Q"),
            ],
        )?;

        let large = PagedFile::open(&large_path)?;
        assert_eq!(large.len(), large_len);
        assert_eq!(&*large.read_window(0, 4)?.bytes, b"HEAD");
        assert_eq!(
            &*large.read_window(MAX_READ_BYTES as u64, 4)?.bytes,
            b"EDGE"
        );
        assert_eq!(&*large.read_window(high_offset, 4)?.bytes, b"HIGH");
        assert_eq!(&*large.read_window(large_len - 1, 16)?.bytes, b"Q");
        Ok(())
    }

    /*
    A native pathname can contain bytes that UTF-8 cannot represent.
    PagedFile passes these bytes through Path without display conversion.
    */
    #[test]
    fn non_utf8_native_path_opens() -> io::Result<()> {
        let fixture = Fixture::new("native-path")?;
        let name = std::ffi::OsString::from_vec(b"native-\xFF.bin".to_vec());
        let path = fixture.path.join(name);
        fs::write(&path, b"native")?;

        let source = PagedFile::open(&path)?;
        assert_eq!(&*source.read_window(0, 6)?.bytes, b"native");
        Ok(())
    }

    /*
    Open preserves the operating-system error for a missing file.
    It also rejects a directory after a successful nonblocking open.
    */
    #[test]
    fn open_preserves_missing_errors_and_rejects_nonregular_sources() -> io::Result<()> {
        let fixture = Fixture::new("open-errors")?;
        assert_eq!(
            PagedFile::open(&fixture.file("missing.bin"))
                .err()
                .expect("a missing file must fail")
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            PagedFile::open(&fixture.path)
                .err()
                .expect("a directory must fail")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    The FIFO has no writer when PagedFile opens it.
    O_NONBLOCK lets open continue to metadata validation and regular-file refusal.
    The check command also gives this test a process deadline.
    */
    #[test]
    fn fifo_is_rejected_without_blocking() -> io::Result<()> {
        let fixture = Fixture::new("fifo")?;
        let path = fixture.file("source.fifo");
        let pathname = CString::new(path.as_os_str().as_bytes())?;
        if unsafe { mkfifo(pathname.as_ptr(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }

        assert_eq!(
            PagedFile::open(&path)
                .err()
                .expect("a FIFO must fail")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    An explicit modification time change provides a deterministic source-change signal.
    The test does not depend on filesystem timestamp speed or a sleep interval.
    */
    #[test]
    fn modification_time_change_requires_reopen() -> io::Result<()> {
        let fixture = Fixture::new("changed")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"unchanged length")?;
        let source = PagedFile::open(&path)?;

        let file = OpenOptions::new().write(true).open(&path)?;
        let times = FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1));
        file.set_times(times)?;
        assert!(
            source
                .read_window(0, 1)
                .unwrap_err()
                .to_string()
                .contains("Reopen")
        );
        Ok(())
    }

    /*
    Truncation changes the captured length before a positioned read starts.
    The component returns an error and cannot return a partial completed window.
    */
    #[test]
    fn truncation_returns_no_completed_window() -> io::Result<()> {
        let fixture = Fixture::new("truncated")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"abcdefgh")?;
        let source = PagedFile::open(&path)?;

        OpenOptions::new().write(true).open(&path)?.set_len(3)?;
        assert!(
            source
                .read_window(0, 8)
                .unwrap_err()
                .to_string()
                .contains("shrank")
        );
        Ok(())
    }

    /*
    Storage selection keeps the exact 64 MiB boundary in buffered memory.
    The next byte selects paged storage without allocating the sparse file length.
    */
    #[test]
    fn storage_selection_uses_the_exact_cutoff() -> io::Result<()> {
        let fixture = Fixture::new("cutoff")?;
        let buffered_path = fixture.file("buffered.bin");
        sparse_file(&buffered_path, BUFFERED_FILE_LIMIT, &[(0, b"B")])?;
        match open_source(&buffered_path)? {
            OpenedSource::Buffered { data: bytes, .. } => {
                assert_eq!(bytes.len() as u64, BUFFERED_FILE_LIMIT);
                assert_eq!(bytes[0], b'B');
            }
            OpenedSource::Paged(_) => panic!("The cutoff file must use buffered storage."),
        }

        let paged_path = fixture.file("paged.bin");
        sparse_file(&paged_path, BUFFERED_FILE_LIMIT + 1, &[(0, b"P")])?;
        match open_source(&paged_path)? {
            OpenedSource::Paged(source) => {
                assert_eq!(source.len(), BUFFERED_FILE_LIMIT + 1);
                assert_eq!(&*source.read_window(0, 1)?.bytes, b"P");
            }
            OpenedSource::Buffered { .. } => {
                panic!("A file above the cutoff must use paged storage.")
            }
        }
        Ok(())
    }

    /*
    Linux virtual regular files can report zero length while they contain readable data.
    The buffered loader reads this content through the selected descriptor.
    */
    #[test]
    fn zero_length_virtual_regular_file_keeps_content() -> io::Result<()> {
        let path = Path::new("/proc/self/cmdline");
        let metadata = fs::metadata(path)?;
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 0);
        match open_source(path)? {
            OpenedSource::Buffered { data: bytes, .. } => assert!(!bytes.is_empty()),
            OpenedSource::Paged(_) => panic!("The zero-length source must use buffered storage."),
        }
        Ok(())
    }

    /*
    This host read-only fixture reports a 4096-byte length but returns shorter content.
    The buffered selector must preserve the bytes from a normal Linux read.
    */
    #[test]
    fn short_content_virtual_regular_file_keeps_content() -> io::Result<()> {
        let path = Path::new("/sys/kernel/uevent_seqnum");
        let reported_len = path.metadata()?.len();
        match open_source(path)? {
            OpenedSource::Buffered { data, .. } => {
                assert!(!data.is_empty());
                assert!((data.len() as u64) < reported_len);
                assert_eq!(data.last(), Some(&b'\n'));
                assert!(data[..data.len() - 1].iter().all(u8::is_ascii_digit));
            }
            OpenedSource::Paged(_) => panic!("A short virtual file selected paged storage."),
        }
        Ok(())
    }

    /*
    The active descriptor remains on the original inode after pathname replacement.
    Validation rejects the replacement before another window can become visible.
    A fresh open captures the replacement inode and its new bytes.
    */
    #[test]
    fn pathname_replacement_requires_a_fresh_open() -> io::Result<()> {
        let fixture = Fixture::new("replacement")?;
        let path = fixture.file("source.bin");
        let old_path = fixture.file("old.bin");
        let len = BUFFERED_FILE_LIMIT + 1;
        sparse_file(&path, len, &[(0, b"OLD")])?;
        let source = match open_source(&path)? {
            OpenedSource::Paged(source) => source,
            OpenedSource::Buffered { .. } => panic!("The large source must use paged storage."),
        };

        fs::rename(&path, &old_path)?;
        sparse_file(&path, len, &[(0, b"NEW")])?;
        assert!(
            source
                .validate()
                .unwrap_err()
                .to_string()
                .contains("different")
        );
        drop(source);

        let reopened = match open_source(&path)? {
            OpenedSource::Paged(source) => source,
            OpenedSource::Buffered { .. } => panic!("The replacement must use paged storage."),
        };
        assert_eq!(&*reopened.read_window(0, 3)?.bytes, b"NEW");
        Ok(())
    }
}
