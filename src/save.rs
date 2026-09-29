/*
This module publishes buffered and paged regular-file saves through private recovery directories.
Descriptor-relative operations preserve target identity while bounded verification checks prepared bytes and metadata.
*/
use crate::paged::PagedFile;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::os::unix::fs::FileExt;

/*
These Linux constants define descriptor-relative opens, private publication, and expected xattr errors.
The fixed recovery names identify the prepared result, original backup, and exact native target note.
*/
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_NONBLOCK: c_int = 0o4000;
const O_CLOEXEC: c_int = 0o2000000;
const O_DIRECTORY: c_int = 0o200000;
const O_NOFOLLOW: c_int = 0o400000;
const O_PATH: c_int = 0o10000000;
const AT_REMOVEDIR: c_int = 0x200;
const RENAME_NOREPLACE: u32 = 1;
const ELOOP: i32 = 40;
const ENODATA: i32 = 61;
const ERANGE: i32 = 34;
const ENOTSUP: i32 = 95;

const NEW_FILE: &CStr = c"new.bin";
const ORIGINAL_FILE: &CStr = c"original.bin";
const TARGET_FILE: &CStr = c"target.txt";

/*
This C layout supplies nanosecond timestamps to futimens.
The fields match Linux time_t values on the supported 64-bit target.
*/
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/*
These libc calls keep staging, metadata, and publication relative to owned directory descriptors.
Descriptor-relative operations reduce pathname substitution between validation and mutation.
*/
unsafe extern "C" {
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
    fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    fn renameat(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
    ) -> c_int;
    fn renameat2(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
        flags: u32,
    ) -> c_int;
    fn fchown(fd: c_int, owner: u32, group: u32) -> c_int;
    fn futimens(fd: c_int, times: *const Timespec) -> c_int;
    fn geteuid() -> u32;
    fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize;
    fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize;
    fn fsetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
    fn fremovexattr(fd: c_int, name: *const c_char) -> c_int;
    #[cfg(test)]
    fn symlinkat(target: *const c_char, newdirfd: c_int, linkpath: *const c_char) -> c_int;
}

/*
One file state records every target field that must remain stable before replacement publication.
The xattr list contains supported user metadata and the POSIX access ACL.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileState {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/*
Source metadata adds the original access time to the guarded target state.
The independent backup uses both original timestamps after bounded content verification.
*/
#[derive(Clone)]
struct SourceMetadata {
    state: FileState,
    atime: i64,
    atime_nsec: i64,
}

/*
One target owns its canonical parent descriptor and exact native file name.
Publication uses these values without resolving the target path again.
*/
struct Target {
    parent_path: PathBuf,
    path: PathBuf,
    parent: File,
    name: CString,
}

/*
One stage owns a private recovery directory beside its target.
The keep flag selects cleanup or retained recovery evidence when the owner drops.
*/
struct Stage {
    folder_name: CString,
    folder_path: PathBuf,
    parent: File,
    dir: File,
    keep: bool,
}

/*
This result gives the paged viewer a fresh source after successful publication.
An optional warning reports a completed rename with incomplete final synchronization.
*/
pub(crate) struct PagedSaveOutcome {
    pub(crate) source: PagedFile,
    pub(crate) path: PathBuf,
    pub(crate) backup: Option<PathBuf>,
    pub(crate) warning: Option<String>,
}

/*
This error distinguishes retained edit sessions from published paths that could not reopen.
Replacement publication makes the old active path unusable, while Save As retains the old source.
*/
#[derive(Debug)]
pub(crate) enum PagedSaveError {
    Retained(io::Error),
    PublishedReplacement(io::Error),
    PublishedSaveAs(io::Error),
}

/*
These trait implementations expose the exact underlying I/O message and convert prepublication failures.
The caller matches the variant before it changes the active paged view.
*/
impl std::fmt::Display for PagedSaveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retained(error)
            | Self::PublishedReplacement(error)
            | Self::PublishedSaveAs(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PagedSaveError {}

impl From<io::Error> for PagedSaveError {
    fn from(error: io::Error) -> Self {
        Self::Retained(error)
    }
}

/*
This wrapper reuses the application pathname formatter for save messages.
Save operations retain their Path values and never derive an operational path from display text.
*/
fn display_path(path: &Path) -> String {
    crate::display_path(path.as_os_str())
}

/*
This conversion prepares one native file name for libc without changing its pathname bytes.
A zero byte cannot enter a Linux pathname and receives a clear input error.
*/
fn os_name(name: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "The save path contains a zero character.",
        )
    })
}

/*
This constructor separates a destination into one canonical parent and one exact native name.
The opened parent descriptor anchors every later stage and publication operation.
*/
fn target(path: &Path) -> io::Result<Target> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| io::Error::other("Enter a file name."))?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_path = fs::canonicalize(parent)?;
    let parent_file = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_CLOEXEC)
        .open(&parent_path)?;
    Ok(Target {
        path: parent_path.join(name),
        parent_path,
        parent: parent_file,
        name: os_name(name)?,
    })
}

/*
This wrapper converts one openat result into an owned File or the actual operating-system error.
Callers select exact flags for targets, stages, and inspection descriptors.
*/
fn open_at(dir: RawFd, name: &CStr, flags: c_int, mode: u32) -> io::Result<File> {
    let fd = unsafe { openat(dir, name.as_ptr(), flags, mode) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/*
This target open requests read and write access without following a final symbolic link.
It translates only link and permission errors that require an explicit Save As action.
*/
fn open_target(target: &Target) -> io::Result<File> {
    open_at(
        target.parent.as_raw_fd(),
        &target.name,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0,
    )
    .map_err(|error| {
        if error.raw_os_error() == Some(ELOOP) {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The save target is a symbolic link. Use Save As with a new file name.",
            )
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "The save target is not writable. Use Save As with a new file name.",
            )
        } else {
            error
        }
    })
}

/*
This early inspection reads target type and privilege fields without opening file contents.
The later writable open and state capture repeat the required guards through the owned descriptor.
*/
fn inspect_target(target: &Target) -> io::Result<()> {
    let file = open_at(
        target.parent.as_raw_fd(),
        &target.name,
        O_PATH | O_CLOEXEC | O_NOFOLLOW,
        0,
    )?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The save target is a symbolic link. Use Save As with a new file name.",
        ));
    }
    require_regular(&metadata)?;
    require_unprivileged_mode(&metadata)
}

/*
This check rejects an existing paged Save As destination before private staging writes begin.
An identity match reports a source alias, while any other entry reports an existing destination.
*/
fn require_new_paged_target(target: &Target, paged: &PagedFile) -> io::Result<()> {
    match open_at(
        target.parent.as_raw_fd(),
        &target.name,
        O_PATH | O_CLOEXEC | O_NOFOLLOW,
        0,
    ) {
        Ok(file) => {
            let metadata = file.metadata()?;
            if paged.has_identity(metadata.dev(), metadata.ino())? {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The Save As destination identifies the active source.",
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "The Save As destination already exists.",
                ))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/*
This common error identifies a target or source change that invalidates the accepted save baseline.
Callers preserve editor state and require a fresh source open.
*/
fn changed() -> io::Error {
    io::Error::other("The file changed outside the editor. Reload the file before saving.")
}

/*
This policy accepts only one regular target pathname for guarded replacement.
Multiple hard links would make replacement semantics different for another pathname.
*/
fn require_regular(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(io::Error::other(
            "The save target is not a regular file. Use Save As with a new file name.",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(io::Error::other(
            "The save target has multiple hard links. Use Save As to keep linked files unchanged.",
        ));
    }
    Ok(())
}

/*
This policy refuses set-user-ID and set-group-ID targets before staging.
Replacement cannot safely preserve privileged execution semantics for changed bytes.
*/
fn require_unprivileged_mode(metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.mode() & 0o6000 != 0 {
        return Err(io::Error::other(
            "The save target has set-user-ID or set-group-ID permission. Use Save As with a new file name.",
        ));
    }
    Ok(())
}

/*
This classifier identifies the Linux results that mean an extended attribute does not exist or lacks support.
Other errors retain their operating-system details.
*/
fn is_no_xattr(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(ENODATA | ENOTSUP))
}

/*
This reader obtains one complete extended-attribute value while its reported size can change.
Eight bounded retries handle size growth, and a disappearing accepted attribute marks the target changed.
*/
fn xattr_value(file: &File, name: &CStr) -> io::Result<Vec<u8>> {
    for _ in 0..8 {
        let size = unsafe { fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ENODATA) {
                return Err(changed());
            }
            return Err(error);
        }
        let mut value = vec![0; size as usize];
        let read = unsafe {
            fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if read >= 0 {
            value.truncate(read as usize);
            return Ok(value);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERANGE) {
            return Err(error);
        }
    }
    Err(changed())
}

/*
This policy accepts user attributes and the POSIX access ACL.
Privileged or unknown namespaces require Save As because replacement cannot preserve them safely.
*/
fn check_xattr_name(name: &[u8]) -> io::Result<()> {
    if name.starts_with(b"user.") || name == b"system.posix_acl_access" {
        return Ok(());
    }
    let kind = if name.starts_with(b"security.") || name.starts_with(b"trusted.") {
        "privileged"
    } else {
        "unsupported"
    };
    Err(io::Error::other(format!(
        "The file has {kind} metadata '{}'. Use Save As to preserve the original file.",
        String::from_utf8_lossy(name)
    )))
}

/*
This collector reads, validates, and sorts every supported descriptor xattr.
The sorted result gives stable metadata comparisons before publication.
*/
fn xattrs(file: &File) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    /*
    The outer loop retries when the required name-list size changes.
    An unsupported xattr interface produces an empty supported list.
    */
    for _ in 0..8 {
        let size = unsafe { flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let error = io::Error::last_os_error();
            return if is_no_xattr(&error) {
                Ok(Vec::new())
            } else {
                Err(error)
            };
        }
        let mut list = vec![0_u8; size as usize];
        let read = unsafe { flistxattr(file.as_raw_fd(), list.as_mut_ptr().cast(), list.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERANGE) {
                continue;
            }
            return Err(error);
        }
        list.truncate(read as usize);
        /*
        Each zero-terminated name receives a policy check and one complete value read.
        Sorting removes filesystem enumeration order from later identity checks.
        */
        let mut result = Vec::new();
        for bytes in list
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            let name = CString::new(bytes).map_err(|_| changed())?;
            check_xattr_name(bytes)?;
            result.push((bytes.to_vec(), xattr_value(file, &name)?));
        }
        result.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        return Ok(result);
    }
    Err(changed())
}

/*
This snapshot combines Linux identity, content times, link count, permissions, ownership, and supported xattrs.
Replacement compares a later snapshot before the rename commit point.
*/
fn file_state(file: &File) -> io::Result<FileState> {
    let metadata = file.metadata()?;
    Ok(FileState {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.size(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        xattrs: xattrs(file)?,
    })
}

/*
This capture validates replacement policy and retains the original access time.
The returned state supplies both publication guards and staged metadata.
*/
fn source_metadata(file: &File) -> io::Result<SourceMetadata> {
    let metadata = file.metadata()?;
    require_regular(&metadata)?;
    require_unprivileged_mode(&metadata)?;
    Ok(SourceMetadata {
        state: file_state(file)?,
        atime: metadata.atime(),
        atime_nsec: metadata.atime_nsec(),
    })
}

/*
This buffered verifier checks exact length and contents through one reusable 64 KiB buffer.
EOF or a byte mismatch reports an external source change.
*/
fn check_contents(file: &mut File, expected: &[u8]) -> io::Result<()> {
    let length = u64::try_from(expected.len())
        .map_err(|_| io::Error::other("The file is too large to save."))?;
    if file.metadata()?.len() != length {
        return Err(changed());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = [0_u8; 65536];
    for chunk in expected.chunks(buffer.len()) {
        if let Err(error) = file.read_exact(&mut buffer[..chunk.len()]) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                Err(changed())
            } else {
                Err(error)
            };
        }
        if &buffer[..chunk.len()] != chunk {
            return Err(changed());
        }
    }
    Ok(())
}

/*
This writer first removes current supported xattrs and then applies the captured ordered list.
Any failed metadata write stops staging before publication.
*/
fn set_xattrs(file: &File, attrs: &[(Vec<u8>, Vec<u8>)]) -> io::Result<()> {
    /*
    Removing current supported values prevents an inherited default ACL from surviving unexpectedly.
    Missing values need no correction.
    */
    for (name, _) in xattrs(file)? {
        let name = CString::new(name).map_err(|_| changed())?;
        if unsafe { fremovexattr(file.as_raw_fd(), name.as_ptr()) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ENODATA) {
                return Err(error);
            }
        }
    }
    /*
    Each captured native name receives its exact byte value.
    The error names the metadata item that the save could not preserve.
    */
    for (name, value) in attrs {
        let name = CString::new(name.as_slice()).map_err(|_| changed())?;
        if unsafe {
            fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        } < 0
        {
            return Err(io::Error::other(format!(
                "The save cannot preserve metadata '{}': {}",
                String::from_utf8_lossy(name.as_bytes()),
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/*
This function applies owner, group, mode, and supported xattrs to a prepared replacement.
The final verification confirms the staged descriptor before publication.
*/
fn apply_metadata(file: &File, source: &SourceMetadata) -> io::Result<()> {
    let current = file.metadata()?;
    if (current.uid(), current.gid()) != (source.state.uid, source.state.gid)
        && unsafe { fchown(file.as_raw_fd(), source.state.uid, source.state.gid) } < 0
    {
        return Err(io::Error::other(format!(
            "The save cannot preserve the file owner and group: {}",
            io::Error::last_os_error()
        )));
    }
    file.set_permissions(fs::Permissions::from_mode(source.state.mode & 0o7777))?;
    set_xattrs(file, &source.state.xattrs)?;
    verify_metadata(file, source)
}

/*
This comparison checks the replacement metadata fields that must match the captured source.
Identity, size, and timestamps follow the new-file and backup policies separately.
*/
fn verify_metadata(file: &File, source: &SourceMetadata) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != source.state.uid
        || metadata.gid() != source.state.gid
        || metadata.mode() & 0o7777 != source.state.mode & 0o7777
        || xattrs(file)? != source.state.xattrs
    {
        return Err(io::Error::other(
            "The save cannot preserve the file metadata. The original file remains unchanged.",
        ));
    }
    Ok(())
}

/*
This function restores exact source access and modification times on the independent backup.
The immediate metadata check rejects a filesystem that cannot represent the requested values.
*/
fn set_original_times(file: &File, source: &SourceMetadata) -> io::Result<()> {
    let times = [
        Timespec {
            tv_sec: source.atime,
            tv_nsec: source.atime_nsec,
        },
        Timespec {
            tv_sec: source.state.mtime,
            tv_nsec: source.state.mtime_nsec,
        },
    ];
    if unsafe { futimens(file.as_raw_fd(), times.as_ptr()) } < 0 {
        return Err(io::Error::other(format!(
            "The save cannot preserve the backup timestamps: {}",
            io::Error::last_os_error()
        )));
    }
    let metadata = file.metadata()?;
    if (
        metadata.atime(),
        metadata.atime_nsec(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    ) != (
        source.atime,
        source.atime_nsec,
        source.state.mtime,
        source.state.mtime_nsec,
    ) {
        return Err(io::Error::other(
            "The save cannot preserve the backup timestamps.",
        ));
    }
    Ok(())
}

/*
This generator reads cryptographic random bytes from the operating system for one private directory name.
The hexadecimal result contains no path separator or zero byte.
*/
fn random_folder_name() -> io::Result<CString> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut name = String::from(".HView-save-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("Writing to a string cannot fail.");
    }
    Ok(CString::new(name).expect("A generated folder name cannot contain a zero character."))
}

impl Stage {
    /*
    This constructor creates and verifies one private recovery directory beside the destination.
    It anchors all files through a descriptor and records the exact native target path.
    */
    fn new(target: &Target) -> io::Result<Self> {
        let parent = target.parent.try_clone()?;
        loop {
            /*
            The first section creates an unpredictable directory with owner-only access.
            A name collision generates another candidate without changing the target.
            */
            let folder_name = random_folder_name()?;
            if unsafe { mkdirat(target.parent.as_raw_fd(), folder_name.as_ptr(), 0o700) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error);
            }
            #[cfg(test)]
            substitute_stage_name(target.parent.as_raw_fd(), &folder_name)?;
            /*
            The next section opens the new entry without following substitutions.
            A failed open removes only the original directory name through its parent descriptor.
            */
            let dir = match open_at(
                target.parent.as_raw_fd(),
                &folder_name,
                O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW,
                0,
            ) {
                Ok(dir) => dir,
                Err(error) => {
                    unsafe {
                        unlinkat(
                            target.parent.as_raw_fd(),
                            folder_name.as_ptr(),
                            AT_REMOVEDIR,
                        );
                    }
                    return Err(error);
                }
            };
            /*
            Descriptor metadata must identify a directory owned by the current effective user.
            The permission check then confirms exact owner-only recovery access.
            */
            let metadata = match dir.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    unsafe {
                        unlinkat(
                            target.parent.as_raw_fd(),
                            folder_name.as_ptr(),
                            AT_REMOVEDIR,
                        );
                    }
                    return Err(error);
                }
            };
            if !metadata.is_dir() || metadata.uid() != unsafe { geteuid() } {
                unsafe {
                    unlinkat(
                        target.parent.as_raw_fd(),
                        folder_name.as_ptr(),
                        AT_REMOVEDIR,
                    );
                }
                return Err(io::Error::other(
                    "The save cannot create a private recovery directory.",
                ));
            }
            dir.set_permissions(fs::Permissions::from_mode(0o700))?;
            if dir.metadata()?.mode() & 0o777 != 0o700 {
                unsafe {
                    unlinkat(
                        target.parent.as_raw_fd(),
                        folder_name.as_ptr(),
                        AT_REMOVEDIR,
                    );
                }
                return Err(io::Error::other(
                    "The save cannot protect the recovery directory.",
                ));
            }
            /*
            The accepted directory becomes a Stage owner with cleanup enabled.
            The target note completes construction before any content file enters the stage.
            */
            let folder_os = std::ffi::OsString::from_vec(folder_name.as_bytes().to_vec());
            let mut stage = Self {
                folder_path: target.parent_path.join(folder_os),
                folder_name,
                parent,
                dir,
                keep: false,
            };
            stage.write_note(&target.path)?;
            return Ok(stage);
        }
    }

    /*
    This method writes the exact native target bytes into the private recovery note.
    The final newline separates the pathname from later terminal or inspection output.
    */
    fn write_note(&mut self, target: &Path) -> io::Result<()> {
        let mut note = self.create(TARGET_FILE, 0o600)?;
        note.write_all(target.as_os_str().as_bytes())?;
        note.write_all(b"\n")?;
        note.sync_all()
    }

    /*
    This method creates one exclusive stage file without following links.
    The caller selects a restrictive backup mode or a Save As mode filtered by umask.
    */
    fn create(&self, name: &CStr, mode: u32) -> io::Result<File> {
        open_at(
            self.dir.as_raw_fd(),
            name,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode,
        )
    }

    /*
    This buffered helper creates and writes one complete byte slice.
    The test hook can stop midway to verify private-file cleanup before publication.
    */
    fn write_data(&self, name: &CStr, data: &[u8], mode: u32) -> io::Result<File> {
        let mut file = self.create(name, mode)?;
        #[cfg(test)]
        if take_fault(FAULT_WRITE) {
            file.write_all(&data[..data.len() / 2])?;
            return Err(injected("staging write"));
        }
        file.write_all(data)?;
        Ok(file)
    }

    /*
    This method synchronizes prepared directory entries before publication.
    Earlier preparation helpers synchronize file bytes through their owned descriptors.
    */
    fn sync_preparation(&self) -> io::Result<()> {
        self.dir.sync_all()?;
        #[cfg(test)]
        if take_fault(FAULT_PRE_SYNC) {
            return Err(injected("prepublication synchronization"));
        }
        self.parent.sync_all()
    }

    /*
    This formatter states whether publication occurred before an error.
    It includes escaped recovery-path text while Stage retains the underlying native path.
    */
    fn recovery_error(&self, error: io::Error, published: bool) -> io::Error {
        let message = if published {
            format!(
                "Publication finished, but final synchronization failed. New bytes may already be visible. Recovery files remain in {}. Error: {error}",
                display_path(&self.folder_path)
            )
        } else {
            format!(
                "Save publication failed. Recovery files remain in {}. Error: {error}",
                display_path(&self.folder_path)
            )
        };
        io::Error::new(error.kind(), message)
    }

    /*
    This publication path returns a final synchronization warning after a successful rename.
    Paged callers can reopen the published inode before they decide whether the active view remains usable.
    */
    fn publish_tracked(&mut self, target: &Target, replace: bool) -> io::Result<Option<io::Error>> {
        self.keep = true;
        #[cfg(test)]
        if take_fault(FAULT_PUBLISH) {
            let error = injected("publication");
            return Err(self.recovery_error(error, false));
        }
        /*
        The rename commits the prepared inode through owned directory descriptors.
        An uncooperative writer can still change the target after the final check and before this operation.
        */
        let result = unsafe {
            if replace {
                renameat(
                    self.dir.as_raw_fd(),
                    NEW_FILE.as_ptr(),
                    target.parent.as_raw_fd(),
                    target.name.as_ptr(),
                )
            } else {
                renameat2(
                    self.dir.as_raw_fd(),
                    NEW_FILE.as_ptr(),
                    target.parent.as_raw_fd(),
                    target.name.as_ptr(),
                    RENAME_NOREPLACE,
                )
            }
        };
        if result < 0 {
            return Err(self.recovery_error(io::Error::last_os_error(), false));
        }
        /*
        Final directory synchronization starts only after a successful rename.
        A later error becomes a warning because new bytes can already be visible.
        */
        #[cfg(test)]
        if take_fault(FAULT_FINAL_SYNC) {
            let error = injected("final synchronization");
            return Ok(Some(self.recovery_error(error, true)));
        }
        if let Err(error) = self.dir.sync_all() {
            return Ok(Some(self.recovery_error(error, true)));
        }
        if let Err(error) = self.parent.sync_all() {
            return Ok(Some(self.recovery_error(error, true)));
        }
        Ok(None)
    }

    /*
    Buffered callers retain their established error contract for incomplete final synchronization.
    Successful Save As publication removes its empty recovery directory.
    */
    fn publish(&mut self, target: &Target, replace: bool) -> io::Result<()> {
        if let Some(error) = self.publish_tracked(target, replace)? {
            return Err(error);
        }
        if !replace {
            self.keep = false;
        }
        Ok(())
    }

    /*
    This completion flag removes a successful paged Save As recovery directory after verified reopening.
    Replacement saves retain their independent original backup.
    */
    fn finish_save_as(&mut self) {
        self.keep = false;
    }
}

/*
The destructor removes private files and the recovery directory only while cleanup remains enabled.
Published replacement backups and failed-publication evidence remain for explicit user recovery.
*/
impl Drop for Stage {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for name in [NEW_FILE, ORIGINAL_FILE, TARGET_FILE] {
            unsafe {
                unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        unsafe {
            unlinkat(
                self.parent.as_raw_fd(),
                self.folder_name.as_ptr(),
                AT_REMOVEDIR,
            );
        }
    }
}

/*
This buffered preparation writes, verifies, labels, timestamps, and synchronizes the original-byte backup.
The returned descriptor stays open until the buffered publication sequence finishes.
*/
fn prepare_backup(stage: &Stage, before: &[u8], source: &SourceMetadata) -> io::Result<File> {
    let mut backup = stage.write_data(ORIGINAL_FILE, before, 0o600)?;
    check_contents(&mut backup, before)?;
    apply_metadata(&backup, source)?;
    set_original_times(&backup, source)?;
    backup.sync_all()?;
    Ok(backup)
}

/*
This buffered preparation writes and verifies the future target bytes.
Replacement copies captured metadata, while Save As keeps its new-file mode and current umask.
*/
fn prepare_new(stage: &Stage, after: &[u8], source: Option<&SourceMetadata>) -> io::Result<File> {
    let mode = if source.is_some() { 0o600 } else { 0o666 };
    let mut new_file = stage.write_data(NEW_FILE, after, mode)?;
    if let Some(source) = source {
        apply_metadata(&new_file, source)?;
    }
    check_contents(&mut new_file, after)?;
    new_file.sync_all()?;
    Ok(new_file)
}

/*
This preparation streams the captured paged source into an independent original-byte backup.
The backup receives the existing metadata and original access and modification times.
*/
fn prepare_paged_backup(
    stage: &Stage,
    paged: &PagedFile,
    source: &SourceMetadata,
) -> io::Result<File> {
    /*
    Bounded source streaming and comparison complete before captured metadata enters the backup.
    The synchronized descriptor remains available for the final source comparison.
    */
    let backup = stage.create(ORIGINAL_FILE, 0o600)?;
    #[cfg(test)]
    if take_fault(FAULT_WRITE) {
        return Err(injected("staging write"));
    }
    #[cfg(test)]
    if take_fault(FAULT_PAGED_BACKUP_PARTIAL) {
        backup.write_all_at(b"partial backup", 0)?;
        return Err(injected("partial backup write"));
    }
    paged.write_original(&backup)?;
    paged.verify_original(&backup)?;
    apply_metadata(&backup, source)?;
    set_original_times(&backup, source)?;
    backup.sync_all()?;
    Ok(backup)
}

/*
This preparation streams the current logical spans into one fresh publication file.
Replacement metadata comes from the locked target, while Save As uses the current umask.
*/
fn prepare_paged_new(
    stage: &Stage,
    paged: &PagedFile,
    source: Option<&SourceMetadata>,
) -> io::Result<File> {
    /*
    Bounded logical staging establishes exact bytes and length before optional replacement metadata.
    Synchronization makes this descriptor ready for the stage-directory barrier.
    */
    let mode = if source.is_some() { 0o600 } else { 0o666 };
    let new_file = stage.create(NEW_FILE, mode)?;
    #[cfg(test)]
    if take_fault(FAULT_WRITE) {
        return Err(injected("staging write"));
    }
    #[cfg(test)]
    if take_fault(FAULT_PAGED_NEW_PARTIAL) {
        new_file.write_all_at(b"partial new data", 0)?;
        return Err(injected("partial logical write"));
    }
    paged.write_staged(&new_file)?;
    if let Some(source) = source {
        apply_metadata(&new_file, source)?;
    }
    paged.verify_staged(&new_file)?;
    new_file.sync_all()?;
    Ok(new_file)
}

/*
This buffered final guard compares descriptor metadata and complete accepted source bytes.
It repeats the checks through a new pathname open before the rename commit point.
*/
fn check_target(
    target: &Target,
    original: &mut File,
    expected: &FileState,
    before: &[u8],
) -> io::Result<()> {
    if file_state(original)? != *expected {
        return Err(changed());
    }
    check_contents(original, before)?;
    let mut current = open_target(target)?;
    require_regular(&current.metadata()?)?;
    if file_state(&current)? != *expected {
        return Err(changed());
    }
    check_contents(&mut current, before)
}

/*
This final guard checks the locked paged target, its pathname, metadata, and original bytes.
The independent backup supplies bounded content verification before publication.
*/
fn check_paged_target(
    target: &Target,
    original: &File,
    expected: &FileState,
    paged: &PagedFile,
    backup: &File,
) -> io::Result<()> {
    paged.validate()?;
    paged.validate_descriptor(original)?;
    if file_state(original)? != *expected {
        return Err(changed());
    }
    paged.verify_original(backup)?;

    let current = open_target(target)?;
    require_regular(&current.metadata()?)?;
    paged.validate_descriptor(&current)?;
    if file_state(&current)? != *expected {
        return Err(changed());
    }
    paged.validate()
}

/*
This helper reopens one published path and verifies the prepared staging identity.
It rejects a substituted path before the caller adopts a new paged baseline.
*/
fn reopen_paged(path: &Path, device: u64, inode: u64) -> io::Result<PagedFile> {
    #[cfg(test)]
    if take_fault(FAULT_PAGED_REOPEN) {
        return Err(injected("published source reopen"));
    }
    #[cfg(test)]
    substitute_published_path(path)?;
    let source = PagedFile::open(path)?;
    if !source.has_identity(device, inode)? {
        return Err(io::Error::other(
            "The published path identifies a different file.",
        ));
    }
    Ok(source)
}

/// Replace a regular file and keep an independent backup beside the target.
///
/// Advisory locks coordinate only with processes that use compatible locks.
/// The replacement gets a new inode, change time, and birth time.
/// The backup retains the original access and modification times.
/// The caller supplies the descriptor that provided the accepted bytes.
/// The result contains the backup path and the published descriptor.
/// Cleanup errors can leave an incomplete recovery directory.
/// A power loss after publication and before directory synchronization makes the publication result uncertain.
pub fn replace(
    path: &Path,
    accepted: &File,
    before: &[u8],
    after: &[u8],
) -> io::Result<(PathBuf, File)> {
    /*
    The first section opens, locks, validates, and captures one exact regular target.
    The writable descriptor must match the descriptor that supplied the accepted bytes before any staging begins.
    A failure here creates no recovery directory and leaves the target unchanged.
    */
    let target = target(path)?;
    inspect_target(&target)?;
    let mut original = open_target(&target)?;
    let accepted_metadata = accepted.metadata()?;
    let original_metadata = original.metadata()?;
    if (original_metadata.dev(), original_metadata.ino())
        != (accepted_metadata.dev(), accepted_metadata.ino())
    {
        return Err(changed());
    }
    original.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => {
            io::Error::other("The save target is in use. Close the other writer or use Save As.")
        }
        TryLockError::Error(error) => io::Error::other(format!(
            "The save cannot lock the target. Use Save As. Error: {error}"
        )),
    })?;
    let source = source_metadata(&original)?;
    check_contents(&mut original, before)?;

    /*
    The second section prepares both byte images before the final target guard.
    Publication returns the prepared descriptor with the independent backup path.
    The caller adopts this descriptor without reopening an unchecked pathname.
    */
    let mut stage = Stage::new(&target)?;
    let _backup = prepare_backup(&stage, before, &source)?;
    let new_file = prepare_new(&stage, after, Some(&source))?;
    stage.sync_preparation()?;
    check_target(&target, &mut original, &source.state, before)?;
    stage.publish(&target, true)?;
    Ok((
        stage
            .folder_path
            .join(std::ffi::OsStr::from_bytes(ORIGINAL_FILE.to_bytes())),
        new_file,
    ))
}

/// Create a file without replacing any existing destination entry.
/// The result contains the resolved native destination and the published descriptor.
/// Cleanup errors can leave an incomplete recovery directory.
/// A power loss after publication and before directory synchronization makes the publication result uncertain.
pub fn save_as(path: &Path, data: &[u8]) -> io::Result<(PathBuf, File)> {
    /*
    Save As stages one complete buffered image and publishes it with exclusive rename semantics.
    A successful publication returns the resolved native destination and the prepared descriptor.
    The caller retains that descriptor as the next Save identity.
    */
    let target = target(path)?;
    let mut stage = Stage::new(&target)?;
    let new_file = prepare_new(&stage, data, None)?;
    stage.sync_preparation()?;
    stage.publish(&target, false)?;
    Ok((target.path, new_file))
}

/*
This guarded replacement saves current paged spans and keeps an independent original backup.
The caller retains its active source for all failures that occur before publication.
*/
pub(crate) fn replace_paged(
    path: &Path,
    paged: &PagedFile,
) -> Result<PagedSaveOutcome, PagedSaveError> {
    /*
    The first section validates one stable source and the same writable target descriptor.
    The advisory lock prevents compatible writers from entering the publication interval.
    */
    paged.validate()?;
    let target = target(path)?;
    inspect_target(&target)?;
    let original = open_target(&target)?;
    original.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => PagedSaveError::Retained(io::Error::other(
            "The save target is in use. Close the other writer or use Save As.",
        )),
        TryLockError::Error(error) => PagedSaveError::Retained(io::Error::other(format!(
            "The save cannot lock the target. Use Save As. Error: {error}"
        ))),
    })?;
    paged.validate_descriptor(&original)?;
    let source = source_metadata(&original)?;

    /*
    This section prepares and verifies both independent files before the final target guard.
    The new-file identity remains available through its descriptor after rename.
    */
    let mut stage = Stage::new(&target)?;
    let backup = prepare_paged_backup(&stage, paged, &source)?;
    let new_file = prepare_paged_new(&stage, paged, Some(&source))?;
    let metadata = new_file.metadata()?;
    let new_identity = (metadata.dev(), metadata.ino());
    #[cfg(test)]
    substitute_source_after_preparation(&target.path)?;
    check_paged_target(&target, &original, &source.state, paged, &backup)?;
    set_original_times(&backup, &source)?;
    backup.sync_all()?;
    stage.sync_preparation()?;
    paged.validate()?;
    paged.validate_descriptor(&original)?;
    if file_state(&original)? != source.state {
        return Err(changed().into());
    }

    /*
    This section publishes the staged inode and then requires the same inode on reopen.
    A successful reopen establishes a new source baseline even when final synchronization reports a warning.
    */
    let warning = stage.publish_tracked(&target, true)?;
    let backup_path = stage
        .folder_path
        .join(std::ffi::OsStr::from_bytes(ORIGINAL_FILE.to_bytes()));
    let reopened = reopen_paged(&target.path, new_identity.0, new_identity.1).map_err(|error| {
        let warning = warning
            .as_ref()
            .map(|warning| format!(" Final synchronization warning: {warning}"))
            .unwrap_or_default();
        PagedSaveError::PublishedReplacement(io::Error::new(
            error.kind(),
            format!(
                "Publication finished at {}. The replacement cannot reopen. Original bytes remain in {}.{warning} Reopen error: {error}",
                display_path(&target.path),
                display_path(&backup_path)
            ),
        ))
    })?;
    Ok(PagedSaveOutcome {
        source: reopened,
        path: target.path,
        backup: Some(backup_path),
        warning: warning.map(|error| error.to_string()),
    })
}

/*
This guarded Save As publishes current paged spans without replacing an existing destination.
The original source and its complete edit session remain usable if the published destination cannot reopen.
*/
pub(crate) fn save_as_paged(
    path: &Path,
    paged: &PagedFile,
) -> Result<PagedSaveOutcome, PagedSaveError> {
    /*
    The first section validates the source and refuses any existing destination before staging.
    The active source remains unchanged throughout this independent publication path.
    */
    paged.validate()?;
    let target = target(path)?;
    require_new_paged_target(&target, paged)?;
    let mut stage = Stage::new(&target)?;
    let new_file = prepare_paged_new(&stage, paged, None)?;
    let metadata = new_file.metadata()?;
    let new_identity = (metadata.dev(), metadata.ino());
    stage.sync_preparation()?;
    paged.verify_staged(&new_file)?;
    paged.validate()?;
    #[cfg(test)]
    create_destination_race(&target.path)?;

    /*
    This section uses RENAME_NOREPLACE and then verifies the exact published inode.
    Successful clean publication removes the private staging directory after adoption.
    */
    let warning = stage.publish_tracked(&target, false)?;
    let reopened = reopen_paged(&target.path, new_identity.0, new_identity.1).map_err(|error| {
        let warning = warning
            .as_ref()
            .map(|warning| format!(" Final synchronization warning: {warning}"))
            .unwrap_or_default();
        PagedSaveError::PublishedSaveAs(io::Error::new(
            error.kind(),
            format!(
                "Publication finished at {}, but the destination cannot reopen. The original source and memory edits remain active. Recovery files remain in {}.{warning} Reopen error: {error}",
                display_path(&target.path),
                display_path(&stage.folder_path)
            ),
        ))
    })?;
    if warning.is_none() {
        stage.finish_save_as();
    }
    Ok(PagedSaveOutcome {
        source: reopened,
        path: target.path,
        backup: None,
        warning: warning.map(|error| error.to_string()),
    })
}

/*
These test fault identifiers stop one exact save phase through thread-local state.
The hooks cannot enter production builds or user configuration.
*/
#[cfg(test)]
const FAULT_WRITE: u8 = 1;
#[cfg(test)]
const FAULT_PRE_SYNC: u8 = 2;
#[cfg(test)]
const FAULT_PUBLISH: u8 = 3;
#[cfg(test)]
const FAULT_FINAL_SYNC: u8 = 4;
#[cfg(test)]
const FAULT_STAGE_SUBSTITUTE: u8 = 5;
#[cfg(test)]
const FAULT_PAGED_REOPEN: u8 = 6;
#[cfg(test)]
const FAULT_PAGED_BACKUP_PARTIAL: u8 = 7;
#[cfg(test)]
const FAULT_PAGED_NEW_PARTIAL: u8 = 8;

/*
These thread-local values isolate one failure or pathname action inside each test thread.
Every helper consumes its scheduled action before another save can observe it.
*/
#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static STAGE_SUBSTITUTE: std::cell::RefCell<Option<CString>> = const {
        std::cell::RefCell::new(None)
    };
    static LATE_SOURCE_SUBSTITUTE: std::cell::RefCell<Option<(PathBuf, Vec<u8>)>> = const {
        std::cell::RefCell::new(None)
    };
    static DESTINATION_RACE: std::cell::RefCell<Option<Vec<u8>>> = const {
        std::cell::RefCell::new(None)
    };
    static PUBLISHED_SUBSTITUTE: std::cell::RefCell<Option<Vec<u8>>> = const {
        std::cell::RefCell::new(None)
    };
}

/*
This test helper arms one phase failure for the current test thread.
The next matching phase consumes the value.
*/
#[cfg(test)]
fn set_fault(fault: u8) {
    FAULT.with(|value| value.set(fault));
}

/*
This test helper records an outside target and arms recovery-directory substitution.
The Stage constructor invokes the substitution after its initial mkdir operation.
*/
#[cfg(test)]
fn set_stage_substitute(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    STAGE_SUBSTITUTE.with(|value| *value.borrow_mut() = Some(path));
    set_fault(FAULT_STAGE_SUBSTITUTE);
}

/*
This test helper schedules a pathname replacement after paged preparation and before final validation.
The old path moves to the supplied location, and new external bytes take its place.
*/
#[cfg(test)]
fn set_late_source_substitute(moved: &Path, replacement: &[u8]) {
    LATE_SOURCE_SUBSTITUTE.with(|value| {
        *value.borrow_mut() = Some((moved.to_owned(), replacement.to_vec()));
    });
}

/*
This test helper performs one scheduled source replacement at the exact final-guard boundary.
The replacement uses normal filesystem operations and leaves both path identities available for assertions.
*/
#[cfg(test)]
fn substitute_source_after_preparation(path: &Path) -> io::Result<()> {
    if let Some((moved, replacement)) =
        LATE_SOURCE_SUBSTITUTE.with(|value| value.borrow_mut().take())
    {
        fs::rename(path, moved)?;
        fs::write(path, replacement)?;
    }
    Ok(())
}

/*
This test helper schedules one real destination entry after Save As preflight.
The later exclusive rename must reject the raced entry.
*/
#[cfg(test)]
fn set_destination_race(bytes: &[u8]) {
    DESTINATION_RACE.with(|value| *value.borrow_mut() = Some(bytes.to_vec()));
}

/*
This test helper creates the scheduled destination immediately before exclusive publication.
The production rename path then supplies the actual AlreadyExists result.
*/
#[cfg(test)]
fn create_destination_race(path: &Path) -> io::Result<()> {
    if let Some(bytes) = DESTINATION_RACE.with(|value| value.borrow_mut().take()) {
        fs::write(path, bytes)?;
    }
    Ok(())
}

/*
This test helper schedules replacement bytes for a path after publication and before reopen.
The identity check must reject the new inode.
*/
#[cfg(test)]
fn set_published_substitute(bytes: &[u8]) {
    PUBLISHED_SUBSTITUTE.with(|value| *value.borrow_mut() = Some(bytes.to_vec()));
}

/*
This test helper replaces one published path before PagedFile opens it.
The prepared descriptor remains owned until the save outcome returns.
*/
#[cfg(test)]
fn substitute_published_path(path: &Path) -> io::Result<()> {
    if let Some(bytes) = PUBLISHED_SUBSTITUTE.with(|value| value.borrow_mut().take()) {
        fs::remove_file(path)?;
        fs::write(path, bytes)?;
    }
    Ok(())
}

/*
This test-only operation replaces the new directory name with a symbolic link to an outside fixture.
The production O_NOFOLLOW open must reject the substituted entry without changing the fixture.
*/
#[cfg(test)]
fn substitute_stage_name(parent: RawFd, folder_name: &CStr) -> io::Result<()> {
    if !take_fault(FAULT_STAGE_SUBSTITUTE) {
        return Ok(());
    }
    let target = STAGE_SUBSTITUTE.with(|value| value.borrow_mut().take().unwrap());
    if unsafe { unlinkat(parent, folder_name.as_ptr(), AT_REMOVEDIR) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { symlinkat(target.as_ptr(), parent, folder_name.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/*
This test helper consumes a fault only when the current phase matches.
Other save phases leave the pending value available.
*/
#[cfg(test)]
fn take_fault(fault: u8) -> bool {
    FAULT.with(|value| {
        if value.get() == fault {
            value.set(0);
            true
        } else {
            false
        }
    })
}

/*
This test helper creates one stable operating-system error for an injected phase.
Tests compare the phase text with the matching publication state.
*/
#[cfg(test)]
fn injected(action: &str) -> io::Error {
    io::Error::other(format!("Injected {action} failure."))
}

/*
These tests exercise buffered and paged saves through disposable directories.
They verify bytes, metadata, identity, failure ownership, and bounded sparse publication.
*/
#[cfg(test)]
mod tests {
    use super::*;
    use crate::paged::PagedEditCursor;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    /*
    One fixture owns a unique temporary directory and all recovery folders created below it.
    Drop removes the complete disposable tree after each test.
    */
    struct Fixture(PathBuf);

    impl Fixture {
        /*
        This constructor uses the production random-name generator for one collision-resistant test directory.
        The caller creates all source and destination paths below this owner.
        */
        fn new() -> Self {
            let name = random_folder_name().unwrap();
            let path = std::env::temp_dir().join(std::ffi::OsStr::from_bytes(name.as_bytes()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        /*
        This method lists only private save recovery directories in the fixture root.
        Tests use the result to verify cleanup or retained evidence.
        */
        fn recovery_dirs(&self) -> Vec<PathBuf> {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .as_bytes()
                        .starts_with(b".HView-save-")
                })
                .collect()
        }
    }

    /*
    Fixture cleanup removes source files, published files, and retained private recovery evidence.
    No test path remains after the Fixture owner drops.
    */
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    /*
    This helper attaches one supported user xattr through the same Linux descriptor API as production code.
    Tests use the value to verify exact replacement metadata.
    */
    fn set_test_xattr(file: &File, name: &CStr, value: &[u8]) {
        assert_eq!(
            unsafe {
                fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0
        );
    }

    /*
    This helper creates one complete paged edit cursor for backend transactions.
    Tests vary the offset while keeping the viewport and nibble state deterministic.
    */
    fn paged_cursor(offset: u64) -> PagedEditCursor {
        PagedEditCursor {
            offset,
            top: offset.saturating_sub(16),
            low_nibble: false,
        }
    }

    /*
    This helper opens one source and applies a single structural edit with history.
    The returned owner lets each save check inspect retained or reset state.
    */
    fn edited_paged(path: &Path, start: u64, remove_len: u64, replacement: &[u8]) -> PagedFile {
        let mut paged = PagedFile::open(path).unwrap();
        paged.begin_edit().unwrap();
        assert!(
            paged
                .splice_bytes(
                    start,
                    remove_len,
                    replacement,
                    paged_cursor(start),
                    paged_cursor(start + replacement.len() as u64),
                    false,
                )
                .unwrap()
        );
        paged
    }

    /*
    This helper creates two edits and undoes the second operation.
    The returned source has one available Undo record and one available Redo record.
    */
    fn paged_with_both_histories(path: &Path) -> PagedFile {
        let mut paged = edited_paged(path, 0, 1, b"X");
        assert!(
            paged
                .splice_bytes(1, 1, b"Y", paged_cursor(1), paged_cursor(2), false)
                .unwrap()
        );
        assert_eq!(paged.undo().unwrap(), Some(paged_cursor(1)));
        assert_eq!(small_paged_bytes(&paged), b"Xbc");
        paged
    }

    /*
    This assertion moves through both retained history directions and returns to the initial failure state.
    Exact cursors and bytes prove that a failure changed no record.
    */
    fn assert_both_histories(paged: &mut PagedFile) {
        assert_eq!(paged.undo().unwrap(), Some(paged_cursor(0)));
        assert_eq!(small_paged_bytes(paged), b"abc");
        assert_eq!(paged.redo().unwrap(), Some(paged_cursor(1)));
        assert_eq!(small_paged_bytes(paged), b"Xbc");
        assert_eq!(paged.redo().unwrap(), Some(paged_cursor(2)));
        assert_eq!(small_paged_bytes(paged), b"XYc");
        assert_eq!(paged.undo().unwrap(), Some(paged_cursor(1)));
        assert_eq!(small_paged_bytes(paged), b"Xbc");
    }

    /*
    This helper returns one recovery directory by its exact native target note.
    Failure tests can inspect deterministic entries without depending on random folder names.
    */
    fn recovery_for_target(target: &Path) -> PathBuf {
        let mut expected = target.as_os_str().as_bytes().to_vec();
        expected.push(b'\n');
        let matches: Vec<_> = fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .as_bytes()
                    .starts_with(b".HView-save-")
            })
            .filter(|folder| fs::read(folder.join("target.txt")).unwrap() == expected)
            .collect();
        assert_eq!(matches.len(), 1);
        matches.into_iter().next().unwrap()
    }

    /*
    This helper returns sorted native entry names from one retained recovery directory.
    Exact lists detect missing data and unexpected partial files.
    */
    fn recovery_entries(folder: &Path) -> Vec<Vec<u8>> {
        let mut entries: Vec<_> = fs::read_dir(folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().as_bytes().to_vec())
            .collect();
        entries.sort_unstable();
        entries
    }

    /*
    This helper reads one small logical source after a save outcome establishes its new baseline.
    Large sparse tests use positioned markers instead of this complete test-only read.
    */
    fn small_paged_bytes(paged: &PagedFile) -> Vec<u8> {
        paged
            .read_window(0, usize::try_from(paged.len()).unwrap())
            .unwrap()
            .bytes
            .into_vec()
    }

    /*
    This test stops each private paged preparation phase before publication.
    Exact bytes, history cursors, and directory cleanup prove that each failure leaves the active edit owner unchanged.
    */
    #[test]
    fn paged_prepublication_failures_clean_up_and_preserve_state() {
        for (name, fault, phase) in [
            (
                "backup-partial",
                FAULT_PAGED_BACKUP_PARTIAL,
                "partial backup write",
            ),
            (
                "logical-partial",
                FAULT_PAGED_NEW_PARTIAL,
                "partial logical write",
            ),
            ("pre-sync", FAULT_PRE_SYNC, "prepublication synchronization"),
        ] {
            /*
            Each row uses a new fixture because one fault must not affect another save.
            The source has one Undo record and one Redo record before the injected phase starts.
            */
            let fixture = Fixture::new();
            let path = fixture.0.join(format!("{name}.bin"));
            fs::write(&path, b"abc").unwrap();
            let mut paged = paged_with_both_histories(&path);
            set_fault(fault);

            let error = replace_paged(&path, &paged).err().unwrap();
            assert!(matches!(&error, PagedSaveError::Retained(_)));
            assert_eq!(error.to_string(), format!("Injected {phase} failure."));
            assert_eq!(fs::read(&path).unwrap(), b"abc");
            assert!(fixture.recovery_dirs().is_empty());
            assert!(paged.editing());
            assert_both_histories(&mut paged);
        }

        /*
        Save As uses only the logical-result and preparation-sync phases.
        Each refusal leaves the new destination absent and preserves the independent original source.
        */
        for (name, fault, phase) in [
            (
                "save-as-logical-partial",
                FAULT_PAGED_NEW_PARTIAL,
                "partial logical write",
            ),
            (
                "save-as-pre-sync",
                FAULT_PRE_SYNC,
                "prepublication synchronization",
            ),
        ] {
            let fixture = Fixture::new();
            let source_path = fixture.0.join(format!("{name}-source.bin"));
            let destination = fixture.0.join(format!("{name}-destination.bin"));
            fs::write(&source_path, b"abc").unwrap();
            let mut paged = paged_with_both_histories(&source_path);
            set_fault(fault);

            let error = save_as_paged(&destination, &paged).err().unwrap();
            assert!(matches!(&error, PagedSaveError::Retained(_)));
            assert_eq!(error.to_string(), format!("Injected {phase} failure."));
            assert!(!destination.exists());
            assert_eq!(fs::read(&source_path).unwrap(), b"abc");
            assert!(fixture.recovery_dirs().is_empty());
            assert_both_histories(&mut paged);
        }
    }

    /*
    This test replaces the source pathname after staging and before the final source guard.
    The retained owner rejects the new identity, and cancellation does not accept the replacement as a new baseline.
    */
    #[test]
    fn paged_late_source_substitution_refuses_publication() {
        let fixture = Fixture::new();
        let path = fixture.0.join("late-source.bin");
        let moved = fixture.0.join("captured-source.bin");
        fs::write(&path, b"abc").unwrap();
        let mut paged = paged_with_both_histories(&path);
        set_late_source_substitute(&moved, b"external");

        let error = replace_paged(&path, &paged).err().unwrap();
        assert!(matches!(&error, PagedSaveError::Retained(_)));
        assert_eq!(
            error.to_string(),
            "The source path identifies a different file. Reopen the source."
        );
        assert_eq!(fs::read(&path).unwrap(), b"external");
        assert_eq!(fs::read(&moved).unwrap(), b"abc");
        assert!(fixture.recovery_dirs().is_empty());
        assert!(paged.editing());
        assert!(paged.has_changes());

        /*
        Explicit cancellation restores the captured source spans without changing the source stamp.
        The moved pathname remains unavailable through the original captured path.
        */
        paged.cancel_edit();
        assert!(!paged.editing());
        assert!(!paged.has_changes());
        assert!(paged.validate().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"external");
        assert_eq!(fs::read(&moved).unwrap(), b"abc");
    }

    /*
    This test stops replacement and Save As immediately before rename.
    Exact recovery contents and native notes prove that publication did not occur and state remains available.
    */
    #[test]
    fn paged_publication_failures_retain_exact_recovery() {
        let fixture = Fixture::new();

        /*
        Replacement uses a non-UTF-8 target to verify escaped display text and exact native note bytes.
        A later write through the original descriptor cannot change the independent prepared files.
        */
        let replace_parent = fixture
            .0
            .join(std::ffi::OsString::from_vec(b"native-\xff".to_vec()));
        fs::create_dir(&replace_parent).unwrap();
        let replace_path = replace_parent.join("replace.bin");
        fs::write(&replace_path, b"abc").unwrap();
        let original = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&replace_path)
            .unwrap();
        let mut replace_source = paged_with_both_histories(&replace_path);
        set_fault(FAULT_PUBLISH);
        let error = replace_paged(&replace_path, &replace_source).err().unwrap();
        assert!(matches!(&error, PagedSaveError::Retained(_)));
        assert_eq!(fs::read(&replace_path).unwrap(), b"abc");
        let replace_recovery = recovery_for_target(&replace_path);
        assert_eq!(
            recovery_entries(&replace_recovery),
            [
                b"new.bin".to_vec(),
                b"original.bin".to_vec(),
                b"target.txt".to_vec()
            ]
        );
        assert_eq!(
            fs::read(replace_recovery.join("original.bin")).unwrap(),
            b"abc"
        );
        assert_eq!(fs::read(replace_recovery.join("new.bin")).unwrap(), b"Xbc");
        assert_eq!(
            error.to_string(),
            format!(
                "Save publication failed. Recovery files remain in {}. Error: Injected publication failure.",
                display_path(&replace_recovery)
            )
        );
        assert!(error.to_string().contains("\\xFF"));
        assert_both_histories(&mut replace_source);
        original.write_all_at(b"new", 0).unwrap();
        assert_eq!(
            fs::read(replace_recovery.join("original.bin")).unwrap(),
            b"abc"
        );
        assert_eq!(fs::read(replace_recovery.join("new.bin")).unwrap(), b"Xbc");

        /*
        Save As keeps the destination absent and retains only the prepared result and native target note.
        The original source and both history directions remain available after the refusal.
        */
        let source_path = fixture.0.join("save-as-publish-source.bin");
        let destination = fixture.0.join("save-as-publish-destination.bin");
        fs::write(&source_path, b"abc").unwrap();
        let mut save_as_source = paged_with_both_histories(&source_path);
        set_fault(FAULT_PUBLISH);
        let error = save_as_paged(&destination, &save_as_source).err().unwrap();
        assert!(matches!(&error, PagedSaveError::Retained(_)));
        assert!(!destination.exists());
        let save_as_recovery = recovery_for_target(&destination);
        assert_eq!(
            recovery_entries(&save_as_recovery),
            [b"new.bin".to_vec(), b"target.txt".to_vec()]
        );
        assert_eq!(fs::read(save_as_recovery.join("new.bin")).unwrap(), b"Xbc");
        assert_eq!(
            error.to_string(),
            format!(
                "Save publication failed. Recovery files remain in {}. Error: Injected publication failure.",
                display_path(&save_as_recovery)
            )
        );
        assert_both_histories(&mut save_as_source);
        assert_eq!(fs::read(&source_path).unwrap(), b"abc");
    }

    /*
    This test creates the Save As destination after preflight and before the exclusive rename.
    The real RENAME_NOREPLACE error preserves the raced bytes, prepared result, target note, and editor history.
    */
    #[test]
    fn paged_save_as_race_uses_exclusive_publication() {
        let fixture = Fixture::new();
        let source_path = fixture.0.join("race-source.bin");
        let destination = fixture.0.join("race-destination.bin");
        fs::write(&source_path, b"abc").unwrap();
        let mut source = paged_with_both_histories(&source_path);
        set_destination_race(b"raced");

        let error = save_as_paged(&destination, &source).err().unwrap();
        let kind = match &error {
            PagedSaveError::Retained(error) => error.kind(),
            _ => panic!("The raced destination reached a published outcome."),
        };
        assert_eq!(kind, io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"raced");
        let recovery = recovery_for_target(&destination);
        assert_eq!(
            recovery_entries(&recovery),
            [b"new.bin".to_vec(), b"target.txt".to_vec()]
        );
        assert_eq!(fs::read(recovery.join("new.bin")).unwrap(), b"Xbc");
        let os_error = io::Error::from_raw_os_error(17);
        assert_eq!(
            error.to_string(),
            format!(
                "Save publication failed. Recovery files remain in {}. Error: {os_error}",
                display_path(&recovery)
            )
        );
        assert_both_histories(&mut source);
        assert_eq!(fs::read(&source_path).unwrap(), b"abc");
    }

    /*
    This test substitutes the private stage name before its descriptor opens.
    Descriptor-relative cleanup must not follow the link or change the outside fixture.
    */
    #[test]
    fn paged_stage_substitution_preserves_outside_fixture() {
        let fixture = Fixture::new();
        let source_path = fixture.0.join("stage-source.bin");
        let destination = fixture.0.join("stage-destination.bin");
        let outside = fixture.0.join("outside.bin");
        fs::write(&source_path, b"abc").unwrap();
        fs::write(&outside, b"outside").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o640)).unwrap();
        let mut source = paged_with_both_histories(&source_path);
        set_stage_substitute(&outside);

        let error = save_as_paged(&destination, &source).err().unwrap();
        assert!(matches!(error, PagedSaveError::Retained(_)));
        assert!(!destination.exists());
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        assert_eq!(fs::metadata(&outside).unwrap().mode() & 0o777, 0o640);
        assert_eq!(fixture.recovery_dirs().len(), 1);
        assert!(
            fs::symlink_metadata(&fixture.recovery_dirs()[0])
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_both_histories(&mut source);
    }

    /*
    This test replaces one buffered target while preserving policy metadata and an independent backup.
    Later source-descriptor writes prove that neither published file aliases the old descriptor.
    */
    #[test]
    fn replace_preserves_bytes_metadata_and_independent_backup() {
        /*
        The first section creates the source metadata and captures its prepublication inode.
        Exact timestamps and a user xattr make policy loss visible.
        */
        let fixture = Fixture::new();
        let path = fixture.0.join("sample.bin");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        set_test_xattr(&file, c"user.hview-test", b"metadata");
        let times = [
            Timespec {
                tv_sec: 1_600_000_000,
                tv_nsec: 123_456_789,
            },
            Timespec {
                tv_sec: 1_600_000_001,
                tv_nsec: 987_654_321,
            },
        ];
        assert_eq!(unsafe { futimens(file.as_raw_fd(), times.as_ptr()) }, 0);
        let source = source_metadata(&file).unwrap();
        let old_inode = file.metadata().unwrap().ino();

        /*
        The second section checks published bytes, backup bytes, identity, and every preserved metadata field.
        The backup timestamp check occurs before reading its contents can update access time.
        */
        let (backup, saved) = replace(&path, &file, b"original", b"edited").unwrap();
        let backup_file = File::open(&backup).unwrap();
        let backup_metadata = backup_file.metadata().unwrap();
        assert_eq!(
            (backup_metadata.atime(), backup_metadata.atime_nsec()),
            (times[0].tv_sec, times[0].tv_nsec)
        );
        assert_eq!(
            (backup_metadata.mtime(), backup_metadata.mtime_nsec()),
            (times[1].tv_sec, times[1].tv_nsec)
        );
        assert_eq!(fs::read(&path).unwrap(), b"edited");
        assert_eq!(fs::read(&backup).unwrap(), b"original");
        assert_ne!(saved.metadata().unwrap().ino(), old_inode);
        assert_eq!(
            saved.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
        assert_eq!(saved.metadata().unwrap().mode() & 0o7777, 0o640);
        assert_eq!(saved.metadata().unwrap().uid(), source.state.uid);
        assert_eq!(saved.metadata().unwrap().gid(), source.state.gid);
        assert_eq!(backup_metadata.mode() & 0o7777, 0o640);
        assert_eq!(backup_metadata.uid(), source.state.uid);
        assert_eq!(backup_metadata.gid(), source.state.gid);
        assert_eq!(xattrs(&saved).unwrap(), source.state.xattrs);
        assert_eq!(xattrs(&backup_file).unwrap(), source.state.xattrs);

        /*
        A write through the old descriptor changes only the unlinked inode.
        The published replacement and independent backup must keep their accepted bytes.
        */
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"changed!").unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"original");
        assert_eq!(fs::read(&path).unwrap(), b"edited");
    }

    /*
    This test redirects buffered paths to different files with identical accepted bytes.
    Replacement must refuse each identity before staging or changing either file.
    */
    #[test]
    fn buffered_replacement_rejects_matching_path_substitution_before_staging() {
        for redirect_parent in [false, true] {
            /*
            Both regular files contain the same bytes while their descriptors identify different inodes.
            The source selector supplies the accepted bytes and their original read descriptor.
            */
            let fixture = Fixture::new();
            let first = fixture.0.join("first");
            let second = fixture.0.join("second");
            fs::create_dir(&first).unwrap();
            fs::create_dir(&second).unwrap();
            let original_path = first.join("sample.bin");
            let other_path = second.join("sample.bin");
            fs::write(&original_path, b"same").unwrap();
            fs::write(&other_path, b"same").unwrap();
            let parent = fixture.0.join("parent");
            symlink(&first, &parent).unwrap();
            let path = if redirect_parent {
                parent.join("sample.bin")
            } else {
                original_path.clone()
            };
            let crate::paged::OpenedSource::Buffered { data, file, .. } =
                crate::paged::open_source(&path).unwrap()
            else {
                panic!("The short source must use buffered storage.");
            };
            let original_inode = file.metadata().unwrap().ino();

            /*
            A parent-link change or pathname replacement redirects the writable target after the read.
            The retained descriptor prevents the original inode from becoming available for reuse.
            */
            if redirect_parent {
                fs::remove_file(&parent).unwrap();
                symlink(&second, &parent).unwrap();
            } else {
                fs::rename(&original_path, first.join("moved.bin")).unwrap();
                fs::write(&original_path, b"same").unwrap();
            }
            assert_ne!(fs::metadata(&path).unwrap().ino(), original_inode);
            assert_eq!(fs::read(&path).unwrap(), data);
            let error = replace(&path, &file, &data, b"edit").unwrap_err();
            assert!(error.to_string().contains("changed outside the editor"));
            assert_eq!(fs::read(&original_path).unwrap(), b"same");
            assert_eq!(fs::read(&other_path).unwrap(), b"same");
            assert_eq!(
                fs::read_dir(&first).unwrap().count(),
                if redirect_parent { 1 } else { 2 }
            );
            assert_eq!(fs::read_dir(&second).unwrap().count(), 1);
            assert!(fixture.recovery_dirs().is_empty());
        }
    }

    /*
    This test uses each published buffered descriptor as the identity for the next replacement.
    A retained descriptor from an earlier Save must fail even when the accepted bytes match.
    */
    #[test]
    fn buffered_replacement_renews_identity_for_repeated_saves() {
        let fixture = Fixture::new();
        let path = fixture.0.join("repeat.bin");
        fs::write(&path, b"first").unwrap();
        let crate::paged::OpenedSource::Buffered { data, file, .. } =
            crate::paged::open_source(&path).unwrap()
        else {
            panic!("The short source must use buffered storage.");
        };
        let (first_backup, first) = replace(&path, &file, &data, b"second").unwrap();
        assert_eq!(fs::read(first_backup).unwrap(), b"first");
        assert_eq!(
            first.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
        assert!(replace(&path, &file, b"second", b"stale").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"second");

        /*
        The returned descriptor identifies the prepared inode after publication without a new path open.
        A second Save must adopt another new descriptor and preserve its exact preceding backup.
        */
        let (second_backup, second) = replace(&path, &first, b"second", b"third").unwrap();
        assert_eq!(fs::read(second_backup).unwrap(), b"second");
        assert_eq!(fs::read(&path).unwrap(), b"third");
        assert_ne!(
            first.metadata().unwrap().ino(),
            second.metadata().unwrap().ino()
        );
        assert_eq!(
            second.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
        assert_eq!(fixture.recovery_dirs().len(), 2);
    }

    /*
    This test retains the resolved Save As path and its prepared descriptor.
    A later parent-link change cannot redirect replacement Save to another matching file.
    */
    #[test]
    fn buffered_save_as_retains_resolved_path_and_supports_replacement() {
        let fixture = Fixture::new();
        let first = fixture.0.join("first");
        let second = fixture.0.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let parent = fixture.0.join("parent");
        symlink(&first, &parent).unwrap();
        let (path, file) = save_as(&parent.join("copy.bin"), b"saved").unwrap();
        assert_eq!(path, first.join("copy.bin"));
        assert_eq!(
            file.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
        assert!(fs::read_dir(&first).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .as_bytes()
                .starts_with(b".HView-save-")
        }));

        /*
        Save As returns the canonical parent path used for descriptor-relative publication.
        Replacement uses that path and the returned descriptor after the original parent link changes.
        */
        fs::write(second.join("copy.bin"), b"saved").unwrap();
        fs::remove_file(&parent).unwrap();
        symlink(&second, &parent).unwrap();
        let (_, published) = replace(&path, &file, b"saved", b"edited").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"edited");
        assert_eq!(fs::read(parent.join("copy.bin")).unwrap(), b"saved");
        assert_eq!(
            published.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
    }

    /*
    This test rejects changed bytes, nonregular paths, links, locks, and pathname substitution.
    Each condition stops before buffered replacement publication.
    */
    #[test]
    fn replace_rejects_content_path_links_and_locks() {
        /*
        Initial checks cover stale accepted bytes and a directory target.
        Both inputs keep their existing filesystem objects unchanged.
        */
        let fixture = Fixture::new();
        let path = fixture.0.join("sample.bin");
        fs::write(&path, b"changed").unwrap();
        assert!(replace(&path, &File::open(&path).unwrap(), b"original", b"edit").is_err());
        assert!(
            replace(&fixture.0, &File::open(&fixture.0).unwrap(), b"", b"edit")
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );

        /*
        Symbolic-link and hard-link checks preserve every linked source path.
        Removing the test hard link restores one-link state for the lock check.
        */
        let link = fixture.0.join("link.bin");
        symlink(&path, &link).unwrap();
        assert!(
            replace(&link, &File::open(&link).unwrap(), b"changed", b"edit")
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );

        let hard = fixture.0.join("hard.bin");
        fs::hard_link(&path, &hard).unwrap();
        assert!(
            replace(&path, &File::open(&path).unwrap(), b"changed", b"edit")
                .unwrap_err()
                .to_string()
                .contains("hard links")
        );
        fs::remove_file(&hard).unwrap();

        /*
        An advisory lock held by another descriptor blocks compatible replacement.
        Releasing the fixture lock permits later checks to use the target.
        */
        let lock = File::open(&path).unwrap();
        lock.try_lock().unwrap();
        assert!(
            replace(&path, &File::open(&path).unwrap(), b"changed", b"edit")
                .unwrap_err()
                .to_string()
                .contains("in use")
        );
        drop(lock);

        /*
        The final section replaces the pathname after descriptor state capture.
        The repeated target open detects the new inode before publication.
        */
        let target = target(&path).unwrap();
        let original = open_target(&target).unwrap();
        let state = file_state(&original).unwrap();
        let moved = fixture.0.join("moved.bin");
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"changed").unwrap();
        let mut original = original;
        assert!(check_target(&target, &mut original, &state, b"changed").is_err());
    }

    /*
    This test refuses unwritable and privileged buffered replacement targets.
    Every refusal preserves original bytes and creates no recovery data.
    */
    #[test]
    fn replace_rejects_read_only_and_privilege_modes() {
        let fixture = Fixture::new();
        let read_only = fixture.0.join("read-only.bin");
        fs::write(&read_only, b"original").unwrap();
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o444)).unwrap();
        let error = replace(
            &read_only,
            &File::open(&read_only).unwrap(),
            b"original",
            b"edited",
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("Save As"));
        assert_eq!(fs::read(&read_only).unwrap(), b"original");

        /*
        Each privileged mode receives its own target and exact mode assertion.
        The shared policy error identifies both set-user-ID and set-group-ID conditions.
        */
        for (name, mode) in [("setuid.bin", 0o4755), ("setgid.bin", 0o2755)] {
            let path = fixture.0.join(name);
            fs::write(&path, b"original").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, mode);
            let error =
                replace(&path, &File::open(&path).unwrap(), b"original", b"edited").unwrap_err();
            assert!(error.to_string().contains("set-user-ID or set-group-ID"));
            assert_eq!(fs::read(&path).unwrap(), b"original");
        }
        assert!(fixture.recovery_dirs().is_empty());
    }

    /*
    This test substitutes the recovery directory name with a link to an outside file.
    Descriptor checks must preserve the victim bytes and permissions.
    */
    #[test]
    fn stage_name_substitution_does_not_change_victim_permissions() {
        let fixture = Fixture::new();
        let victim = fixture.0.join("victim.bin");
        fs::write(&victim, b"victim").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        set_stage_substitute(&victim);

        let target = fixture.0.join("new.bin");
        assert!(save_as(&target, b"new").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o7777, 0o644);
        let residue = fixture.recovery_dirs();
        assert_eq!(residue.len(), 1);
        assert!(
            fs::symlink_metadata(&residue[0])
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /*
    This test verifies exclusive buffered Save As for files, links, and a destination race.
    A refused race retains prepared bytes in its private recovery directory.
    */
    #[test]
    fn save_as_uses_atomic_destination_refusal() {
        /*
        Initial publication creates one destination and refuses a second write to the same name.
        Existing destination bytes remain exact.
        */
        let fixture = Fixture::new();
        let path = fixture.0.join("new.bin");
        assert_eq!(save_as(&path, b"new").unwrap().0, path);
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            save_as(&path, b"overwrite").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"new");

        /*
        A dangling link is still an existing destination entry.
        Exclusive publication must preserve the link itself.
        */
        let dangling = fixture.0.join("dangling.bin");
        symlink(fixture.0.join("missing.bin"), &dangling).unwrap();
        assert_eq!(
            save_as(&dangling, b"overwrite").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(
            fs::symlink_metadata(&dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        /*
        The race fixture creates a link after preparation and before exclusive rename.
        RENAME_NOREPLACE preserves both the raced entry and staged new bytes.
        */
        let raced_path = fixture.0.join("raced.bin");
        let raced_target = target(&raced_path).unwrap();
        let mut stage = Stage::new(&raced_target).unwrap();
        let _new_file = prepare_new(&stage, b"staged", None).unwrap();
        stage.sync_preparation().unwrap();
        symlink(fixture.0.join("missing-raced.bin"), &raced_path).unwrap();
        assert_eq!(
            stage.publish(&raced_target, false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(stage.folder_path.join("new.bin")).unwrap(),
            b"staged"
        );
        assert!(
            fs::symlink_metadata(&raced_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /*
    This test maps each injected buffered failure phase to cleanup, recovery, and visible publication state.
    It preserves actual target bytes at every boundary.
    */
    #[test]
    fn failures_keep_or_remove_the_correct_recovery_data() {
        /*
        Private write and prepublication synchronization failures remove incomplete stage data.
        Neither phase creates the destination.
        */
        let fixture = Fixture::new();
        let path = fixture.0.join("new.bin");

        set_fault(FAULT_WRITE);
        assert!(save_as(&path, b"partial data").is_err());
        assert!(!path.exists());
        assert!(fixture.recovery_dirs().is_empty());

        set_fault(FAULT_PRE_SYNC);
        assert!(save_as(&path, b"prepared data").is_err());
        assert!(!path.exists());
        assert!(fixture.recovery_dirs().is_empty());

        /*
        A Save As publication failure retains complete prepared bytes for recovery.
        The destination does not exist because rename did not occur.
        */
        set_fault(FAULT_PUBLISH);
        let error = save_as(&path, b"recover data").unwrap_err();
        assert!(error.to_string().contains("Recovery files remain"));
        let recovery = fixture.recovery_dirs();
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            fs::read(recovery[0].join("new.bin")).unwrap(),
            b"recover data"
        );
        fs::remove_dir_all(&recovery[0]).unwrap();

        /*
        A final Save As synchronization failure follows rename.
        The error states that destination bytes can already be visible and retains recovery evidence.
        */
        set_fault(FAULT_FINAL_SYNC);
        let error = save_as(&path, b"visible data").unwrap_err();
        assert!(error.to_string().contains("may already be visible"));
        assert_eq!(fs::read(&path).unwrap(), b"visible data");
        assert_eq!(fixture.recovery_dirs().len(), 1);
        for recovery in fixture.recovery_dirs() {
            fs::remove_dir_all(recovery).unwrap();
        }

        /*
        Replacement publication failure retains original, new, and target-note files.
        The external target keeps original bytes until rename succeeds.
        */
        let replace_path = fixture.0.join("replace.bin");
        fs::write(&replace_path, b"original").unwrap();
        let accepted = File::open(&replace_path).unwrap();
        set_fault(FAULT_PUBLISH);
        let error = replace(&replace_path, &accepted, b"original", b"edited").unwrap_err();
        assert!(error.to_string().contains("Recovery files remain"));
        assert_eq!(fs::read(&replace_path).unwrap(), b"original");
        let recovery = fixture.recovery_dirs();
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            fs::read(recovery[0].join("original.bin")).unwrap(),
            b"original"
        );
        assert_eq!(fs::read(recovery[0].join("new.bin")).unwrap(), b"edited");
        fs::remove_dir_all(&recovery[0]).unwrap();

        /*
        Replacement final synchronization failure keeps the new target and independent original backup.
        Retained recovery data explains both byte states.
        */
        set_fault(FAULT_FINAL_SYNC);
        let error = replace(&replace_path, &accepted, b"original", b"edited").unwrap_err();
        assert!(error.to_string().contains("may already be visible"));
        assert_eq!(fs::read(&replace_path).unwrap(), b"edited");
        let recovery = fixture.recovery_dirs();
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            fs::read(recovery[0].join("original.bin")).unwrap(),
            b"original"
        );

        /*
        Final synchronization failure returns no replacement descriptor to adopt.
        A retry with the retained original descriptor must refuse the published inode before staging.
        */
        assert!(replace(&replace_path, &accepted, b"edited", b"retry").is_err());
        assert_eq!(fs::read(&replace_path).unwrap(), b"edited");
        assert_eq!(fixture.recovery_dirs().len(), 1);
    }

    /*
    This test replaces one edited paged source and verifies bytes, metadata, backup times, and fresh history.
    A later canceled edit proves that the reopened owner supplies the new source baseline.
    */
    #[test]
    fn paged_replacement_preserves_metadata_and_adopts_the_prepared_inode() {
        let fixture = Fixture::new();
        let path = fixture.0.join("paged.bin");
        fs::write(&path, b"abcdef").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        set_test_xattr(&file, c"user.hview-paged", b"metadata");
        let times = [
            Timespec {
                tv_sec: 1_600_000_100,
                tv_nsec: 123_456_789,
            },
            Timespec {
                tv_sec: 1_600_000_101,
                tv_nsec: 987_654_321,
            },
        ];
        assert_eq!(unsafe { futimens(file.as_raw_fd(), times.as_ptr()) }, 0);
        let expected = source_metadata(&file).unwrap();

        let paged = edited_paged(&path, 2, 2, b"XYZ");
        let outcome = replace_paged(&path, &paged).unwrap();
        let backup = outcome.backup.unwrap();
        assert_eq!(outcome.path, path);
        assert!(outcome.warning.is_none());
        assert_eq!(fs::read(&path).unwrap(), b"abXYZef");
        assert_eq!(small_paged_bytes(&outcome.source), b"abXYZef");
        assert!(!outcome.source.editing());
        assert!(!outcome.source.has_changes());

        /*
        This section checks replacement and backup metadata after every bounded verification read completed.
        The restored backup timestamps must remain exact at the operation boundary.
        */
        let saved = File::open(&path).unwrap();
        let saved_metadata = saved.metadata().unwrap();
        let backup_file = File::open(&backup).unwrap();
        let backup_metadata = backup_file.metadata().unwrap();
        assert_ne!(saved_metadata.ino(), expected.state.ino);
        assert!(
            outcome
                .source
                .has_identity(saved_metadata.dev(), saved_metadata.ino())
                .unwrap()
        );
        assert_eq!(saved_metadata.mode() & 0o7777, 0o640);
        assert_eq!(saved_metadata.uid(), expected.state.uid);
        assert_eq!(saved_metadata.gid(), expected.state.gid);
        assert_eq!(xattrs(&saved).unwrap(), expected.state.xattrs);
        assert_eq!(xattrs(&backup_file).unwrap(), expected.state.xattrs);
        assert_eq!(
            (backup_metadata.atime(), backup_metadata.atime_nsec()),
            (times[0].tv_sec, times[0].tv_nsec)
        );
        assert_eq!(
            (backup_metadata.mtime(), backup_metadata.mtime_nsec()),
            (times[1].tv_sec, times[1].tv_nsec)
        );
        assert_eq!(fs::read(&backup).unwrap(), b"abcdef");

        /*
        A later write through the original descriptor changes only its unlinked source inode.
        The retained backup and published result must remain independent from that descriptor.
        */
        file.write_all_at(b"UVWXYZ", 0).unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"abcdef");
        assert_eq!(fs::read(&path).unwrap(), b"abXYZef");

        /*
        A new edit and cancellation use the published bytes as the fresh baseline.
        The adopted PagedFile owns the verified staged inode and no retained history.
        */
        let mut reopened = outcome.source;
        reopened.begin_edit().unwrap();
        assert_eq!(reopened.undo().unwrap(), None);
        assert_eq!(reopened.redo().unwrap(), None);
        reopened
            .replace_bytes(0, b"Q", paged_cursor(0), paged_cursor(1), false)
            .unwrap();
        reopened.cancel_edit();
        assert_eq!(small_paged_bytes(&reopened), b"abXYZef");
    }

    /*
    This test publishes replacement, insertion, deletion, and empty layouts through exclusive Save As.
    Each result owns a clean baseline while the original source bytes remain unchanged.
    */
    #[test]
    fn paged_save_as_preserves_each_structural_layout() {
        let fixture = Fixture::new();
        /*
        Each row prepares one logical layout and its exact expected destination bytes.
        The outcome must adopt a clean source while the original source remains unchanged.
        */
        for (name, start, remove, replacement, expected) in [
            ("unchanged", 0, 0, &b""[..], &b"abcdef"[..]),
            ("replace", 2, 2, &b"XYZ"[..], &b"abXYZef"[..]),
            ("insert", 6, 0, &b"!"[..], &b"abcdef!"[..]),
            ("delete", 1, 4, &b""[..], &b"af"[..]),
            ("empty", 0, 6, &b""[..], &b""[..]),
        ] {
            let source_path = fixture.0.join(format!("{name}-source.bin"));
            let destination = fixture.0.join(format!("{name}-copy.bin"));
            fs::write(&source_path, b"abcdef").unwrap();
            let paged = if remove == 0 && replacement.is_empty() {
                PagedFile::open(&source_path).unwrap()
            } else {
                edited_paged(&source_path, start, remove, replacement)
            };
            let outcome = save_as_paged(&destination, &paged).unwrap();
            assert_eq!(outcome.path, destination);
            assert_eq!(fs::read(&destination).unwrap(), expected);
            assert_eq!(small_paged_bytes(&outcome.source), expected);
            let metadata = fs::metadata(&destination).unwrap();
            assert!(
                outcome
                    .source
                    .has_identity(metadata.dev(), metadata.ino())
                    .unwrap()
            );
            assert_eq!(fs::read(&source_path).unwrap(), b"abcdef");
            assert!(outcome.backup.is_none());
            assert!(outcome.warning.is_none());
            assert!(!outcome.source.editing());
            assert!(!outcome.source.has_changes());
        }
    }

    /*
    This test publishes unchanged, replacement, growth, shrinkage, and empty layouts through replacement Save.
    Every recovery backup keeps the complete original bytes for its target.
    */
    #[test]
    fn paged_replacement_preserves_each_structural_layout() {
        let fixture = Fixture::new();
        /*
        Each row creates an independent target, logical layout, and expected result.
        The replacement outcome must own a clean baseline with an exact original backup.
        */
        for (name, start, remove, replacement, expected) in [
            ("unchanged", 0, 0, &b""[..], &b"abcdef"[..]),
            ("replace", 2, 2, &b"XY"[..], &b"abXYef"[..]),
            ("grow", 2, 1, &b"XYZ"[..], &b"abXYZdef"[..]),
            ("shrink", 1, 4, &b"Q"[..], &b"aQf"[..]),
            ("empty", 0, 6, &b""[..], &b""[..]),
        ] {
            let path = fixture.0.join(format!("replacement-{name}.bin"));
            fs::write(&path, b"abcdef").unwrap();
            let paged = if remove == 0 && replacement.is_empty() {
                PagedFile::open(&path).unwrap()
            } else {
                edited_paged(&path, start, remove, replacement)
            };
            let outcome = replace_paged(&path, &paged).unwrap();
            assert_eq!(fs::read(&path).unwrap(), expected);
            assert_eq!(small_paged_bytes(&outcome.source), expected);
            assert_eq!(fs::read(outcome.backup.unwrap()).unwrap(), b"abcdef");
            assert!(!outcome.source.editing());
            assert!(!outcome.source.has_changes());
        }
    }

    /*
    This test saves sparse high-offset source spans and memory bytes without dense physical allocation.
    The replacement backup remains independent and keeps the complete original sparse length.
    */
    #[test]
    fn paged_replacement_preserves_sparse_bytes_above_four_gib() {
        use std::os::unix::fs::FileExt;

        let fixture = Fixture::new();
        let path = fixture.0.join("sparse.bin");
        let length = (4_u64 << 30) + 0x20_001;
        let high = (4_u64 << 30) + 0x10_000;
        let file = File::create(&path).unwrap();
        file.set_len(length).unwrap();
        file.write_all_at(b"A", 0).unwrap();
        file.write_all_at(b"B", 65_536).unwrap();
        file.write_all_at(b"Z", length - 1).unwrap();
        file.sync_all().unwrap();

        let paged = edited_paged(&path, high, 0, b"XY");
        let outcome = replace_paged(&path, &paged).unwrap();
        let backup = outcome.backup.unwrap();
        assert_eq!(outcome.source.len(), length + 2);
        let saved = File::open(&path).unwrap();
        let original = File::open(&backup).unwrap();
        let mut bytes = [0_u8; 2];
        saved.read_exact_at(&mut bytes, high).unwrap();
        assert_eq!(&bytes, b"XY");
        saved.read_exact_at(&mut bytes[..1], length + 1).unwrap();
        assert_eq!(bytes[0], b'Z');
        original.read_exact_at(&mut bytes[..1], high).unwrap();
        assert_eq!(bytes[0], 0);
        original.read_exact_at(&mut bytes[..1], length - 1).unwrap();
        assert_eq!(bytes[0], b'Z');
        assert_eq!(original.metadata().unwrap().len(), length);
        assert!(saved.metadata().unwrap().blocks() * 512 < 16 * 1024 * 1024);
        assert!(original.metadata().unwrap().blocks() * 512 < 16 * 1024 * 1024);
    }

    /*
    This test distinguishes final synchronization warnings from published reopen failures.
    Save As reopen failure must retain the original paged edit owner and its history.
    */
    #[test]
    fn paged_publication_outcomes_preserve_the_correct_owner() {
        let fixture = Fixture::new();

        /*
        A post-rename synchronization failure returns a warning with an adopted new baseline.
        Published target bytes prove that the warning cannot describe an unchanged file.
        */
        let warning_path = fixture.0.join("warning.bin");
        fs::write(&warning_path, b"abc").unwrap();
        let warning_source = paged_with_both_histories(&warning_path);
        set_fault(FAULT_FINAL_SYNC);
        let mut warning = replace_paged(&warning_path, &warning_source).unwrap();
        assert_eq!(fs::read(&warning_path).unwrap(), b"Xbc");
        let warning_recovery = recovery_for_target(&warning_path);
        assert_eq!(
            recovery_entries(&warning_recovery),
            [b"original.bin".to_vec(), b"target.txt".to_vec()]
        );
        assert_eq!(
            fs::read(warning_recovery.join("original.bin")).unwrap(),
            b"abc"
        );
        assert_eq!(
            warning.warning.unwrap(),
            format!(
                "Publication finished, but final synchronization failed. New bytes may already be visible. Recovery files remain in {}. Error: Injected final synchronization failure.",
                display_path(&warning_recovery)
            )
        );
        assert!(!warning.source.editing());
        warning.source.begin_edit().unwrap();
        assert_eq!(warning.source.undo().unwrap(), None);
        assert_eq!(warning.source.redo().unwrap(), None);

        /*
        Save As final synchronization failure also adopts the published destination with a warning.
        The original source path and bytes remain independent.
        */
        let warning_source_path = fixture.0.join("save-as-warning-source.bin");
        let warning_destination = fixture.0.join("save-as-warning-destination.bin");
        fs::write(&warning_source_path, b"abc").unwrap();
        let warning_source = paged_with_both_histories(&warning_source_path);
        set_fault(FAULT_FINAL_SYNC);
        let mut warning = save_as_paged(&warning_destination, &warning_source).unwrap();
        assert_eq!(warning.path, warning_destination);
        assert_eq!(fs::read(&warning_destination).unwrap(), b"Xbc");
        assert_eq!(fs::read(&warning_source_path).unwrap(), b"abc");
        let warning_recovery = recovery_for_target(&warning_destination);
        assert_eq!(
            recovery_entries(&warning_recovery),
            [b"target.txt".to_vec()]
        );
        assert_eq!(
            warning.warning.unwrap(),
            format!(
                "Publication finished, but final synchronization failed. New bytes may already be visible. Recovery files remain in {}. Error: Injected final synchronization failure.",
                display_path(&warning_recovery)
            )
        );
        assert!(!warning.source.editing());
        warning.source.begin_edit().unwrap();
        assert_eq!(warning.source.undo().unwrap(), None);
        assert_eq!(warning.source.redo().unwrap(), None);

        /*
        Replacement reopen failure reports an unusable active path and independent backup location.
        The external target already contains new bytes.
        */
        let replace_path = fixture.0.join("replace-reopen.bin");
        fs::write(&replace_path, b"abc").unwrap();
        let replace_source = edited_paged(&replace_path, 0, 1, b"Y");
        set_fault(FAULT_PAGED_REOPEN);
        let error = replace_paged(&replace_path, &replace_source).err().unwrap();
        assert!(matches!(&error, PagedSaveError::PublishedReplacement(_)));
        assert!(error.to_string().contains("Original bytes remain"));
        assert_eq!(fs::read(&replace_path).unwrap(), b"Ybc");
        let recovery = fixture.recovery_dirs();
        assert!(recovery.iter().any(|path| {
            fs::read(path.join("original.bin")).ok().as_deref() == Some(&b"abc"[..])
        }));

        /*
        Save As reopen failure keeps the original paged owner, logical edit, and both history directions.
        Explicit cancellation still restores the original source layout.
        */
        let source_path = fixture.0.join("save-as-source.bin");
        let destination = fixture.0.join("save-as-destination.bin");
        fs::write(&source_path, b"abc").unwrap();
        let mut save_as_source = edited_paged(&source_path, 0, 1, b"Z");
        set_fault(FAULT_PAGED_REOPEN);
        let error = save_as_paged(&destination, &save_as_source).err().unwrap();
        assert!(matches!(&error, PagedSaveError::PublishedSaveAs(_)));
        assert_eq!(fs::read(&destination).unwrap(), b"Zbc");
        assert_eq!(small_paged_bytes(&save_as_source), b"Zbc");
        assert!(save_as_source.undo().unwrap().is_some());
        assert_eq!(small_paged_bytes(&save_as_source), b"abc");
        assert!(save_as_source.redo().unwrap().is_some());
        save_as_source.cancel_edit();
        assert_eq!(small_paged_bytes(&save_as_source), b"abc");
        assert_eq!(fs::read(&source_path).unwrap(), b"abc");
    }

    /*
    This test replaces each published pathname with another inode before reopen validation.
    Replacement reports an unusable published path, while Save As retains the independent original edit owner.
    */
    #[test]
    fn paged_reopen_rejects_a_substituted_published_inode() {
        let fixture = Fixture::new();

        /*
        Replacement already published the logical bytes before the hook substitutes its pathname.
        The error identifies publication and the independent original backup without adopting the wrong inode.
        */
        let replace_path = fixture.0.join("substituted-replacement.bin");
        fs::write(&replace_path, b"abc").unwrap();
        let replace_source = paged_with_both_histories(&replace_path);
        set_published_substitute(b"outside");
        let error = replace_paged(&replace_path, &replace_source).err().unwrap();
        assert!(matches!(&error, PagedSaveError::PublishedReplacement(_)));
        assert_eq!(fs::read(&replace_path).unwrap(), b"outside");
        let replace_recovery = recovery_for_target(&replace_path);
        let backup = replace_recovery.join("original.bin");
        assert_eq!(
            recovery_entries(&replace_recovery),
            [b"original.bin".to_vec(), b"target.txt".to_vec()]
        );
        assert_eq!(fs::read(&backup).unwrap(), b"abc");
        assert_eq!(
            error.to_string(),
            format!(
                "Publication finished at {}. The replacement cannot reopen. Original bytes remain in {}. Reopen error: The published path identifies a different file.",
                display_path(&replace_path),
                display_path(&backup)
            )
        );

        /*
        Save As keeps the original path, descriptor, logical bytes, histories, and cursors after the identity error.
        Undo, Redo, and explicit cancellation remain usable because the original source did not change.
        */
        let source_path = fixture.0.join("substituted-save-as-source.bin");
        let destination = fixture.0.join("substituted-save-as-destination.bin");
        fs::write(&source_path, b"abc").unwrap();
        let mut save_as_source = paged_with_both_histories(&source_path);
        set_published_substitute(b"outside");
        let error = save_as_paged(&destination, &save_as_source).err().unwrap();
        assert!(matches!(&error, PagedSaveError::PublishedSaveAs(_)));
        assert_eq!(fs::read(&destination).unwrap(), b"outside");
        assert_eq!(fs::read(&source_path).unwrap(), b"abc");
        let save_as_recovery = recovery_for_target(&destination);
        assert_eq!(
            recovery_entries(&save_as_recovery),
            [b"target.txt".to_vec()]
        );
        assert_eq!(
            error.to_string(),
            format!(
                "Publication finished at {}, but the destination cannot reopen. The original source and memory edits remain active. Recovery files remain in {}. Reopen error: The published path identifies a different file.",
                display_path(&destination),
                display_path(&save_as_recovery)
            )
        );
        assert_both_histories(&mut save_as_source);
        save_as_source.cancel_edit();
        assert!(!save_as_source.editing());
        assert_eq!(small_paged_bytes(&save_as_source), b"abc");
        assert_eq!(fs::read(&source_path).unwrap(), b"abc");
    }

    /*
    This test refuses existing destinations, source aliases, and mismatched replacement identities before publication.
    Every failure keeps the source layout and Undo history available.
    */
    #[test]
    fn paged_save_refusals_keep_edit_state_and_destinations() {
        let fixture = Fixture::new();
        let source_path = fixture.0.join("source.bin");
        let existing = fixture.0.join("existing.bin");
        let other = fixture.0.join("other.bin");
        fs::write(&source_path, b"abc").unwrap();
        fs::write(&existing, b"existing").unwrap();
        fs::write(&other, b"other").unwrap();
        let mut source = edited_paged(&source_path, 0, 1, b"X");

        /*
        Existing and source-alias destinations fail before exclusive publication.
        A replacement path that identifies another file also fails the descriptor identity guard.
        */
        let existing_error = save_as_paged(&existing, &source).err().unwrap();
        assert!(matches!(existing_error, PagedSaveError::Retained(_)));
        assert_eq!(fs::read(&existing).unwrap(), b"existing");
        let alias_error = save_as_paged(&source_path, &source).err().unwrap();
        assert_eq!(
            match alias_error {
                PagedSaveError::Retained(error) => error.kind(),
                _ => panic!("The source alias reached publication."),
            },
            io::ErrorKind::InvalidInput
        );
        let replacement_error = replace_paged(&other, &source).err().unwrap();
        assert!(matches!(replacement_error, PagedSaveError::Retained(_)));
        assert_eq!(fs::read(&other).unwrap(), b"other");
        /*
        The accepted memory bytes and Undo record remain available after every refusal.
        One Undo restores the captured source bytes.
        */
        assert_eq!(small_paged_bytes(&source), b"Xbc");
        assert!(source.undo().unwrap().is_some());
        assert_eq!(small_paged_bytes(&source), b"abc");

        /*
        An external source change fails before staging and leaves the active edit owner intact.
        Explicit cancellation remains available without accepting a new source stamp.
        */
        let changed_path = fixture.0.join("changed.bin");
        fs::write(&changed_path, b"abc").unwrap();
        let mut changed_source = edited_paged(&changed_path, 0, 1, b"X");
        fs::write(&changed_path, b"external").unwrap();
        let error = replace_paged(&changed_path, &changed_source).err().unwrap();
        assert!(matches!(error, PagedSaveError::Retained(_)));
        assert!(changed_source.editing());
        assert!(changed_source.has_changes());
        changed_source.cancel_edit();
        assert!(!changed_source.editing());
        assert!(changed_source.validate().is_err());
        assert_eq!(fs::read(&changed_path).unwrap(), b"external");
        assert!(fixture.recovery_dirs().is_empty());
    }

    /*
    This test applies the established target policy to the paged replacement route.
    Symbolic links, hard links, advisory locks, read-only targets, and privileged modes must fail before publication.
    */
    #[test]
    fn paged_replacement_uses_existing_target_policy() {
        let fixture = Fixture::new();

        /*
        A symbolic-link target cannot identify the active source for replacement.
        The referenced regular file remains unchanged.
        */
        let symlink_source = fixture.0.join("symlink-source.bin");
        let symlink_path = fixture.0.join("symlink.bin");
        fs::write(&symlink_source, b"abc").unwrap();
        symlink(&symlink_source, &symlink_path).unwrap();
        let source = edited_paged(&symlink_source, 0, 1, b"X");
        let error = replace_paged(&symlink_path, &source).err().unwrap();
        assert!(error.to_string().contains("symbolic link"));
        assert_eq!(fs::read(&symlink_source).unwrap(), b"abc");

        /*
        A source with two pathname links fails the established replacement policy.
        Both names continue to identify the original bytes.
        */
        let hard_path = fixture.0.join("hard.bin");
        let hard_alias = fixture.0.join("hard-alias.bin");
        fs::write(&hard_path, b"abc").unwrap();
        fs::hard_link(&hard_path, &hard_alias).unwrap();
        let source = edited_paged(&hard_path, 0, 1, b"X");
        let error = replace_paged(&hard_path, &source).err().unwrap();
        assert!(error.to_string().contains("hard links"));
        assert_eq!(fs::read(&hard_alias).unwrap(), b"abc");

        /*
        Another compatible advisory lock blocks replacement before staging.
        Dropping the lock ends only the fixture condition.
        */
        let lock_path = fixture.0.join("locked.bin");
        fs::write(&lock_path, b"abc").unwrap();
        let source = edited_paged(&lock_path, 0, 1, b"X");
        let lock = File::open(&lock_path).unwrap();
        lock.try_lock().unwrap();
        let error = replace_paged(&lock_path, &source).err().unwrap();
        assert!(error.to_string().contains("in use"));
        drop(lock);

        /*
        A read-only target returns PermissionDenied and keeps its disk bytes.
        The test runs on the required unprivileged host identity.
        */
        let read_only = fixture.0.join("read-only.bin");
        fs::write(&read_only, b"abc").unwrap();
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o444)).unwrap();
        let source = edited_paged(&read_only, 0, 1, b"X");
        let error = replace_paged(&read_only, &source).err().unwrap();
        assert!(matches!(
            error,
            PagedSaveError::Retained(error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(fs::read(&read_only).unwrap(), b"abc");

        /*
        A privileged target mode fails before recovery staging starts.
        The final directory check confirms that every refusal left no recovery data.
        */
        let privileged = fixture.0.join("privileged.bin");
        fs::write(&privileged, b"abc").unwrap();
        fs::set_permissions(&privileged, fs::Permissions::from_mode(0o4755)).unwrap();
        let source = edited_paged(&privileged, 0, 1, b"X");
        let error = replace_paged(&privileged, &source).err().unwrap();
        assert!(error.to_string().contains("set-user-ID"));
        assert_eq!(fs::read(&privileged).unwrap(), b"abc");
        assert!(fixture.recovery_dirs().is_empty());
    }

    /*
    This test verifies POSIX access ACL preservation and removal of inherited ACLs for plain files.
    It covers both buffered and paged replacement paths.
    */
    #[test]
    fn acl_and_metadata_policy_are_explicit() {
        /*
        The fixture adds one named-user access ACL and a default parent ACL.
        Buffered replacement must copy the source ACL to target and backup.
        */
        let fixture = Fixture::new();
        let path = fixture.0.join("acl.bin");
        let plain_path = fixture.0.join("plain.bin");
        fs::write(&path, b"original").unwrap();
        fs::write(&plain_path, b"plain").unwrap();
        let status = Command::new("setfacl")
            .args(["-m", "u:1:r--"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let status = Command::new("setfacl")
            .args(["-m", "d:u:1:r--"])
            .arg(&fixture.0)
            .status()
            .unwrap();
        assert!(status.success());
        let original = File::open(&path).unwrap();
        let acl = xattrs(&original).unwrap();
        assert!(
            acl.iter()
                .any(|(name, _)| name == b"system.posix_acl_access")
        );
        let (backup, _) =
            replace(&path, &File::open(&path).unwrap(), b"original", b"edited").unwrap();
        assert_eq!(xattrs(&File::open(&path).unwrap()).unwrap(), acl);
        assert_eq!(xattrs(&File::open(backup).unwrap()).unwrap(), acl);

        /*
        The paged route uses the same ACL metadata functions for the published file and independent backup.
        The edit changes one byte without changing the accepted access ACL.
        */
        let paged_path = fixture.0.join("paged-acl.bin");
        fs::write(&paged_path, b"paged").unwrap();
        let status = Command::new("setfacl")
            .args(["-m", "u:1:r--"])
            .arg(&paged_path)
            .status()
            .unwrap();
        assert!(status.success());
        let paged_acl = xattrs(&File::open(&paged_path).unwrap()).unwrap();
        let paged = edited_paged(&paged_path, 0, 1, b"P");
        let outcome = replace_paged(&paged_path, &paged).unwrap();
        assert_eq!(
            xattrs(&File::open(&paged_path).unwrap()).unwrap(),
            paged_acl
        );
        assert_eq!(
            xattrs(&File::open(outcome.backup.unwrap()).unwrap()).unwrap(),
            paged_acl
        );

        /*
        A plain source must not acquire the parent default ACL in either published file.
        Stage metadata replacement removes inherited supported attributes before final verification.
        */
        let plain_attrs = xattrs(&File::open(&plain_path).unwrap()).unwrap();
        assert!(plain_attrs.is_empty());
        let (plain_backup, _) = replace(
            &plain_path,
            &File::open(&plain_path).unwrap(),
            b"plain",
            b"edited",
        )
        .unwrap();
        assert!(
            xattrs(&File::open(&plain_path).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(
            xattrs(&File::open(plain_backup).unwrap())
                .unwrap()
                .is_empty()
        );

        /*
        The final checks define accepted and refused xattr namespaces directly.
        Privileged metadata receives a specific policy message.
        */
        assert!(check_xattr_name(b"user.note").is_ok());
        assert!(check_xattr_name(b"system.posix_acl_access").is_ok());
        assert!(
            check_xattr_name(b"security.capability")
                .unwrap_err()
                .to_string()
                .contains("privileged")
        );
        assert!(check_xattr_name(b"system.unknown").is_err());
    }

    /*
    This test reports a missing destination parent before it creates a stage or target.
    The requested path remains absent.
    */
    #[test]
    fn staging_failure_does_not_change_a_target() {
        /*
        The missing parent makes target construction fail before private-directory creation.
        The error kind and absent destination identify that exact boundary.
        */
        let fixture = Fixture::new();
        let path = fixture.0.join("missing").join("new.bin");
        assert_eq!(
            save_as(&path, b"data").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!path.exists());
    }

    /*
    This test saves empty buffered output, a multiwindow backup, and one Unicode destination.
    The cases keep exact data across zero, large, and non-ASCII inputs.
    */
    #[test]
    fn empty_large_and_unicode_files_save() {
        /*
        The first section replaces a multiwindow source with an empty logical result.
        The target becomes empty while its independent backup keeps every original byte.
        */
        let fixture = Fixture::new();
        let path = fixture.0.join("large.bin");
        let data = vec![0xa5; 131_073];
        fs::write(&path, &data).unwrap();
        let (backup, _) = replace(&path, &File::open(&path).unwrap(), &data, b"").unwrap();
        assert!(fs::read(&path).unwrap().is_empty());
        assert_eq!(fs::read(backup).unwrap(), data);

        /*
        The final section publishes one buffered Save As path with non-ASCII UTF-8 characters.
        The exact native PathBuf and bytes survive publication.
        */
        let unicode = fixture.0.join("données.bin");
        assert_eq!(save_as(&unicode, b"new").unwrap().0, unicode);
        assert_eq!(fs::read(unicode).unwrap(), b"new");
    }
}
