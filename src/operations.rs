/*
This module provides masked search, comparison, and bounded byte transforms.
Comparison reads one guarded peer while the current Editor bytes remain unchanged.
The shared scanner keeps changed ranges across read windows and returns no partial canceled result.
*/
use crate::analysis::{Outcome, Progress, WINDOW_BYTES};
use crate::paged::{OpenedSource, SourceStamp, open_source};
use std::{borrow::Cow, fs, io, path::Path};

/*
Each search byte stores its required value and its significant-bit mask.
Wildcard nibbles clear the corresponding mask bits before matching begins.
*/
pub struct Pattern {
    bytes: Vec<(u8, u8)>,
}

/*
This parser accepts complete hexadecimal byte pairs after whitespace removal.
Each question mark leaves one nibble unconstrained for the later search.
Invalid input returns before a Pattern becomes available.
*/
pub fn parse_pattern(text: &str) -> Result<Pattern, String> {
    let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err("Enter complete hex byte pairs. Use ? for a wildcard nibble.".into());
    }
    /*
    Each pair contributes one value and one mask in input order.
    The completed vectors connect the parsed nibbles to the matching methods.
    */
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_chunks::<2>().0 {
        let mut value = 0;
        let mut mask = 0;
        for digit in pair {
            value <<= 4;
            mask <<= 4;
            if *digit != '?' {
                value |= digit
                    .to_digit(16)
                    .ok_or("The pattern contains an invalid hex digit.")?
                    as u8;
                mask |= 0x0f;
            }
        }
        bytes.push((value, mask));
    }
    Ok(Pattern { bytes })
}

/*
These methods construct exact patterns and search bounded slices.
The caller selects the start position and the search direction.
*/
impl Pattern {
    /*
    Exact input must contain one byte before the constructor assigns complete masks.
    Ownership moves into the Pattern without a second source-byte buffer.
    */
    pub fn exact(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Enter at least one search byte.".into());
        }
        Ok(Self {
            bytes: bytes.into_iter().map(|byte| (byte, 0xff)).collect(),
        })
    }

    /*
    The complete pattern must fit before any candidate slice enters the matcher.
    Forward searches exclude earlier positions, and backward searches include the selected start position.
    */
    pub fn find(&self, data: &[u8], start: usize, backward: bool) -> Option<usize> {
        let last = data.len().checked_sub(self.bytes.len())?;
        let matches = |offset: &usize| {
            self.bytes
                .iter()
                .zip(&data[*offset..])
                .all(|(&(value, mask), &byte)| byte & mask == value)
        };
        if backward {
            (0..=start.min(last)).rev().find(matches)
        } else {
            (start..=last).find(matches)
        }
    }
}

/*
This entry point opens the selected path only after the worker checks cancellation.
The existing source loader rejects nonregular peers and selects bounded storage.
Buffered peers retain their read descriptor through final source validation.
Paged peers retain their descriptor and use the existing 64 KiB read guard.
*/
pub(crate) fn compare_file_cancellable(
    left: &[u8],
    path: &Path,
    limit: usize,
    mut progress: impl FnMut(Progress) -> bool,
) -> Result<Outcome<Vec<(usize, String)>>, String> {
    if !progress(Progress::new(0, 0)) {
        return Ok(Outcome::Canceled);
    }
    match open_source(path).map_err(|error| error.to_string())? {
        OpenedSource::Buffered { data, file, stamp } => {
            /*
            Retain the loader stamp that validated the buffered bytes.
            Final checks compare the descriptor and pathname with that accepted stamp.
            Actual byte length preserves zero-length and short-content Linux virtual files.
            */
            difference_ranges_cancellable(
                left,
                data.len() as u64,
                limit,
                |start, len| Ok(Cow::Borrowed(&data[start as usize..start as usize + len])),
                || {
                    stamp.validate(SourceStamp::from_metadata(&file.metadata()?))?;
                    stamp.validate(SourceStamp::from_metadata(&fs::metadata(path)?))
                },
                progress,
            )
        }
        OpenedSource::Paged(source) => {
            /*
            Each paged callback owns one bounded window from the accepted descriptor.
            The final validation also protects results that stop at the range limit.
            */
            difference_ranges_cancellable(
                left,
                source.len(),
                limit,
                |start, len| {
                    source
                        .read_window(start, len)
                        .map(|window| Cow::Owned(window.bytes.into_vec()))
                },
                || source.validate(),
                progress,
            )
        }
    }
}

/*
This scanner compares the common byte range in bounded windows.
The read callback supplies borrowed buffered bytes or one owned paged window.
One pending range and eight peer bytes preserve previews across window boundaries.
The validation callback checks the source before a complete result becomes available.
*/
fn difference_ranges_cancellable<'a>(
    left: &[u8],
    right_len: u64,
    limit: usize,
    mut read: impl FnMut(u64, usize) -> io::Result<Cow<'a, [u8]>>,
    mut validate: impl FnMut() -> io::Result<()>,
    mut progress: impl FnMut(Progress) -> bool,
) -> Result<Outcome<Vec<(usize, String)>>, String> {
    let common = (left.len() as u64).min(right_len);
    let end = (left.len() as u64).max(right_len);
    let mut result = Vec::new();
    let mut offset = 0_u64;
    let mut start = None;
    let mut right_preview = Vec::with_capacity(8);

    /*
    Equal bytes close the pending range, while changed bytes extend that range.
    The pending start survives every window boundary until an equal byte or EOF closes the range.
    Reaching the requested range limit stops further source reads.
    */
    'scan: while offset < common && result.len() < limit {
        if !progress(Progress::new(offset, end)) {
            return Ok(Outcome::Canceled);
        }
        let count = (common - offset).min(WINDOW_BYTES as u64) as usize;
        let other = read(offset, count).map_err(|error| error.to_string())?;
        if other.len() != count {
            return Err("The comparison read returned an incomplete window.".into());
        }
        for (index, &byte) in other.iter().enumerate() {
            let position = offset + index as u64;
            if left[position as usize] != byte {
                start.get_or_insert(position as usize);
                if right_preview.len() < 8 {
                    right_preview.push(byte);
                }
            } else if let Some(range_start) = start.take() {
                result.push(difference_row(
                    left,
                    &right_preview,
                    range_start,
                    position,
                    right_len,
                ));
                right_preview.clear();
                if result.len() == limit {
                    offset = position;
                    break 'scan;
                }
            }
        }
        offset += count as u64;
    }

    /*
    An unequal tail contains no matching byte, so its length determines the complete range.
    Read only missing peer preview bytes instead of scanning a large sparse tail.
    A pending common-range difference joins the tail without a second result row.
    */
    if result.len() < limit {
        if common < end {
            start.get_or_insert(common as usize);
            let count = (right_len - common).min((8 - right_preview.len()) as u64) as usize;
            if count != 0 {
                if !progress(Progress::new(common, end)) {
                    return Ok(Outcome::Canceled);
                }
                let other = read(common, count).map_err(|error| error.to_string())?;
                if other.len() != count {
                    return Err("The comparison read returned an incomplete window.".into());
                }
                right_preview.extend_from_slice(&other);
            }
            offset = end;
        }
        if let Some(range_start) = start {
            result.push(difference_row(
                left,
                &right_preview,
                range_start,
                offset,
                right_len,
            ));
        }
    }

    /*
    Cancellation discards all collected rows before and after final source validation.
    A detected source change returns an error instead of a completed stale result.
    */
    let last = Progress::new(offset, end);
    if !progress(last) {
        return Ok(Outcome::Canceled);
    }
    validate().map_err(|error| error.to_string())?;
    if !progress(last) {
        return Ok(Outcome::Canceled);
    }
    Ok(Outcome::Completed(result))
}

/*
This formatter keeps the existing range text and eight-byte previews.
The u64 range length describes peers above 4 GiB without a peer-sized allocation.
Result offsets remain within the buffered left input or its EOF boundary.
*/
fn difference_row(
    left: &[u8],
    right_preview: &[u8],
    start: usize,
    end: u64,
    right_len: u64,
) -> (usize, String) {
    let left_bytes = &left[start.min(left.len())..end.min(left.len() as u64) as usize];
    let len = end - start as u64;
    let right_count = right_len.min(end).saturating_sub(start as u64);
    (
        start,
        format!(
            "{} {}: old [{}], new [{}]",
            len,
            if len == 1 { "byte" } else { "bytes" },
            difference_preview(left_bytes, left_bytes.len() as u64),
            difference_preview(right_preview, right_count),
        ),
    )
}

/*
This formatter distinguishes absent bytes from a present preview.
The complete side length controls the suffix when the stored preview has only eight bytes.
*/
fn difference_preview(bytes: &[u8], len: u64) -> String {
    if len == 0 {
        return "<absent>".into();
    }
    let mut text = bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    if len > 8 {
        text.push_str(" ...");
    }
    text
}

/*
This transform validates the complete range and mask before changing any byte.
Fill replaces each byte, while XOR combines each byte with the repeating mask.
The caller retains responsibility for one Editor history transaction.
*/
pub fn transform(
    data: &mut [u8],
    start: usize,
    len: usize,
    mask: &[u8],
    xor: bool,
) -> Result<(), String> {
    if len == 0 {
        return Err("The block length must be greater than zero.".into());
    }
    if mask.is_empty() {
        return Err("Enter at least one mask byte.".into());
    }
    let end = start
        .checked_add(len)
        .filter(|&end| end <= data.len())
        .ok_or("The block extends past the file end.")?;
    /*
    The validated range makes every mask index and byte mutation safe.
    Mask repetition starts at the first selected byte for both transform kinds.
    */
    for (index, byte) in data[start..end].iter_mut().enumerate() {
        if xor {
            *byte ^= mask[index % mask.len()];
        } else {
            *byte = mask[index % mask.len()];
        }
    }
    Ok(())
}

/*
These tests check pure byte operations and guarded comparison lifecycle behavior.
Disposable files provide buffered, paged, virtual, and changed-source cases.
*/
#[cfg(test)]
mod tests {
    use super::*;
    use crate::paged::BUFFERED_FILE_LIMIT;
    use std::cell::Cell;
    use std::fs::{File, FileTimes};
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    /*
    This helper exercises the production scanner with two borrowed byte slices.
    Pure comparison tests share the same range state, tail handling, and preview formatter as file comparisons.
    */
    fn differences(left: &[u8], right: &[u8], limit: usize) -> Vec<(usize, String)> {
        match difference_ranges_cancellable(
            left,
            right.len() as u64,
            limit,
            |start, len| Ok(Cow::Borrowed(&right[start as usize..start as usize + len])),
            || Ok(()),
            |_| true,
        )
        .unwrap()
        {
            Outcome::Completed(rows) => rows,
            Outcome::Canceled => panic!("The comparison did not request cancellation."),
        }
    }

    /*
    Each fixture owns a unique disposable directory for regular comparison peers.
    The counter separates test paths within one process, and Drop removes every fixture entry.
    */
    struct Fixture(PathBuf);

    impl Fixture {
        /*
        Directory creation completes before a test can create or replace its peer.
        Tests keep all comparison state inside the returned directory.
        */
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "hview-comparison-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        /*
        This path helper keeps native fixture names beneath the disposable directory.
        */
        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    /*
    Cleanup also removes replacement peers and retired source paths after a failed assertion.
    */
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /*
    Masked search must preserve wildcard nibble meaning at every candidate boundary.
    Malformed input must not construct a partially valid pattern.
    */
    #[test]
    fn masked_search_checks_nibbles_and_boundaries() {
        let pattern = parse_pattern("a? ?F\t??").unwrap();
        let data = [0xaf, 0x01, 0xff, 0xa2, 0x3f, 0, 0xab, 0xff, 0x12];
        assert_eq!(pattern.find(&data, 0, false), Some(3));
        assert_eq!(pattern.find(&data, 3, false), Some(3));
        assert_eq!(pattern.find(&data, 4, false), Some(6));
        assert_eq!(pattern.find(&data, 7, false), None);
        assert_eq!(pattern.find(&data, usize::MAX, false), None);
        assert_eq!(pattern.find(&data, usize::MAX, true), Some(6));
        assert_eq!(pattern.find(&data, 5, true), Some(3));
        assert_eq!(pattern.find(&data, 2, true), None);
        assert_eq!(pattern.find(&data[..2], 0, true), None);
        assert_eq!(
            parse_pattern("a??f??").unwrap().find(&data, 0, false),
            Some(3)
        );
        for text in ["", "  ", "?", "ABC", "GG", "0xAA", "AA-Z"] {
            assert!(parse_pattern(text).is_err(), "{text}");
        }
    }

    /*
    Exact search accepts zero bytes and overlapping matches.
    Empty input cannot construct a pattern or produce an out-of-range match.
    */
    #[test]
    fn exact_search_handles_zero_bytes_and_overlapping_matches() {
        assert!(Pattern::exact(Vec::new()).is_err());
        let pattern = Pattern::exact(vec![0, 0]).unwrap();
        assert_eq!(pattern.find(&[0, 0, 0], 1, false), Some(1));
        assert_eq!(pattern.find(&[0, 0, 0], 0, true), Some(0));
        assert_eq!(pattern.find(&[], 0, false), None);
    }

    /*
    The shared scanner retains the existing changed-range grouping and display text.
    Length-only tails preserve absent-side previews and the requested result limit.
    */
    #[test]
    fn comparison_groups_changes_and_length_only_tails() {
        let result = differences(&[1, 2, 3, 4], &[1, 9, 8, 4, 5], 10);
        assert_eq!(
            result,
            vec![
                (1, "2 bytes: old [02 03], new [09 08]".into()),
                (4, "1 byte: old [<absent>], new [05]".into()),
            ]
        );
        assert_eq!(
            differences(&[1, 2], &[1], 1)[0].1,
            "1 byte: old [02], new [<absent>]"
        );
        assert_eq!(differences(&[1], &[2], 0), Vec::new());
        assert_eq!(differences(&[], &[], 10), Vec::new());
        assert_eq!(differences(&[1, 2], &[1, 2], 10), Vec::new());
        assert_eq!(differences(&[1, 0, 1], &[2, 0, 2], 1).len(), 1);
        assert_eq!(
            differences(&[], &[0; 9], 1)[0].1,
            "9 bytes: old [<absent>], new [00 00 00 00 00 00 00 00 ...]"
        );
    }

    /*
    A changed range crosses the 64 KiB boundary without a second result row.
    More than 10,001 separate changes stop at the requested cap with unchanged row text.
    */
    #[test]
    fn comparison_preserves_window_crossing_ranges_and_result_limit() {
        let left = vec![0; WINDOW_BYTES + 12];
        let mut right = left.clone();
        right[WINDOW_BYTES - 4..WINDOW_BYTES + 9].fill(7);
        assert_eq!(
            differences(&left, &right, 10001),
            vec![(
                WINDOW_BYTES - 4,
                "13 bytes: old [00 00 00 00 00 00 00 00 ...], new [07 07 07 07 07 07 07 07 ...]"
                    .into(),
            )]
        );
        let mut right = vec![0; 20004];
        for byte in right.iter_mut().step_by(2) {
            *byte = 1;
        }
        let rows = differences(&vec![0; right.len()], &right, 10001);
        assert_eq!(rows.len(), 10001);
        assert_eq!(
            rows.last().unwrap(),
            &(20000, "1 byte: old [00], new [01]".into())
        );
    }

    /*
    Guarded file comparison must accept regular peers above both storage boundaries.
    A sparse high-offset tail needs only its first eight preview bytes.
    Changed common bytes still form one range across the paged window boundary.
    */
    #[test]
    fn comparison_reads_large_sparse_peers_in_bounded_windows() {
        let fixture = Fixture::new();
        let path = fixture.file("peer.bin");
        let file = File::create(&path).unwrap();
        let len = BUFFERED_FILE_LIMIT + 128;
        file.set_len(len).unwrap();
        file.write_all_at(&[7; 13], (WINDOW_BYTES - 4) as u64)
            .unwrap();
        let left = vec![0; WINDOW_BYTES + 12];
        let rows = compare_file_cancellable(&left, &path, 10001, |_| true).unwrap();
        assert_eq!(
            rows,
            Outcome::Completed(vec![
                (
                    WINDOW_BYTES - 4,
                    "13 bytes: old [00 00 00 00 00 00 00 00 ...], new [07 07 07 07 07 07 07 07 ...]".into(),
                ),
                (
                    left.len(),
                    format!("{} bytes: old [<absent>], new [00 00 00 00 00 00 00 00 ...]", len - left.len() as u64),
                ),
            ])
        );

        /*
        The second peer exceeds 4 GiB while the left buffer contains only three bytes.
        Tail length and preview remain exact without reading the sparse tail.
        */
        let len = (1_u64 << 32) + 17;
        file.set_len(len).unwrap();
        file.write_all_at(b"ABCabcdefgh", 0).unwrap();
        assert_eq!(
            compare_file_cancellable(b"ABC", &path, 10001, |_| true).unwrap(),
            Outcome::Completed(vec![(
                3,
                format!(
                    "{} bytes: old [<absent>], new [61 62 63 64 65 66 67 68 ...]",
                    len - 3
                ),
            )])
        );
    }

    /*
    Linux virtual regular files can report zero or excessive length for readable short content.
    Buffered comparison must use the actual returned bytes instead of the metadata length.
    */
    #[test]
    fn comparison_preserves_virtual_regular_file_content() {
        let path = Path::new("/proc/self/cmdline");
        let left = fs::read(path).unwrap();
        assert!(!left.is_empty());
        assert_eq!(path.metadata().unwrap().len(), 0);
        assert_eq!(
            compare_file_cancellable(&left, path, 10001, |_| true).unwrap(),
            Outcome::Completed(Vec::new())
        );

        /*
        The sysfs sequence number can change between independent content reads.
        Its completed comparison row must describe the accepted short content from one descriptor.
        */
        let path = Path::new("/sys/kernel/uevent_seqnum");
        let reported = path.metadata().unwrap().len();
        let Outcome::Completed(rows) =
            compare_file_cancellable(&[], path, 10001, |_| true).unwrap()
        else {
            panic!("The comparison did not request cancellation.");
        };
        assert_eq!(rows.len(), 1);
        let count = rows[0]
            .1
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(count > 0 && count < reported);
        assert!(rows[0].1.contains("old [<absent>], new ["));
    }

    /*
    Cancellation before opening must win over a missing-path error.
    Cancellation after one window must discard earlier rows and prevent the next window read.
    Cancellation at final validation must also prevent a completed result.
    */
    #[test]
    fn comparison_cancellation_discards_partial_ranges() {
        let fixture = Fixture::new();
        assert_eq!(
            compare_file_cancellable(&[], &fixture.file("missing.bin"), 10001, |_| false),
            Ok(Outcome::Canceled)
        );
        let left = vec![0; WINDOW_BYTES * 3];
        let mut right = left.clone();
        right[1] = 1;
        let mut reads = 0;
        let canceled = difference_ranges_cancellable(
            &left,
            right.len() as u64,
            10001,
            |start, len| {
                assert!(len <= WINDOW_BYTES);
                reads += 1;
                Ok(Cow::Borrowed(&right[start as usize..start as usize + len]))
            },
            || panic!("A canceled comparison must not validate a completed result."),
            |progress| progress.completed < WINDOW_BYTES as u64,
        )
        .unwrap();
        assert_eq!(canceled, Outcome::Canceled);
        assert_eq!(reads, 1);

        /*
        The descriptor check runs before the final cancellation callback rejects the result.
        No caller can obtain the complete row collected before cancellation.
        */
        let validated = Cell::new(false);
        assert_eq!(
            difference_ranges_cancellable(
                &[1],
                1,
                10001,
                |_, _| Ok(Cow::Borrowed(&[2])),
                || {
                    validated.set(true);
                    Ok(())
                },
                |progress| progress.completed == 0 || !validated.get(),
            )
            .unwrap(),
            Outcome::Canceled
        );
    }

    /*
    A source change after the last scan must prevent completed buffered and paged results.
    Deterministic timestamp changes and matching-byte pathname replacements exercise both final guards.
    */
    #[test]
    fn comparison_refuses_changed_and_replaced_peers_before_completion() {
        let fixture = Fixture::new();
        for len in [4, BUFFERED_FILE_LIMIT + 1] {
            let path = fixture.file("peer.bin");
            let file = File::create(&path).unwrap();
            file.set_len(len).unwrap();
            let mut changed = false;
            let error = compare_file_cancellable(&[0; 4], &path, 10001, |progress| {
                if progress.total != 0 && progress.completed == progress.total && !changed {
                    file.set_times(
                        FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)),
                    )
                    .unwrap();
                    changed = true;
                }
                true
            })
            .unwrap_err();
            assert!(changed);
            assert!(error.contains("Reopen the source"), "{error}");

            /*
            Restore the peer before opening a new comparison stamp.
            A replacement keeps the same length and bytes but changes native identity.
            */
            let mut replaced = false;
            let error = compare_file_cancellable(&[0; 4], &path, 10001, |progress| {
                if progress.total != 0 && progress.completed == progress.total && !replaced {
                    fs::rename(&path, fixture.file("retired.bin")).unwrap();
                    File::create(&path).unwrap().set_len(len).unwrap();
                    replaced = true;
                }
                true
            })
            .unwrap_err();
            assert!(replaced);
            assert!(error.contains("Reopen the source"), "{error}");
            fs::remove_file(fixture.file("retired.bin")).unwrap();
        }
    }

    /*
    Repeating masks must preserve exact bytes after a reversible XOR pair.
    Invalid ranges and empty masks must leave the complete input unchanged.
    */
    #[test]
    fn transforms_repeat_masks_and_reject_invalid_ranges_without_changes() {
        let original = [1, 2, 3, 4, 5, 6];
        let mut data = original;
        transform(&mut data, 1, 4, &[0xff, 0x10], true).unwrap();
        assert_eq!(data, [1, 0xfd, 0x13, 0xfb, 0x15, 6]);
        transform(&mut data, 1, 4, &[0xff, 0x10], true).unwrap();
        assert_eq!(data, original);
        transform(&mut data, 2, 4, &[0xaa, 0xbb, 0xcc], false).unwrap();
        assert_eq!(data, [1, 2, 0xaa, 0xbb, 0xcc, 0xaa]);
        let unchanged = data;
        for (start, len, mask) in [
            (0, 0, &[1][..]),
            (0, 1, &[][..]),
            (5, 2, &[1][..]),
            (6, 1, &[1][..]),
            (usize::MAX, 2, &[1][..]),
            (2, usize::MAX, &[1][..]),
        ] {
            assert!(transform(&mut data, start, len, mask, false).is_err());
            assert_eq!(data, unchanged);
        }
        assert!(transform(&mut [], 0, 1, &[1], true).is_err());
    }
}
