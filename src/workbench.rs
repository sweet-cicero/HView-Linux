/*
This module provides Help and the buffered analysis tools that run from the main editor loop.
Each tool uses the active Editor bytes, including accepted edits that are not saved.
*/
use crate::{
    analysis::{self, Outcome, Progress},
    console::Console,
    editor::{ByteOrder, Editor, Mode, RawModel},
    format, inspect, operations,
};
use std::{cell::Cell, io, path::Path};

/*
This worker wrapper keeps terminal access on the caller thread and lends stable Editor bytes to one scoped worker.
It redraws progress only when the value or terminal size changes. An idle resize still receives the latest status.
The base frame returns before the result browser, cancellation return, or error notice.
Only a matching source stamp can expose a complete payload to the caller.
*/
pub(crate) fn run_analysis<T: Send>(
    console: &Console,
    view: &Editor,
    base: &[String],
    operation: &str,
    work: impl FnOnce(analysis::Reporter) -> Result<Outcome<T>, String> + Send,
) -> io::Result<Option<T>> {
    let stamp = view.buffer_stamp();
    let first = Progress::new(0, 0);
    let last_progress = Cell::new(first);
    let last_size = Cell::new(console.dimensions());
    console.analysis_progress(base, operation, first.completed, first.total)?;

    /*
    The update callback accepts advisory progress while the cancellation callback owns physical input polling.
    Both callbacks share small copied display state, so neither callback holds Console input or output ownership.
    */
    let terminal = analysis::run(
        stamp,
        work,
        |progress| {
            let size = console.dimensions();
            if progress != last_progress.get() || size != last_size.get() {
                console.analysis_progress(base, operation, progress.completed, progress.total)?;
                last_progress.set(progress);
                last_size.set(size);
            }
            Ok(())
        },
        || {
            let size = console.dimensions();
            if size != last_size.get() {
                let progress = last_progress.get();
                console.analysis_progress(base, operation, progress.completed, progress.total)?;
                last_size.set(size);
            }
            console.cancel_requested()
        },
    );

    /*
    The worker has joined when run returns, so this section can restore the editor frame before any notice.
    Outer worker or callback I/O errors return unchanged after a best-effort frame restoration.
    Stale results and inner analysis errors use the existing modal policy.
    */
    let terminal = match terminal {
        Ok(terminal) => {
            console.draw(base)?;
            terminal
        }
        Err(error) => {
            let _ = console.draw(base);
            return Err(error);
        }
    };
    let result = match terminal.accept(view.buffer_stamp()) {
        Ok(result) => result,
        Err(error) => {
            console.modal(base, &error.to_string())?;
            return Ok(None);
        }
    };
    match result {
        Ok(Outcome::Completed(value)) => Ok(Some(value)),
        Ok(Outcome::Canceled) => Ok(None),
        Err(error) => {
            console.modal(base, &format!("Analysis failed: {error}"))?;
            Ok(None)
        }
    }
}

/*
This helper moves a buffered view to one selected result.
Code mode aligns its viewport with the selected instruction position.
*/
pub fn jump(view: &mut Editor, offset: usize, rows: usize) {
    view.goto(offset as u64, rows);
    if view.mode == Mode::Code {
        view.top = view.offset;
    }
}

/*
This browser renders one bounded result list and returns the selected file offset.
It keeps selection and horizontal scroll state while terminal dimensions change.
*/
fn browse(console: &Console, title: &str, items: &[(usize, String)]) -> io::Result<Option<usize>> {
    let mut selected = 0usize;
    let mut column = 0usize;
    loop {
        /*
        This section builds one page around the selected result.
        Empty results receive a clear row before the common navigation footer.
        */
        let (_width, height) = console.dimensions();
        let page = height.saturating_sub(4).max(1);
        let mut lines = vec![String::new(); height];
        if let Some(line) = lines.first_mut() {
            *line = format!(" {title} | {} results", items.len());
        }
        let top = selected / page * page;
        for (index, (offset, text)) in items.iter().enumerate().skip(top).take(page) {
            if let Some(line) = lines.get_mut(index - top + 2) {
                *line = format!(
                    " {} {offset:08X}  {}",
                    if index == selected { '>' } else { ' ' },
                    text.chars().skip(column).collect::<String>()
                );
            }
        }
        if items.is_empty()
            && let Some(line) = lines.get_mut(2)
        {
            *line = " No results.".into();
        }
        if let Some(footer) = lines.last_mut() {
            *footer =
                " Up/Down Select  PgUp/PgDn Page  Left/Right Scroll  Enter Goto  Esc Back".into();
        }
        console.draw(&lines)?;
        /*
        This section applies selection, paging, and horizontal scrolling keys.
        Enter returns a real item offset, while Escape cancels the browser.
        */
        match console.key()?.code {
            27 => return Ok(None),
            13 => return Ok(items.get(selected).map(|item| item.0)),
            38 => selected = selected.saturating_sub(1),
            40 => selected = (selected + 1).min(items.len().saturating_sub(1)),
            33 => selected = selected.saturating_sub(page),
            34 => selected = (selected + page).min(items.len().saturating_sub(1)),
            36 => selected = 0,
            35 => selected = items.len().saturating_sub(1),
            37 => column = column.saturating_sub(16),
            39 => {
                column = (column + 16).min(items.iter().map(|item| item.1.len()).max().unwrap_or(0))
            }
            _ => {}
        }
    }
}

/*
This screen lists every current viewer and tool shortcut.
Escape, Enter, Alt+H, and legacy macro F1 records return to the active view.
*/
pub fn help(console: &Console) -> io::Result<()> {
    let help = [
        " Editor controls",
        " Alt+E Edit  Ctrl+Z/Y Undo/Redo  Alt+S Save  Esc Cancel",
        " Ctrl+S Save As: save the buffer to a new file",
        " Alt+M, M, or Enter Mode  O x86 Code size  Ctrl+Q Quit",
        " H/J/K/L Move  Ctrl+T Analysis tools",
        " Alt+H Help  Alt+W Wrap  Alt+L Line notice  Alt+A Assemble",
        " Alt+G Goto  Alt+M Mode",
        " Alt+F Search  Alt+R/B Next/Previous  Alt+O Files",
        " Alt+P/N Previous/Next file",
        " Hex search accepts wildcards: 48 8B ?? A? ?F",
        " Code: Enter Follow direct relative branch/call  Backspace Return",
        " Ctrl+T Analysis tools:",
        "   A  Convert a file offset, RVA, or VA",
        "   R  Set AUTO or an x86, ARM, Thumb, or ARM64 raw model",
        "   S  Browse ASCII and UTF-16 ASCII strings",
        "   P  Browse executable structures and jump to their bytes",
        "   E  Browse the entropy map; Escape cancels its work",
        "   D  Compare the current buffer with another file",
        "   I  Inspect integers at the cursor",
        "   X  Apply a repeating XOR mask in edit mode",
        "   F  Fill a range with a repeating pattern in edit mode",
        " Tools use the current editor buffer, including unsaved edits.",
        " AUTO uses executable metadata. A raw model uses its runtime base.",
        " Range offsets and lengths use hexadecimal numbers.",
    ];
    loop {
        /*
        This section fits as many Help lines as the current terminal height permits.
        A later resize redraws the same complete list from its first line.
        */
        let (_width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        for (slot, text) in lines
            .iter_mut()
            .skip(1)
            .take(height.saturating_sub(2))
            .zip(help)
        {
            *slot = text.into();
        }
        if let Some(footer) = lines.last_mut() {
            *footer = " Press Alt+H, Esc, or Enter to return.".into();
        }
        console.draw(&lines)?;
        let key = console.key()?;
        if matches!(key.code, 27 | 13 | 112) || key.is_alt(b'H') {
            return Ok(());
        }
    }
}

/*
This parser accepts one complete hexadecimal usize value for bounded tool ranges.
*/
fn number(text: &str) -> Result<usize, String> {
    let text = text.trim();
    usize::from_str_radix(text, 16)
        .map_err(|_| "Enter a hexadecimal offset and length within the address range.".into())
}

/*
This parser reads one address-kind letter and one complete hexadecimal u64 value.
It returns the common address record used by the current raw and PE converters.
*/
fn address_input(text: &str) -> Result<(format::AddressKind, u64), String> {
    let (kind, digits) = text
        .split_once(' ')
        .ok_or("Enter F, R, or V, one space, and a hexadecimal address.")?;
    if kind.len() != 1 || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Enter F, R, or V, one space, and a hexadecimal address.".into());
    }
    let kind = match kind {
        "F" => format::AddressKind::File,
        "R" => format::AddressKind::Rva,
        "V" => format::AddressKind::Va,
        _ => return Err("Enter F, R, or V, one space, and a hexadecimal address.".into()),
    };
    let value = u64::from_str_radix(digits, 16)
        .map_err(|_| "The address exceeds the 64-bit address range.".to_string())?;
    Ok((kind, value))
}

/*
This parser selects AUTO or one complete raw architecture model.
It validates the architecture, width, byte order, and hexadecimal runtime base.
*/
fn raw_model_input(text: &str) -> Result<Option<RawModel>, String> {
    /*
    This section recognizes the exact AUTO value before it splits a manual model.
    The strict field checks reject missing, extra, or partially valid model text.
    */
    const ERROR: &str = "Enter AUTO, X86 16|32|64 LE|BE HEXBASE, or ARM|THUMB|ARM64 LE|BE HEXBASE.";
    if text == "AUTO" {
        return Ok(None);
    }
    let fields: Vec<_> = text.split(' ').collect();
    /*
    This section converts validated fields into bounded numeric and enum values.
    It constructs the model only after all fields pass their complete checks.
    */
    let (architecture, order, base) = match fields.as_slice() {
        ["X86", bits @ ("16" | "32" | "64"), order, base] => (
            crate::format::Architecture::x86(bits.parse().unwrap())?,
            *order,
            *base,
        ),
        ["ARM", order, base] => (crate::format::Architecture::Arm, *order, *base),
        ["THUMB", order, base] => (crate::format::Architecture::Thumb, *order, *base),
        ["ARM64", order, base] => (crate::format::Architecture::Arm64, *order, *base),
        _ => return Err(ERROR.into()),
    };
    if base.is_empty() || !base.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ERROR.into());
    }
    let byte_order = match order {
        "LE" => ByteOrder::Little,
        "BE" => ByteOrder::Big,
        _ => return Err(ERROR.into()),
    };
    let base = u64::from_str_radix(base, 16)
        .map_err(|_| "The raw runtime base exceeds the 64-bit address range.".to_string())?;
    Ok(Some(RawModel {
        base,
        architecture,
        byte_order,
    }))
}

/*
This prompt applies one validated raw model to the active Editor.
The result tells the main loop whether address-dependent return history must clear.
*/
fn set_raw_model(console: &Console, view: &mut Editor, base: &[String]) -> io::Result<bool> {
    /*
    This section collects one model choice and reports parser errors without changing the Editor.
    A canceled prompt leaves the model unchanged and requests no branch-return history invalidation.
    */
    let Some(input) = console.prompt(
        base,
        "Raw model: AUTO, X86 16|32|64 LE|BE HEXBASE, or ARM|THUMB|ARM64 LE|BE HEXBASE",
    )?
    else {
        return Ok(false);
    };
    let model = match raw_model_input(&input) {
        Ok(model) => model,
        Err(error) => {
            console.modal(base, &error)?;
            return Ok(false);
        }
    };
    /*
    This section applies the accepted model through Editor validation.
    The return value requests history invalidation only when the runtime address model changes.
    */
    let before = view.raw_model;
    if let Err(error) = view.set_raw_model(model) {
        console.modal(base, &error)?;
        return Ok(false);
    }
    Ok(match (before, model) {
        (None, None) => false,
        (Some(old), Some(new)) => old.base != new.base || old.architecture != new.architecture,
        _ => true,
    })
}

/*
This tool converts one supported address domain through the current Editor model.
Mapped file bytes enter the common result browser and can move the active view.
*/
fn convert_address(console: &Console, view: &mut Editor, base: &[String]) -> io::Result<()> {
    /*
    The metadata section selects a format label and offers only valid input domains.
    A parser error returns through the current modal without changing the Editor.
    */
    let metadata = match view.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            console.modal(base, &error)?;
            return Ok(());
        }
    };
    let label = metadata.format_label().unwrap_or("File");
    let prompt = if label == "RAW" {
        "RAW address: F file or V VA (hex)".into()
    } else if metadata.has_rva() {
        format!("{label} address: F file, R RVA, or V VA (hex)")
    } else if metadata.has_va() {
        format!("{label} address: F file or V VA (hex)")
    } else if label == "ELF" {
        "ELF relocatable address: F file (hex)".into()
    } else {
        format!("{label} address: F file (hex)")
    };
    let Some(input) = console.prompt(base, &prompt)? else {
        return Ok(());
    };
    let address = address_input(&input).and_then(|(kind, value)| view.convert_address(kind, value));
    let address = match address {
        Ok(address) => address,
        Err(error) => {
            console.modal(base, &error)?;
            return Ok(());
        }
    };
    /*
    This section formats every available address kind for one result row.
    A mapped file offset can become the next active cursor position.
    */
    let file = address
        .file_offset
        .map(|value| format!("{value:08X}"))
        .unwrap_or_else(|| "-".into());
    let rva = address
        .rva
        .map(|value| format!("{value:08X}"))
        .unwrap_or_else(|| "-".into());
    let va = address
        .va
        .map(|value| format!("{value:016X}"))
        .unwrap_or_else(|| "-".into());
    let text = if metadata.has_rva() || label == "RAW" {
        format!("File={file} RVA={rva} VA={va}")
    } else if metadata.has_va() {
        format!("File={file} VA={va}")
    } else {
        format!("File={file}")
    };
    match address.file_offset {
        Some(offset) if view.data.get(offset).is_some() => {
            let title = match label {
                "RAW" => "RAW address | current buffer, runtime base".into(),
                "PE" => "PE address | current buffer, preferred ImageBase".into(),
                "ELF" if metadata.has_va() => "ELF address | current buffer, link-time VA".into(),
                "ELF" => "ELF relocatable address | current buffer, file only".into(),
                _ => format!("{label} address | current buffer, file only"),
            };
            if let Some(offset) = browse(console, &title, &[(offset, text)])? {
                jump(view, offset, console.height().saturating_sub(2));
            }
        }
        Some(_) => {
            console.modal(base, "The converted file offset has no file byte.")?;
        }
        None => {
            console.modal(
                base,
                &format!("{text} | No file bytes exist for this virtual address."),
            )?;
        }
    }
    Ok(())
}

/*
This edit tool parses one bounded range and applies Fill or XOR through Editor history.
It calculates the destination viewport before the single replacement transaction.
*/
fn change_range(
    console: &Console,
    view: &mut Editor,
    base: &[String],
    xor: bool,
) -> io::Result<()> {
    if !view.editing {
        console.modal(base, "Press Alt+E to enter edit mode first.")?;
        return Ok(());
    }
    let Some(range) =
        console.prompt_seed(base, "Start Length (hex)", &format!("{:X} 1", view.offset))?
    else {
        return Ok(());
    };
    let fields: Vec<_> = range.split_whitespace().collect();
    let parsed = if fields.len() == 2 {
        number(fields[0]).and_then(|start| number(fields[1]).map(|len| (start, len)))
    } else {
        Err("Enter a start offset and a length.".into())
    };
    let (start, len) = match parsed {
        Ok(range) => range,
        Err(error) => {
            console.modal(base, &error)?;
            return Ok(());
        }
    };
    /*
    This section parses the repeating mask and copies only the selected range.
    The final Editor transaction preserves Undo, Redo, and dirty-state rules.
    */
    let Some(mask) = console.prompt(
        base,
        if xor {
            "XOR mask (hex)"
        } else {
            "Fill pattern (hex)"
        },
    )?
    else {
        return Ok(());
    };
    let result = crate::hex_pattern(&mask).and_then(|mask| {
        let end = start
            .checked_add(len)
            .ok_or("The block extends past the file end.")?;
        let bytes = view
            .data
            .get(start..end)
            .ok_or("The block extends past the file end.")?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(bytes.len())
            .map_err(|_| "Cannot allocate the edit history.")?;
        replacement.extend_from_slice(bytes);
        operations::transform(&mut replacement, 0, len, &mask, xor)?;
        let offset = start as u64;
        let top = if view.mode == Mode::Code {
            offset
        } else {
            let rows = console.height().saturating_sub(2) as u64;
            let file_rows = (view.data.len() as u64).div_ceil(16);
            (offset.saturating_sub(rows * 8) / 16 * 16).min(file_rows.saturating_sub(rows) * 16)
        };
        view.replace_bytes(start, replacement, (offset, top))
    });
    match result {
        Ok(()) => {}
        Err(error) => {
            console.modal(base, &error)?;
        }
    }
    Ok(())
}

/*
This dispatcher draws the buffered analysis menu and runs one selected tool.
Modified letters do not select a tool or leak into any later character command.
*/
pub fn tools(console: &Console, view: &mut Editor, base: &[String]) -> io::Result<bool> {
    /*
    This loop redraws the menu after a resize and returns one meaningful key.
    Each action uses the active Editor only after this input boundary accepts it.
    */
    let key = loop {
        let (_width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        for (line, text) in lines.iter_mut().skip(2).zip([
            " Analysis tools",
            " A  Address: convert a file offset, RVA, or VA",
            " R  Raw model: AUTO, X86 16|32|64 LE|BE HEXBASE, or ARM|THUMB|ARM64 LE|BE HEXBASE",
            " S  Strings: ASCII and UTF-16 ASCII, minimum 4 characters",
            " P  Executable structures",
            " E  Entropy map: cancellable bounded analysis",
            " D  Compare: browse changed ranges against another file",
            " I  Integers: signed and unsigned, little and big endian",
            " X  XOR range: repeat a hexadecimal mask (edit mode)",
            " F  Fill range: repeat a hexadecimal pattern (edit mode)",
            " Esc  Return",
        ]) {
            *line = text.into();
        }
        console.draw(&lines)?;
        let key = console.key()?;
        if key.code != 0 || key.character != '\0' {
            break key;
        }
    };
    if !key.accepts_text() {
        return Ok(false);
    }

    /*
    This dispatch runs one address, model, inspection, comparison, or range-edit action.
    Strings, executable structures, and comparisons keep their 10,000-row limit.
    Entropy and integer results keep their separate natural bounds.
    */
    let mut clear_return_history = false;
    let items = match key.character.to_ascii_uppercase() {
        /*
        The address tool converts one value and can move the active cursor through its result browser.
        */
        'A' => {
            convert_address(console, view, base)?;
            None
        }
        /*
        The raw-model tool changes address interpretation without changing source bytes.
        Its result tells the caller whether to clear branch-return history.
        */
        'R' => {
            clear_return_history = set_raw_model(console, view, base)?;
            None
        }
        /*
        The string tool scans the current buffer with a four-character minimum.
        It truncates stored display results before it enters the shared browser.
        */
        'S' => {
            // ponytail: Bound result storage. Add streamed results when larger lists are needed.
            let mut items = inspect::strings(&view.data, 4, 10001);
            let title = if items.len() > 10000 {
                items.truncate(10000);
                "Strings | truncated at 10000 results"
            } else {
                "Strings"
            };
            Some((title, items))
        }
        /*
        The executable tool parses bounded format structures from the current buffer.
        Parser errors become modal notices, and valid rows use the common display limit.
        */
        'P' => match format::structures(&view.data, 10001) {
            Ok(mut items) => {
                let base_title = format::structure_title(&view.data);
                let title = if items.len() > 10000 {
                    items.truncate(10000);
                    match base_title {
                        "ELF structures" => "ELF structures | truncated at 10000 results",
                        _ => "PE structures | truncated at 10000 results",
                    }
                } else {
                    base_title
                };
                Some((title, items))
            }
            Err(error) => {
                console.modal(base, &error)?;
                None
            }
        },
        /*
        The entropy tool selects blocks of at least 4,096 bytes from the current unsaved buffer.
        Large buffers increase the block size so the result remains naturally bounded.
        A scoped worker reports progress and returns only complete stamped rows.
        */
        'E' => {
            let block = 4096usize.max(view.data.len().div_ceil(4096));
            run_analysis(console, view, base, "Entropy", |reporter| {
                Ok(inspect::entropy_map_cancellable(
                    &view.data,
                    block,
                    |progress| reporter.progress(progress),
                ))
            })?
            .map(|items| ("Entropy | bits/byte, not a packer verdict", items))
        }
        /*
        The comparison worker opens one regular peer and reads bounded windows.
        Current unsaved bytes remain the left input while the caller accepts cancellation and terminal input.
        Only complete, validated rows enter the existing result browser.
        */
        'D' => {
            let Some(path) = console.prompt(base, "Compare file")? else {
                return Ok(false);
            };
            let path = Path::new(path.trim().trim_matches('"'));
            run_analysis(console, view, base, "Compare", |reporter| {
                operations::compare_file_cancellable(&view.data, path, 10001, |progress| {
                    reporter.progress(progress)
                })
            })?
            .map(|mut items| {
                let title = if items.len() > 10000 {
                    items.truncate(10000);
                    "Compare | buffer -> file | truncated at 10000 ranges"
                } else {
                    "Compare | buffer -> file"
                };
                (title, items)
            })
        }
        /*
        The integer tool reads bounded values at the cursor with the selected byte order.
        All returned rows point back to the current cursor position.
        */
        'I' => {
            let rows = inspect::integers(
                &view.data,
                view.offset as usize,
                view.raw_model.map(|model| model.byte_order),
            )
            .into_iter()
            .map(|text| (view.offset as usize, text))
            .collect();
            Some(("Integers at cursor", rows))
        }
        /*
        Fill and XOR share the same range-edit helper and one Editor history transaction.
        The selected letter decides whether the repeating mask replaces or transforms bytes.
        */
        'X' | 'F' => {
            change_range(
                console,
                view,
                base,
                key.character.eq_ignore_ascii_case(&'x'),
            )?;
            None
        }
        _ => None,
    };
    /*
    List-producing actions enter the shared browser after their bounded analysis completes.
    The selected result updates the cursor before control returns to the main loop.
    */
    if let Some((title, items)) = items
        && let Some(offset) = browse(console, title, &items)?
    {
        jump(view, offset, console.height().saturating_sub(2));
    }
    Ok(clear_return_history)
}

/*
These unit tests protect strict tool-number, address, and raw-model parsing.
They use complete accepted and rejected input tables without terminal state.
*/
#[cfg(test)]
mod tests {
    use super::*;

    /*
    This test rejects partial and signed range values.
    */
    #[test]
    fn range_numbers_require_complete_input() {
        assert_eq!(number("10").unwrap(), 16);
        assert!(number("10junk").is_err());
        assert!(number("").is_err());
        assert!(number("-1").is_err());
    }

    /*
    This test checks every address kind and malformed grammar group.
    */
    #[test]
    fn address_input_requires_one_complete_hexadecimal_value() {
        use format::AddressKind::{File, Rva, Va};

        assert_eq!(address_input("F 400"), Ok((File, 0x400)));
        assert_eq!(address_input("R 1010"), Ok((Rva, 0x1010)));
        assert_eq!(address_input("V 140001010"), Ok((Va, 0x140001010)));
        for input in [
            "F +400",
            "F -400",
            "F 0x400",
            "F 400 ",
            "F 400 data",
            "F 10000000000000000",
            "A 400",
        ] {
            assert!(address_input(input).is_err(), "accepted {input:?}");
        }
    }

    /*
    This test checks AUTO, one complete model, and each invalid model field.
    */
    #[test]
    fn raw_model_input_requires_the_complete_strict_grammar() {
        /*
        The valid section checks x86 and each ARM-family grammar with exact parsed fields.
        AUTO returns no explicit model.
        */
        let model = raw_model_input("X86 32 BE 123456789ABCDEF0")
            .unwrap()
            .unwrap();
        assert_eq!(model.base, 0x123456789abcdef0);
        assert_eq!(model.architecture, format::Architecture::X86(32));
        assert_eq!(model.byte_order, ByteOrder::Big);
        let arm = raw_model_input("ARM BE 1000").unwrap().unwrap();
        assert_eq!(arm.architecture, format::Architecture::Arm);
        assert_eq!(arm.byte_order, ByteOrder::Big);
        let thumb = raw_model_input("THUMB LE 2000").unwrap().unwrap();
        assert_eq!(thumb.architecture, format::Architecture::Thumb);
        assert_eq!(thumb.base, 0x2000);
        let arm64 = raw_model_input("ARM64 LE 140000000").unwrap().unwrap();
        assert_eq!(arm64.architecture, format::Architecture::Arm64);
        assert_eq!(arm64.base, 0x140000000);
        assert!(raw_model_input("AUTO").unwrap().is_none());
        /*
        The invalid table rejects case changes, noncanonical widths, incomplete fields, and bad numeric forms.
        No partial input can construct a raw model.
        */
        for input in [
            "auto",
            "AUTO ",
            "X86 8 LE 0",
            "X86 032 LE 0",
            "X86 +32 LE 0",
            "X86 16 ME 0",
            "X86 64 LE 0x10",
            "X86 64 LE 10 ",
            "X86  64 LE 10",
            "X86 64 LE 10000000000000000",
            "ARM64 64 LE 10",
            "ARM 32 LE 10",
            "THUMB ME 10",
        ] {
            assert!(raw_model_input(input).is_err(), "accepted {input:?}");
        }
    }
}
