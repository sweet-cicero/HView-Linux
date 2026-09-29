/*
These modules provide terminal I/O, file handling, editing, analysis, persistence, and bounded source access.
The main lifecycle connects their established interfaces without adding shared global state.
*/
/*
The analysis module supplies scoped work, cooperative cancellation, progress, and stamped terminal results.
The buffered Entropy tool connects these boundaries to Linux terminal input.
*/
mod analysis;
mod assembler;
mod checksum;
mod cli;
mod config;
mod console;
mod decoder;
mod editor;
mod files;
mod format;
mod inspect;
mod macros;
mod native;
mod operations;
mod paged;
mod save;
/*
L05.2 compiles resumable Text scans and suffix invalidation before L16 connects Text viewer integration.
The temporary allowance applies only to entries that have no application caller before L16.
*/
#[allow(
    dead_code,
    reason = "L05.2 builds the Text index contract before L16 viewer integration."
)]
mod text_index;
mod workbench;

/*
These imports provide the application state types and standard Linux path interfaces.
Native path values remain separate from text used for terminal display.
*/
use console::Console;
use editor::{Editor, Key, Mode};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/*
These constants define compact shortcut bars and bounded navigation history.
Each view selects the shortcut bar that matches its available operations.
*/
const NORMAL_KEYS: &str = " Alt: H Help E Edit M Mode G Goto F Find O Files | Ctrl+Q Quit ";
const TEXT_KEYS: &str = " Alt: H Help W Unwrap L Lines M Mode G Goto F Find O Files | Ctrl+Q Quit ";
const EDIT_KEYS: &str = " Alt+H Help  Ctrl+Z/Y Undo/Redo  Alt+S Save  Ctrl+S Save As  Esc Cancel ";
const CODE_EDIT_KEYS: &str =
    " Alt+H Help  Alt+A Assemble  Ctrl+Z/Y Undo/Redo  Alt+S Save  Esc Cancel ";
const PAGED_KEYS: &str = " Alt: H Help E Edit G Goto O Files P/N Prev/Next | Ctrl+Q Quit ";
const PAGED_EDIT_KEYS: &str =
    " Alt+S Save  Ctrl+S Save As  Ctrl+Z/Y Undo/Redo  Alt+G Goto  Esc Cancel ";
const RETURN_HISTORY_LIMIT: usize = 256;

/*
This helper writes visible text into a fixed terminal row.
The zip operation clips text at the available row width.
*/
fn put(line: &mut [char], column: usize, text: &str) {
    for (slot, ch) in line.iter_mut().skip(column).zip(text.chars()) {
        *slot = ch;
    }
}

/*
This formatter converts native pathname bytes into display text only.
Valid UTF-8 remains readable, terminal controls use Unicode escapes, and invalid bytes use hexadecimal escapes.
Callers retain the original PathBuf for every file operation.
*/
fn display_path(path: &std::ffi::OsStr) -> String {
    /*
    The loop copies each valid UTF-8 segment and escapes controls.
    An invalid segment becomes hexadecimal byte escapes before parsing continues.
    */
    let mut output = String::new();
    let mut bytes = path.as_bytes();
    loop {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                for character in text.chars() {
                    if character.is_control() {
                        output.push_str(&format!("\\u{{{:X}}}", character as u32));
                    } else {
                        output.push(character);
                    }
                }
                break;
            }
            Err(error) => {
                let (valid, rest) = bytes.split_at(error.valid_up_to());
                for character in std::str::from_utf8(valid).unwrap().chars() {
                    if character.is_control() {
                        output.push_str(&format!("\\u{{{:X}}}", character as u32));
                    } else {
                        output.push(character);
                    }
                }
                let count = error.error_len().unwrap_or(rest.len());
                for byte in &rest[..count] {
                    output.push_str(&format!("\\x{byte:02X}"));
                }
                bytes = &rest[count..];
                if bytes.is_empty() {
                    break;
                }
            }
        }
    }
    output
}

/*
This helper adds the Code architecture, format domain, and displayed address to one header.
File-domain fields end before the complete file-offset field starts.
*/
fn apply_code_header(
    header: &mut [char],
    file_offset: u64,
    location: format::CodeLocation,
    architecture: format::Architecture,
    real_mode: bool,
    format_label: Option<&str>,
    show_address: bool,
) {
    let width = header.len();
    let architecture_column = if location.domain == format::AddressDomain::File {
        width.saturating_sub(44)
    } else {
        width.saturating_sub(40)
    };
    put(
        header,
        architecture_column,
        if real_mode {
            "Real16"
        } else {
            architecture.label()
        },
    );
    if let Some(format_label) = format_label {
        let (label_column, label) = if location.domain == format::AddressDomain::File {
            (width.saturating_sub(38), "FILE")
        } else {
            (width.saturating_sub(31), format_label)
        };
        put(header, label_column, label);
    }
    if show_address || location.address != file_offset {
        put(
            header,
            width.saturating_sub(28),
            &format!(".{:08X}", location.address),
        );
    }
}

/*
This renderer converts one buffered Editor state into a complete terminal frame.
The header shows file state and position before the body and active key bar.
*/
fn frame(
    view: &Editor,
    file: &Path,
    console: &Console,
    updated: bool,
    writable: bool,
    metadata: &Result<format::Metadata, String>,
    decoder: &mut Option<decoder::Decoder>,
) -> Vec<String> {
    /*
    The first section builds a fixed-width header from the current file and editor state.
    Code mode adds its address model after the common header exists.
    */
    let (width, height) = console.dimensions();
    let body_rows = height.saturating_sub(2);
    let mut lines = vec![String::new(); height];
    let mut header = vec![' '; width];
    header[0] = '▲';
    put(
        &mut header,
        5,
        &display_path(file.file_name().unwrap_or_default()),
    );
    put(
        &mut header,
        width.saturating_sub(58),
        if view.editing {
            "↓FWO EDITMODE"
        } else if updated {
            "↓FUO --------"
        } else if writable {
            "↓FWO --------"
        } else {
            "↓FRO --------"
        },
    );
    put(
        &mut header,
        width.saturating_sub(33),
        &format!(
            "{:08X}│HView-Linux {}",
            view.offset,
            env!("CARGO_PKG_VERSION")
        ),
    );
    lines[0] = header.into_iter().collect();
    if view.raw_model.is_some() {
        let mut header: Vec<char> = lines[0].chars().collect();
        put(&mut header, width.saturating_sub(31), "RAW");
        lines[0] = header.into_iter().collect();
    }
    if view.mode == Mode::Code
        && let Ok(location) = code_location(metadata, view.offset)
        && let Ok(architecture) = metadata
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|metadata| metadata.decoder_architecture(view.code_bits))
    {
        let mut code_header: Vec<char> = lines[0].chars().collect();
        apply_code_header(
            &mut code_header,
            view.offset,
            location,
            architecture,
            effective_real_mode(view, architecture),
            if view.raw_model.is_none() {
                metadata
                    .as_ref()
                    .ok()
                    .and_then(format::Metadata::format_label)
            } else {
                None
            },
            view.raw_model.is_some(),
        );
        lines[0] = code_header.into_iter().collect();
    }

    /*
    The body uses decoded rows for Code mode and Editor rows for other modes.
    The left bar gives stable visual markers without changing the row data.
    */
    let body = if view.mode == Mode::Code {
        code_rows(view, body_rows, metadata, decoder)
    } else {
        view.render_body(width.saturating_sub(1), body_rows)
    };
    for (i, line) in body.iter().enumerate() {
        let bar = if i == 0 {
            '↑'
        } else if i == height.saturating_sub(4) {
            '↓'
        } else if i == height.saturating_sub(3) {
            '▼'
        } else if view.data.is_empty() {
            '░'
        } else {
            '▓'
        };
        if let Some(row) = lines.get_mut(i + 1) {
            *row = format!("{bar}{line}");
        }
    }
    if view.is_text && view.mode == Mode::Text {
        let line_count = view.data[..(view.offset as usize).min(view.data.len())]
            .windows(view.delimiter.len())
            .filter(|pair| *pair == view.delimiter)
            .count();
        let mut header: Vec<char> = lines[0].chars().collect();
        put(
            &mut header,
            width.saturating_sub(38),
            &format!("{line_count:6}"),
        );
        lines[0] = header.into_iter().collect();
    }

    /*
    The final section selects the key bar from mode and edit state.
    Padding fills the remaining terminal width with the established background character.
    */
    let text_keys = if view.wrap {
        TEXT_KEYS.to_owned()
    } else {
        TEXT_KEYS.replace("W Unwrap", "W Wrap  ")
    };
    let keys = if view.editing && view.mode == Mode::Code {
        CODE_EDIT_KEYS
    } else if view.editing {
        EDIT_KEYS
    } else if view.mode == Mode::Text {
        &text_keys
    } else {
        NORMAL_KEYS
    };
    if let Some(footer) = lines.last_mut() {
        *footer = format!(
            "{keys}{}",
            "▒".repeat(width.saturating_sub(keys.chars().count()))
        );
    }
    lines
}

/*
This helper converts a file offset into the current CodeLocation.
It preserves the stored format error and the address domain.
*/
fn code_location(
    metadata: &Result<format::Metadata, String>,
    offset: u64,
) -> Result<format::CodeLocation, String> {
    match metadata {
        Ok(metadata) => metadata.code_location(offset),
        Err(error) => Err(error.clone()),
    }
}

/*
This cache returns a decoder for the requested architecture, syntax, and Real16 state.
It replaces the cached decoder only when one requested property changes.
*/
fn decoder_for(
    decoder: &mut Option<decoder::Decoder>,
    architecture: format::Architecture,
    syntax: decoder::Syntax,
    real_mode: bool,
) -> Result<&decoder::Decoder, String> {
    if decoder.as_ref().is_none_or(|decoder| {
        decoder.architecture() != architecture
            || decoder.syntax() != syntax
            || decoder.real_mode() != real_mode
    }) {
        let replacement = decoder::Decoder::with_architecture(architecture, syntax, real_mode)?;
        *decoder = Some(replacement);
    }
    Ok(decoder.as_ref().unwrap())
}

/*
This helper enables Real16 only for an effective x86 16-bit decoder.
Automatic ARM-family PE selection cannot receive an x86 execution flag.
*/
fn effective_real_mode(view: &Editor, architecture: format::Architecture) -> bool {
    matches!(architecture, format::Architecture::X86(16)) && view.decode_real_mode()
}

/*
PreviewRows carries formatted instructions and the consumed source range.
The first instruction size supports replacement-length decisions.
*/
struct PreviewRows {
    rows: Vec<String>,
    end: usize,
    first_size: Option<usize>,
}

/*
AssemblyPreview separates summary text from original and proposed instruction columns.
The confirmation view consumes this record without changing editor bytes.
*/
#[derive(Debug)]
struct AssemblyPreview {
    summary: Vec<String>,
    original: Vec<String>,
    proposed: Vec<String>,
}

/*
This helper formats bytes for the assembly summary.
An empty slice identifies the file end explicitly.
*/
fn spaced_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<end of file>".into();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/*
This decoder builds bounded preview rows from one file range.
Optional byte fallback keeps invalid source bytes visible during comparison.
*/
fn preview_rows(
    data: &[u8],
    file_start: usize,
    stop: usize,
    metadata: &format::Metadata,
    decoder: &decoder::Decoder,
    byte_fallback: bool,
) -> PreviewRows {
    /*
    Each loop maps one file offset, decodes one instruction, and advances by its size.
    An address or decode error becomes the final explanatory row.
    */
    let mut rows = Vec::new();
    let mut relative = 0usize;
    let mut first_size = None;
    while file_start.saturating_add(relative) < stop {
        let file_offset = file_start.saturating_add(relative);
        let address = match metadata.code_address(file_offset as u64) {
            Ok((address, _)) => address,
            Err(error) => {
                rows.push(format!("F:{file_offset:X} <address error: {error}>"));
                break;
            }
        };
        let instruction = match if byte_fallback {
            decoder.decode_or_byte(data, relative as u64, address)
        } else {
            decoder.decode(data, relative as u64, address)
        } {
            Ok(instruction) => instruction,
            Err(error) => {
                rows.push(format!(
                    "F:{file_offset:X} <decode error: {error}> A:{address:X}"
                ));
                break;
            }
        };
        first_size.get_or_insert(instruction.size);
        let text = instruction
            .text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        rows.push(format!("F:{file_offset:X} {text} A:{address:X}"));
        relative = relative.saturating_add(instruction.size);
    }
    PreviewRows {
        rows,
        end: file_start.saturating_add(relative),
        first_size,
    }
}

/*
This builder validates an assembly replacement and prepares its comparison record.
It does not change Editor data before the user accepts the later confirmation.
*/
fn assembly_preview(
    view: &Editor,
    metadata: &format::Metadata,
    decoder: &mut Option<decoder::Decoder>,
    replacement: &[u8],
) -> Result<AssemblyPreview, String> {
    /*
    The first section checks the target range and selects a compatible decoder.
    These checks prevent an invalid replacement from reaching preview allocation.
    */
    if replacement.is_empty() {
        return Err("The assembler produced no replacement bytes.".into());
    }
    let start =
        usize::try_from(view.offset).map_err(|_| "The offset exceeds the address range.")?;
    if start > view.data.len() {
        return Err("The offset exceeds the file size.".into());
    }
    let end = start
        .checked_add(replacement.len())
        .ok_or("The instruction exceeds the address range.")?;
    let new_len = view.data.len().max(end);
    view.validate_raw_len(new_len)?;
    let address = metadata.code_address(view.offset)?.0;
    let architecture = metadata.decoder_architecture(view.code_bits)?;
    let decoder = decoder_for(
        decoder,
        architecture,
        view.syntax,
        effective_real_mode(view, architecture),
    )?;

    let original_stop = end.min(view.data.len());
    let mut original = preview_rows(
        &view.data[start..],
        start,
        original_stop,
        metadata,
        decoder,
        view.invalid_code_bytes,
    );

    /*
    The next section combines replacement bytes with enough original tail bytes for decoding.
    Decoder verification requires one complete replacement instruction.
    */
    if start == view.data.len() {
        original
            .rows
            .push(format!("F:{start:X} <end of file> A:{address:X}"));
    }
    let original_end = original.end.max(original_stop);
    let proposed_stop = end.max(original_end);
    let tail_end = proposed_stop
        .saturating_add(architecture.max_instruction_bytes() - 1)
        .min(view.data.len());
    let mut proposed_data = view.data[start..tail_end].to_vec();
    proposed_data.resize(proposed_data.len().max(replacement.len()), 0);
    proposed_data[..replacement.len()].copy_from_slice(replacement);

    let verified = decoder
        .decode(&proposed_data, 0, address)
        .map_err(|error| format!("Cannot verify the replacement instruction: {error}"))?;
    if verified.size != replacement.len() {
        return Err(
            "The assembler and decoder disagree on the replacement instruction length.".into(),
        );
    }
    let proposed = preview_rows(
        &proposed_data,
        start,
        proposed_stop,
        metadata,
        decoder,
        view.invalid_code_bytes,
    );

    /*
    The final section summarizes byte changes, overlap, and file growth.
    The confirmation screen uses this text with both instruction columns.
    */
    let original_size = original.first_size;
    let overwritten = original_stop.saturating_sub(start);
    let shown_original_size = original_size.unwrap_or(0).max(overwritten);
    let original_bytes = &view.data[start..start + shown_original_size];
    let delta = original_size
        .map(|size| format!("{:+} bytes", replacement.len() as i128 - size as i128))
        .unwrap_or_else(|| "n/a".into());
    let growth = new_len - view.data.len();
    let mut summary = vec![
        "Assembly patch preview".into(),
        format!("File offset: {start:08X} | Runtime address: {address:016X}"),
        format!(
            "Original bytes ({}): {}",
            original_bytes.len(),
            spaced_hex(original_bytes)
        ),
        format!(
            "Replacement bytes ({}): {}",
            replacement.len(),
            spaced_hex(replacement)
        ),
        format!("Replacement length delta: {delta} | File growth: +{growth} bytes"),
    ];
    let overlap = original.end.saturating_sub(end);
    if overlap != 0 {
        summary.push(format!(
            "Partial overlap: the final original instruction retains {overlap} byte(s)."
        ));
    }
    if original_size.is_some_and(|size| replacement.len() < size) {
        summary.push(format!(
            "Shorter replacement: {overlap} retained tail byte(s) will be re-decoded."
        ));
    }
    if growth != 0 {
        summary.push(format!("EOF growth: {growth} byte(s) will be appended."));
    }

    Ok(AssemblyPreview {
        summary,
        original: original.rows,
        proposed: proposed.rows,
    })
}

/*
This helper clips one preview field to its terminal column.
An ellipsis identifies removed text when the column has enough space.
*/
fn clipped(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.into();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    format!("{}...", text.chars().take(width - 3).collect::<String>())
}

/*
This helper places original and proposed preview text in equal terminal columns.
The center separator remains visible for every nonempty layout.
*/
fn preview_columns(width: usize, left: &str, right: &str) -> String {
    if width == 0 {
        return String::new();
    }
    let middle = width / 2;
    let mut line = vec![' '; width];
    put(&mut line[..middle], 0, &clipped(left, middle));
    line[middle] = '│';
    put(
        &mut line[middle + 1..],
        0,
        &clipped(right, width - middle - 1),
    );
    line.into_iter().collect()
}

/*
This helper wraps summary text at word boundaries for the confirmation screen.
It always returns at least one row.
*/
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + word.chars().count() + 1 > width {
            rows.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() || rows.is_empty() {
        rows.push(line);
    }
    rows
}

/*
This modal shows assembly effects and waits for apply or cancel.
Resize events rebuild the layout before the next decision.
*/
fn confirm_assembly(console: &Console, preview: &AssemblyPreview) -> io::Result<bool> {
    loop {
        /*
        This section calculates the required layout and builds either instructions or a resize notice.
        No editor state changes while the modal is open.
        */
        let (width, height) = console.dimensions();
        let layout_width = width.max(60);
        let summary: Vec<_> = preview
            .summary
            .iter()
            .flat_map(|text| wrap_text(text, layout_width))
            .collect();
        let required_height = summary.len().saturating_add(4);
        let ready = width >= 60 && height >= required_height;
        let mut lines = vec![String::new(); height];
        if !ready {
            if let Some(line) = lines.first_mut() {
                *line = "Assembly patch preview".into();
            }
            if let Some(line) = lines.get_mut(2) {
                *line = format!(
                    "Resize to at least 60 columns and {required_height} rows. Esc cancels."
                );
            }
            if let Some(line) = lines.last_mut() {
                *line = "Esc Cancel  Resize to apply".into();
            }
        } else {
            let mut row = 0usize;
            for text in summary {
                lines[row] = text;
                row += 1;
            }
            lines[row] = preview_columns(
                width,
                "Original affected instructions",
                "Proposed instructions",
            );
            row += 1;
            let available = height.saturating_sub(row + 1);
            let count = preview.original.len().max(preview.proposed.len());
            let truncated = count > available;
            let data_rows = if truncated {
                available.saturating_sub(1)
            } else {
                count
            };
            for index in 0..data_rows {
                lines[row + index] = preview_columns(
                    width,
                    preview.original.get(index).map_or("", String::as_str),
                    preview.proposed.get(index).map_or("", String::as_str),
                );
            }
            if truncated {
                lines[row + available - 1] = "Preview rows truncated to fit the console.".into();
            }
            lines[height - 1] = "Enter Apply  Esc Cancel".into();
        }

        /*
        The input section redraws after resize and returns only an explicit user decision.
        Enter cannot apply a preview that does not fit.
        */
        console.draw(&lines)?;
        let key = console.key()?;
        let resized = console.dimensions() != (width, height);
        match key.code {
            27 => return Ok(false),
            _ if resized => {}
            13 if ready => return Ok(true),
            _ => {}
        }
    }
}

/*
This helper decodes one instruction at a buffered file offset.
Configured invalid-byte and packed-byte rules determine the returned display instruction.
*/
fn decode_at(
    view: &Editor,
    offset: u64,
    metadata: &Result<format::Metadata, String>,
    decoder: &mut Option<decoder::Decoder>,
) -> Result<(u64, decoder::Instruction), String> {
    /*
    Address conversion and decoder selection happen before byte fallback.
    The fallback produces one data-byte instruction only when configuration permits it.
    */
    let location = code_location(metadata, offset)?;
    let architecture = metadata
        .as_ref()
        .map_err(Clone::clone)?
        .decoder_architecture(view.code_bits)?;
    let decoder = decoder_for(
        decoder,
        architecture,
        view.syntax,
        effective_real_mode(view, architecture),
    )?;
    let mut instruction = if view.invalid_code_bytes {
        decoder.decode_or_byte(&view.data, offset, location.address)?
    } else {
        decoder.decode(&view.data, offset, location.address)?
    };

    /*
    Packed NOP and INT3 runs become one visible instruction with their combined length.
    The caller advances by the resulting instruction size.
    */
    if matches!(architecture, format::Architecture::X86(_))
        && instruction.size == 1
        && let Some(&byte) = view.data.get(offset as usize)
        && ((byte == 0x90 && view.pack_nops) || (byte == 0xCC && view.pack_int3))
    {
        let count = view.data[offset as usize..]
            .iter()
            .take(architecture.max_instruction_bytes())
            .take_while(|&&value| value == byte)
            .count();
        instruction.size = count;
        instruction.hex = format!("{byte:02X}").repeat(count);
    }
    Ok((location.address, instruction))
}

/*
This helper resolves a direct branch or call target from the selected instruction.
It converts the runtime target back to a checked file offset.
*/
fn direct_target_offset(
    view: &Editor,
    metadata: &Result<format::Metadata, String>,
    decoder: &mut Option<decoder::Decoder>,
) -> Result<u64, String> {
    /*
    The source section selects one current byte, Code domain, architecture, and native decoder.
    The decoder reads only bytes that start at the selected source offset.
    */
    let metadata = metadata.as_ref().map_err(Clone::clone)?;
    let location = metadata.code_location(view.offset)?;
    let address = location.address;
    let start =
        usize::try_from(view.offset).map_err(|_| "The branch source exceeds the address range.")?;
    let bytes = view
        .data
        .get(start..)
        .filter(|bytes| !bytes.is_empty())
        .ok_or("The branch source is outside the current buffer.")?;
    let architecture = metadata.decoder_architecture(view.code_bits)?;
    let decoder = decoder_for(
        decoder,
        architecture,
        view.syntax,
        effective_real_mode(view, architecture),
    )?;
    let instruction_size = decoder.decode(bytes, 0, address)?.size;
    let target = decoder
        .direct_target(bytes, address)?
        .ok_or("The instruction has no direct relative branch or call target.")?;

    /*
    The target section corrects native low 32-bit File-domain results when required.
    It then maps the result through the same domain as the displayed source.
    */
    let target = if location.domain == format::AddressDomain::File {
        file_domain_target(architecture, view.offset, instruction_size, target)?
    } else {
        target
    };
    let target = metadata.target_offset(location.domain, target)?;

    /*
    The final section requires one current buffered target byte before navigation can change state.
    This check also bounds explicit raw Metadata, which does not store a file length.
    */
    let index =
        usize::try_from(target).map_err(|_| "The branch target exceeds the address range.")?;
    view.data
        .get(index)
        .map(|_| target)
        .ok_or_else(|| "The branch target is outside the current buffer.".into())
}

/*
This helper corrects Capstone target truncation for non-64-bit File-domain branches.
The signed low 32-bit displacement restores high file offsets without parsing instruction bytes.
*/
fn file_domain_target(
    architecture: format::Architecture,
    source: u64,
    instruction_size: usize,
    target: u64,
) -> Result<u64, String> {
    if !matches!(
        architecture,
        format::Architecture::X86(16 | 32)
            | format::Architecture::Arm
            | format::Architecture::Thumb
    ) {
        return Ok(target);
    }
    if instruction_size == 0 {
        return Err("The file branch location is invalid.".into());
    }
    let next = source
        .checked_add(instruction_size as u64)
        .ok_or("The branch target exceeds the address range.")?;
    let delta = (target as u32).wrapping_sub(next as u32) as i32;
    next.checked_add_signed(i64::from(delta))
        .ok_or_else(|| "The branch target exceeds the address range.".into())
}

/*
This helper appends one Code navigation return position.
It removes the oldest position when the bounded history is full.
*/
fn remember_return(history: &mut VecDeque<(u64, u64)>, position: (u64, u64)) {
    if history.len() >= RETURN_HISTORY_LIMIT {
        history.pop_front();
    }
    history.push_back(position);
}

/*
This helper validates the newest return position against current buffered bytes.
It removes the position only after validation succeeds.
*/
fn take_return(
    history: &mut VecDeque<(u64, u64)>,
    data: &[u8],
) -> Result<Option<(u64, u64)>, String> {
    let Some(&(offset, top)) = history.back() else {
        return Ok(None);
    };
    let offset = usize::try_from(offset)
        .map_err(|_| "The branch return position exceeds the address range.")?;
    if data.get(offset).is_none() || top > data.len() as u64 {
        return Err("The branch return position is outside the current buffer.".into());
    }
    Ok(history.pop_back())
}

/*
This helper decodes the selected instruction as the default assembly input.
X86 seeds use Intel syntax, while ARM-family seeds use their native syntax.
*/
fn assembly_seed(
    view: &Editor,
    metadata: &Result<format::Metadata, String>,
) -> Result<String, String> {
    let address = metadata
        .as_ref()
        .map_err(Clone::clone)?
        .code_address(view.offset)?
        .0;
    let architecture = metadata
        .as_ref()
        .map_err(Clone::clone)?
        .decoder_architecture(view.code_bits)?;
    decoder::Decoder::with_architecture(
        architecture,
        decoder::Syntax::Intel,
        effective_real_mode(view, architecture),
    )?
    .decode(&view.data, view.offset, address)
    .map(|instruction| instruction.text)
}

/*
This helper cycles raw or standard Code widths through their supported sequence.
Standard Code mode includes Real16 after the 64-bit state.
*/
fn cycle_code_mode(view: &mut Editor) -> Result<(), String> {
    if let Some(mut model) = view.raw_model {
        model.architecture = match model.architecture {
            format::Architecture::X86(16) => format::Architecture::X86(32),
            format::Architecture::X86(32) => format::Architecture::X86(64),
            format::Architecture::X86(64) => format::Architecture::X86(16),
            format::Architecture::X86(_) => {
                return Err("The raw x86 code width must be 16, 32, or 64 bits.".into());
            }
            format::Architecture::Arm
            | format::Architecture::Thumb
            | format::Architecture::Arm64 => {
                return Err("Use Ctrl+T, then R, to select a raw architecture.".into());
            }
        };
        return view.set_raw_model(Some(model));
    }
    if !matches!(
        view.metadata()?.decoder_architecture(view.code_bits)?,
        format::Architecture::X86(_)
    ) {
        return Err("The current ARM architecture does not use x86 code widths.".into());
    }
    if view.real_mode {
        view.real_mode = false;
        view.code_bits = 16;
    } else {
        match view.code_bits {
            16 => view.code_bits = 32,
            32 => view.code_bits = 64,
            _ => {
                view.code_bits = 16;
                view.real_mode = true;
            }
        }
    }
    Ok(())
}

/*
This renderer decodes buffered Code rows until the screen or file ends.
The first decode error becomes a visible row and stops further decoding.
*/
fn code_rows(
    view: &Editor,
    rows: usize,
    metadata: &Result<format::Metadata, String>,
    decoder: &mut Option<decoder::Decoder>,
) -> Vec<String> {
    let mut result = Vec::with_capacity(rows);
    let mut offset = view.top;
    while result.len() < rows && offset < view.data.len() as u64 {
        match decode_at(view, offset, metadata, decoder) {
            Ok((address, instruction)) => {
                result.push(format!(
                    "{}{:08X}: {:<31}{}",
                    if address != offset { '.' } else { ' ' },
                    address,
                    instruction
                        .hex
                        .chars()
                        .take(view.opcode_bytes * 2)
                        .collect::<String>(),
                    instruction.text
                ));
                offset += instruction.size as u64;
            }
            Err(error) => {
                result.push(format!(" {offset:08X}: {error}"));
                break;
            }
        }
    }
    result.resize(rows, String::new());
    result
}

/*
This picker lists native directory entries and returns the selected PathBuf.
Display escaping never changes the path used for directory navigation or opening.
*/
fn select_file(console: &Console, mut folder: PathBuf) -> io::Result<Option<PathBuf>> {
    if folder.as_os_str().is_empty() {
        folder = std::env::current_dir()?;
    }
    let mut selected = 0usize;
    loop {
        /*
        Each frame reads and sorts current entries, then adds the parent directory.
        Directories sort before files while the original native paths remain stored.
        */
        let mut entries: Vec<_> = fs::read_dir(&folder)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort_by_key(|path| {
            (
                !path.is_dir(),
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_lowercase(),
            )
        });
        if let Some(parent) = folder.parent() {
            entries.insert(0, parent.to_owned());
        }
        selected = selected.min(entries.len().saturating_sub(1));

        /*
        The display section escapes path text and shows only entries that fit.
        The selection marker identifies the PathBuf used by the input section.
        */
        let (width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        if let Some(line) = lines.get_mut(2) {
            *line = format!("  {}", display_path(folder.as_os_str()));
        }
        for (i, path) in entries
            .iter()
            .skip(selected.saturating_sub(height.saturating_sub(7)))
            .take(height.saturating_sub(6))
            .enumerate()
        {
            if let Some(line) = lines.get_mut(i + 3) {
                *line = format!(
                    "  {} {}{}",
                    if entries.get(selected) == Some(path) {
                        '>'
                    } else {
                        ' '
                    },
                    display_path(path.file_name().unwrap_or_default()),
                    if path.is_dir() { "/" } else { "" }
                );
            }
        }
        if let Some(footer) = lines.last_mut() {
            *footer = format!(
                " Enter Open   Esc Quit{}",
                " ".repeat(width.saturating_sub(27))
            );
        }
        console.draw(&lines)?;

        /*
        Input changes the selection, enters a directory, returns a file, or cancels.
        Escape and Ctrl+Q cancel the picker. Legacy macro F10 records remain compatible.
        */
        let key = console.key()?;
        let ctrl = key.control & 12 != 0;
        match key.code {
            27 | 121 => return Ok(None),
            81 if ctrl => return Ok(None),
            38 => selected = selected.saturating_sub(1),
            40 => selected = (selected + 1).min(entries.len().saturating_sub(1)),
            13 => {
                if let Some(path) = entries.get(selected) {
                    if path.is_dir() {
                        folder = path.clone();
                        selected = 0;
                    } else {
                        return Ok(Some(path.clone()));
                    }
                }
            }
            112..=123 => {
                console.modal(&lines, "This file-selector operation is not reconstructed.")?;
            }
            _ => {}
        }
    }
}

/*
This parser converts complete hexadecimal pairs into search bytes.
It rejects empty, odd-length, and non-ASCII input before conversion.
*/
fn hex_pattern(text: &str) -> Result<Vec<u8>, String> {
    let value: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !value.is_ascii() || value.is_empty() || !value.len().is_multiple_of(2) {
        return Err("Enter complete hexadecimal byte pairs.".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
                .map_err(|_| "Enter hexadecimal byte pairs.".into())
        })
        .collect()
}

/*
This wrapper creates a buffered Editor from bytes and configured view rules.
It keeps view construction in the configuration module.
*/
fn new_view(
    data: Vec<u8>,
    mode: Mode,
    offset: u64,
    config: &config::Config,
) -> Result<Editor, String> {
    config.new_view(data, mode, offset)
}

/*
This selector resolves startup mode from CLI options before configuration defaults.
An offset mode can supply the mode when no explicit mode exists.
*/
fn startup_mode(options: &cli::Options, config: &config::Config) -> Mode {
    let selected = options
        .mode
        .unwrap_or_else(|| options.offset.as_ref().map_or(0, |offset| offset.mode));
    match selected {
        1 => Mode::Text,
        2 => Mode::Hex,
        3 => Mode::Code,
        _ => match config.start_mode.as_str() {
            "Hex" => Mode::Hex,
            "Code" => Mode::Code,
            _ => Mode::Text,
        },
    }
}

/*
This converter accepts only absolute saved paths on Linux.
It reports Windows and unsafe relative syntax without selecting another file.
*/
fn restored_path(text: &str) -> Result<PathBuf, String> {
    let path = Path::new(text);
    if path.is_absolute() {
        return Ok(path.into());
    }
    let bytes = text.as_bytes();
    let drive = bytes.get(1) == Some(&b':') && bytes.first().is_some_and(u8::is_ascii_alphabetic);
    if drive || text.contains('\\') {
        return Err(format!(
            "The saved path uses Windows syntax and cannot open on Linux: {text}"
        ));
    }
    Err(format!(
        "The saved path is relative and cannot restore safely: {text}"
    ))
}

/*
The paged view keeps only display state while PagedFile owns source bytes.
All positions remain u64 values for files that exceed the process address space.
The runtime metadata fields can enter the existing content-free session record after close.
The nibble fields exist only while this paged view remains active.
*/
#[derive(Clone, Debug)]
struct PagedView {
    offset: u64,
    top: u64,
    low_nibble: bool,
    hex_start: Option<paged::PagedEditCursor>,
    code_bits: u32,
    real_mode: bool,
    wrap: bool,
    tab: bool,
    line_feed: config::LineFeed,
    text_column: usize,
    local_offset: bool,
}

/*
These helpers convert the visible paged position to the transaction cursor and restore it.
The edit-only fields stay outside runtime and SAV records because active edits cannot close normally.
*/
impl PagedView {
    /*
    This conversion captures the selected logical byte, viewport, and nibble.
    PagedFile stores this value at each undo and redo boundary.
    */
    fn edit_cursor(&self) -> paged::PagedEditCursor {
        paged::PagedEditCursor {
            offset: self.offset,
            top: self.top,
            low_nibble: self.low_nibble,
        }
    }

    /*
    This restoration applies one history cursor to the matching logical layout.
    The selected byte can equal EOF after a completed final byte.
    Viewport correction uses the final real byte and preserves a valid recorded top.
    */
    fn restore_edit_cursor(&mut self, cursor: paged::PagedEditCursor, len: u64, rows: usize) {
        self.offset = cursor.offset.min(len);
        self.top = cursor.top.min(len.saturating_sub(1));
        self.low_nibble = cursor.low_nibble;
        self.hex_start = None;
        if len == 0 {
            self.offset = 0;
            self.top = 0;
            self.low_nibble = false;
            return;
        }
        let visible = self.offset.min(len - 1);
        let page = (rows.max(1) as u64).saturating_mul(16);
        if visible < self.top {
            self.top = visible / 16 * 16;
        }
        if visible >= self.top.saturating_add(page) {
            self.top = (visible / 16 + 1)
                .saturating_sub(rows.max(1) as u64)
                .saturating_mul(16);
        }
    }
}

/*
RuntimeView keeps bounded restoration state for one native path.
The application updates this state after every close, even when SAV publication is unavailable.
The record never owns file contents or converts its associated native path.
*/
#[derive(Clone, Debug)]
struct RuntimeView {
    mode: Mode,
    offset: u64,
    top: u64,
    code_bits: u32,
    real_mode: bool,
    wrap: bool,
    tab: bool,
    line_feed: config::LineFeed,
    text_column: usize,
    local_offset: bool,
}

/*
These conversions move view metadata between session, Editor, and runtime records.
No conversion owns source bytes or changes the associated native path.
*/
impl RuntimeView {
    /*
    This conversion imports existing session fields into native runtime state.
    The associated native path remains in the parallel path list.
    */
    fn from_saved(saved: &config::SavedFile) -> Self {
        Self {
            mode: match saved.mode {
                2 => Mode::Hex,
                3 => Mode::Code,
                _ => Mode::Text,
            },
            offset: saved.offset,
            top: saved.top,
            code_bits: saved.code_bits,
            real_mode: saved.real_mode,
            wrap: saved.wrap,
            tab: saved.tab,
            line_feed: saved.line_feed,
            text_column: saved.text_column,
            local_offset: saved.local_offset,
        }
    }

    /*
    This conversion captures the buffered editor fields after a close or file switch.
    Later opens restore these fields without retaining the complete Editor or its bytes.
    */
    fn from_editor(view: &Editor, local_offset: bool) -> Result<Self, String> {
        let line_feed = match view.delimiter {
            b"\r\n" => config::LineFeed::CrLf,
            b"\r" => config::LineFeed::Cr,
            b"\n" => config::LineFeed::Lf,
            _ => return Err("The saved line-feed mode is not reconstructed.".into()),
        };
        Ok(Self {
            mode: view.mode,
            offset: view.offset,
            top: view.top,
            code_bits: view.code_bits,
            real_mode: view.real_mode,
            wrap: view.wrap,
            tab: view.expand_tabs,
            line_feed,
            text_column: view.text_column,
            local_offset,
        })
    }

    /*
    This conversion adds legacy path text only at the SAV publication boundary.
    All view fields remain independent from the path representation result.
    */
    fn session_view(&self, path: String) -> config::SessionView {
        config::SessionView {
            path,
            mode: self.mode,
            offset: self.offset,
            top: self.top,
            code_bits: self.code_bits,
            real_mode: self.real_mode,
            wrap: self.wrap,
            tab: self.tab,
            line_feed: self.line_feed,
            text_column: self.text_column,
            local_offset: self.local_offset,
        }
    }
}

/*
The closed paged result separates the native path from legacy session text.
The outer lifecycle validates path representation before it mutates SAV state.
*/
struct PagedClosed {
    path: PathBuf,
    view: PagedView,
}

/*
ClosedView returns either complete buffered editor state or bounded paged state.
The outer lifecycle handles both results through one action path.
*/
enum ClosedView {
    Buffered(PathBuf, Editor),
    Paged(PagedClosed),
}

/*
This conversion makes paged display state available to the shared runtime record.
The native path stays in PagedClosed until the lifecycle updates its path list.
*/
impl PagedClosed {
    /*
    This conversion copies paged display fields into the shared runtime record.
    The caller stores the record beside its unchanged native path.
    */
    fn runtime_view(&self) -> RuntimeView {
        RuntimeView {
            mode: Mode::Hex,
            offset: self.view.offset,
            top: self.view.top,
            code_bits: self.view.code_bits,
            real_mode: self.view.real_mode,
            wrap: self.view.wrap,
            tab: self.view.tab,
            line_feed: self.view.line_feed,
            text_column: self.view.text_column,
            local_offset: self.view.local_offset,
        }
    }
}

/*
This opener handles the established missing-file prompt before storage selection.
A created file receives a fresh read-only descriptor through the common selector.
*/
fn open_source(console: &Console, path: &Path) -> io::Result<Option<paged::OpenedSource>> {
    match paged::open_source(path) {
        Ok(source) => Ok(Some(source)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = console.modal(&[], "File not found. Press 'C' for create")?;
            if !key.accepts_text() || !key.character.eq_ignore_ascii_case(&'c') {
                return Ok(None);
            }
            OpenOptions::new().write(true).create_new(true).open(path)?;
            paged::open_source(path).map(Some)
        }
        Err(error) => Err(error),
    }
}

/*
This formatter receives one bounded row slice and its full source address.
The hexadecimal groups and CP437 text match the buffered Hex view.
*/
fn paged_hex_line(data: &[u8], address: u64, delimiter: char) -> String {
    let mut line = format!(" {address:08X}:  ");
    for index in 0..16 {
        if index > 0 {
            line.push(if index % 4 == 0 { delimiter } else { ' ' });
        }
        if let Some(byte) = data.get(index) {
            line.push_str(&format!("{byte:02X}"));
        } else {
            line.push_str("  ");
        }
    }
    line.push_str("  ");
    line.extend(data.iter().take(16).map(|byte| editor::cp437(*byte)));
    line
}

/*
This reader requests only visible rows and splits large terminals into 64 KiB windows.
Each returned row contains actual bytes or an EOF-clipped final row.
The result adds empty display rows only after the valid source range ends.
*/
fn paged_hex_rows(
    source: &paged::PagedFile,
    top: u64,
    rows: usize,
    delimiter: char,
) -> io::Result<Vec<String>> {
    let mut lines = Vec::with_capacity(rows);
    let mut address = top;
    while lines.len() < rows && address < source.len() {
        let row_count = rows - lines.len();
        let request = row_count.saturating_mul(16).min(paged::MAX_READ_BYTES);
        let window = source.read_window(address, request)?;
        if window.bytes.is_empty() {
            break;
        }
        address = window.start;
        for bytes in window.bytes.chunks(16) {
            lines.push(paged_hex_line(bytes, address, delimiter));
            address = address.saturating_add(bytes.len() as u64);
        }
    }
    if source.len() == 0 && rows != 0 {
        lines.push(paged_hex_line(&[], 0, delimiter));
    }
    lines.resize(rows, String::new());
    Ok(lines)
}

/*
This frame validates and displays the paged view without a file-sized Editor.
The address fields use a minimum width and preserve every high address digit.
The footer lists only controls that the paged view implements.
*/
fn paged_frame(
    view: &PagedView,
    file: &Path,
    source: &paged::PagedFile,
    console: &Console,
    delimiter: char,
) -> io::Result<Vec<String>> {
    /*
    The header shows escaped native filename text, source state, mode, and full selected offset.
    Fixed-width writes clip fields to the current terminal width.
    */
    let (width, height) = console.dimensions();
    let body_rows = height.saturating_sub(2);
    let mut lines = vec![String::new(); height];
    let mut header = vec![' '; width];
    header[0] = '▲';
    put(
        &mut header,
        5,
        &display_path(file.file_name().unwrap_or_default()),
    );
    let source_state = if source.editing() {
        if source.has_changes() {
            "↓MEM EDITMODE"
        } else {
            "↓FRO EDITMODE"
        }
    } else {
        "↓FRO PAGED HEX"
    };
    put(&mut header, width.saturating_sub(58), source_state);
    let status = format!(
        "{:08X}│HView-Linux {}",
        view.offset,
        env!("CARGO_PKG_VERSION")
    );
    put(
        &mut header,
        width.saturating_sub(status.chars().count()),
        &status,
    );
    lines[0] = header.into_iter().collect();

    /*
    The body requests all visible source rows through one or more bounded windows.
    Bar characters identify screen positions and the empty-source state.
    */
    let body = paged_hex_rows(source, view.top, body_rows, delimiter)?;
    for (index, line) in body.into_iter().enumerate() {
        let bar = if index == 0 {
            '↑'
        } else if index == height.saturating_sub(4) {
            '↓'
        } else if index == height.saturating_sub(3) {
            '▼'
        } else if source.len() == 0 {
            '░'
        } else {
            '▓'
        };
        if let Some(row) = lines.get_mut(index + 1) {
            *row = format!("{bar}{line}");
        }
    }

    /*
    The footer lists only implemented paged commands and fills unused width.
    The complete frame returns only after every section is available.
    */
    if let Some(footer) = lines.last_mut() {
        let keys = if source.editing() {
            PAGED_EDIT_KEYS
        } else {
            PAGED_KEYS
        };
        *footer = format!(
            "{keys}{}",
            "▒".repeat(width.saturating_sub(keys.chars().count()))
        );
    }
    Ok(lines)
}

/*
This positioning helper centers a requested byte and clamps the final visible page.
Empty files keep both positions at zero.
Goto also selects the high nibble and closes pending nibble cursor state.
*/
fn paged_goto(view: &mut PagedView, requested: u64, len: u64, rows: usize) {
    view.offset = if len == 0 { 0 } else { requested.min(len - 1) };
    view.low_nibble = false;
    view.hex_start = None;
    let rows = rows.max(1) as u64;
    view.top = view.offset.saturating_sub(rows.saturating_mul(8)) / 16 * 16;
    let file_rows = len.div_ceil(16);
    let final_top = file_rows.saturating_sub(rows).saturating_mul(16);
    view.top = view.top.min(final_top);
}

/*
This restoration keeps a valid saved viewport and clamps stale positions after file changes.
If the saved selected byte is outside the page, normal Goto positioning makes it visible.
*/
fn restore_paged_position(view: &mut PagedView, len: u64, rows: usize) {
    if len == 0 {
        view.offset = 0;
        view.top = 0;
        return;
    }
    view.offset = view.offset.min(len - 1);
    view.top = view.top.min(len - 1);
    let page = (rows.max(1) as u64).saturating_mul(16);
    if view.offset < view.top || view.offset >= view.top.saturating_add(page) {
        paged_goto(view, view.offset, len, rows);
    }
}

/*
This navigation keeps the selected byte inside the visible bounded Hex page.
Checked and saturating movement clamps every operation at the source boundaries.
*/
fn paged_navigate(view: &mut PagedView, key: Key, len: u64, rows: usize) {
    /*
    The first section moves the selected byte with checked or saturating arithmetic.
    Page movement preserves the selected hexadecimal column when possible.
    */
    let final_byte = len.saturating_sub(1);
    let page = (rows.max(1) as u64).saturating_mul(16);
    match key {
        Key::Left => view.offset = view.offset.saturating_sub(1),
        Key::Right => view.offset = view.offset.saturating_add(1).min(final_byte),
        Key::Up => {
            if view.offset >= 16 {
                view.offset -= 16;
            }
        }
        Key::Down => {
            if view.offset.saturating_add(16) < len {
                view.offset += 16;
            }
        }
        Key::Home => view.offset = view.offset / 16 * 16,
        Key::End => view.offset = (view.offset / 16 * 16 + 15).min(final_byte),
        Key::PageUp => {
            view.top = view.top.saturating_sub(page);
            view.offset = view.top.saturating_add(view.offset % 16).min(final_byte);
        }
        Key::PageDown => {
            let column = view.offset % 16;
            let next = view.top.saturating_add(page).saturating_add(column);
            if next < len {
                view.top = view.top.saturating_add(page);
                view.offset = next;
            } else {
                view.offset = (final_byte / 16 * 16 + column).min(final_byte);
            }
        }
        Key::FileStart => {
            view.offset = 0;
            view.top = 0;
        }
        Key::FileEnd => view.offset = final_byte,
    }

    /*
    The second section handles an empty source and keeps the selected byte inside the viewport.
    Viewport correction aligns the top to a complete hexadecimal row.
    */
    if len == 0 {
        view.offset = 0;
        view.top = 0;
        return;
    }
    if view.offset < view.top {
        view.top = view.offset / 16 * 16;
    }
    if view.offset >= view.top.saturating_add(page) {
        view.top = (view.offset / 16 + 1)
            .saturating_sub(rows.max(1) as u64)
            .saturating_mul(16);
    }
}

/*
This helper applies paged navigation while edit mode selects one hexadecimal nibble.
Left and Right move through nibbles, while other keys keep the accepted byte movement.
The caller closes a pending byte group before this helper changes the cursor.
*/
fn paged_edit_navigate(view: &mut PagedView, key: Key, len: u64, rows: usize) {
    match key {
        Key::Left => {
            if !view.low_nibble {
                view.offset = view.offset.saturating_sub(1);
            }
            view.low_nibble = !view.low_nibble;
        }
        Key::Right => {
            if view.low_nibble {
                view.offset = view.offset.saturating_add(1).min(len);
            }
            view.low_nibble = !view.low_nibble;
        }
        key => {
            paged_navigate(view, key, len, rows);
            if matches!(key, Key::Home | Key::End | Key::FileStart | Key::FileEnd) {
                view.low_nibble = false;
            }
        }
    }

    /*
    Nibble movement can select EOF after the final low nibble.
    The viewport follows the final real byte without changing the EOF selection.
    */
    if len != 0 {
        let visible = view.offset.min(len - 1);
        let page = (rows.max(1) as u64).saturating_mul(16);
        if visible < view.top {
            view.top = visible / 16 * 16;
        }
        if visible >= view.top.saturating_add(page) {
            view.top = (visible / 16 + 1)
                .saturating_sub(rows.max(1) as u64)
                .saturating_mul(16);
        }
    }
}

/*
This helper replaces one selected paged Hex nibble through the shared transaction path.
It reads one logical byte, calculates the new byte, and commits cursor state only after success.
The operation refuses EOF to match Windows paged Hex overtype behavior.
*/
fn paged_hex_digit(
    source: &mut paged::PagedFile,
    view: &mut PagedView,
    character: char,
) -> io::Result<()> {
    let digit = character
        .to_digit(16)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Enter a hexadecimal digit."))?
        as u8;
    if view.offset >= source.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Paged Hex editing cannot extend the file at EOF.",
        ));
    }
    let current = source
        .read_window(view.offset, 1)?
        .bytes
        .first()
        .copied()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Cannot read the selected byte.",
            )
        })?;
    let low_nibble = view.low_nibble;
    let before_cursor = view.hex_start.unwrap_or_else(|| view.edit_cursor());
    let after_cursor = paged::PagedEditCursor {
        offset: view.offset + u64::from(low_nibble),
        top: view.top,
        low_nibble: !low_nibble,
    };
    let replacement = editor::replace_nibble(current, digit, low_nibble);
    source.replace_bytes(
        view.offset,
        &[replacement],
        before_cursor,
        after_cursor,
        !low_nibble,
    )?;
    view.offset = after_cursor.offset;
    view.top = after_cursor.top;
    view.low_nibble = after_cursor.low_nibble;
    view.hex_start = (!low_nibble).then_some(before_cursor);
    Ok(())
}

/*
This helper cancels every in-memory paged edit and returns to read-only navigation.
The source restores its captured layout while the view clamps any prior EOF cursor.
*/
fn cancel_paged_edit(source: &mut paged::PagedFile, view: &mut PagedView, rows: usize) {
    source.cancel_edit();
    view.low_nibble = false;
    view.hex_start = None;
    restore_paged_position(view, source.len(), rows);
}

/*
This handler displays an edit error without redrawing stale or replacement source bytes.
The blank error screen keeps the active owner and makes explicit cancellation available.
*/
fn paged_edit_error(
    console: &Console,
    source: &mut paged::PagedFile,
    view: &mut PagedView,
    error: &io::Error,
) -> io::Result<()> {
    let mut base = vec![String::new(); console.height()];
    if let Some(header) = base.first_mut() {
        *header = "Edits remain in memory. Saving requires a stable source.".into();
    }
    if let Some(footer) = base.last_mut() {
        *footer = "Press Escape to cancel all in-memory edits.".into();
    }
    let key = console.modal(&base, &error.to_string())?;
    if key.code == 27 {
        cancel_paged_edit(source, view, console.height().saturating_sub(2));
    }
    Ok(())
}

/*
This helper ends a replacement view that cannot reopen its published path.
The missing closed view prevents stale runtime state, and the flag prevents a stale SAV publication.
*/
fn close_unusable_paged_view(session_publish: &mut bool) -> (EditorAction, Option<PagedClosed>) {
    *session_publish = false;
    (EditorAction::Quit, None)
}

/*
This view retains the owned source during all frames and key actions.
Unsupported modes and address conversions produce notices before Hex display starts.
Each loop validates the source before it publishes the next frame.
*/
fn open_paged_editor(
    console: &Console,
    mut path: PathBuf,
    mut source: paged::PagedFile,
    options: &cli::Options,
    config: &config::Config,
    saved: Option<&RuntimeView>,
    session_publish: &mut bool,
) -> io::Result<(EditorAction, Option<PagedClosed>)> {
    /*
    The first section reports requested Text or Code mode before selecting Hex.
    The notice makes the current large-file limit visible to the user.
    */
    let requested_mode = saved
        .map(|state| state.mode)
        .unwrap_or_else(|| startup_mode(options, config));
    if requested_mode != Mode::Hex {
        console.modal(
            &[],
            "The large-file view supports Hex mode only. HView-Linux will open Hex mode.",
        )?;
    }

    /*
    New views resolve File and End offsets from the captured source length.
    Virtual and entry requests read bounded current metadata without reading the complete source.
    */
    let mut initial = 0;
    if saved.is_none()
        && let Some(offset) = &options.offset
    {
        let requested = match offset.target {
            cli::OffsetTarget::File(value) => Ok(value),
            cli::OffsetTarget::End => Ok(source.len().saturating_sub(1)),
            cli::OffsetTarget::Virtual(value) => format::Metadata::read_from(&source)
                .and_then(|metadata| metadata.legacy_virtual_offset(value)),
            cli::OffsetTarget::EntryPoint => {
                format::Metadata::read_from(&source).and_then(|metadata| metadata.entry_offset())
            }
        };
        initial = match requested {
            Ok(value) => value,
            Err(error) => {
                console.modal(&[], &error)?;
                0
            }
        };
        if initial >= source.len() && source.len() != 0 {
            console.modal(&[], "Jump out of file")?;
            initial = 0;
        }
    }

    /*
    Configuration supplies initial display fields without creating an Editor or copying source bytes.
    A saved runtime record then replaces those fields for a reopened view.
    */
    let line_feed = match config.line_feed {
        config::LineFeed::Auto => config::LineFeed::CrLf,
        value => value,
    };
    let mut view = PagedView {
        offset: initial,
        top: 0,
        low_nibble: false,
        hex_start: None,
        code_bits: config.default_code_size,
        real_mode: false,
        wrap: config.wrap.resolve(true),
        tab: config.tab.resolve(false),
        line_feed,
        text_column: 0,
        local_offset: config.show_offset_local,
    };
    if let Some(state) = saved {
        if !state.local_offset {
            return Err(io::Error::other(
                "Saved global offset display is not reconstructed.",
            ));
        }
        view.offset = state.offset;
        view.top = state.top;
        view.code_bits = state.code_bits;
        view.real_mode = state.real_mode;
        view.wrap = state.wrap;
        view.tab = state.tab;
        view.line_feed = state.line_feed;
        view.text_column = state.text_column;
        view.local_offset = state.local_offset;
    }

    /*
    Position restoration keeps a valid saved viewport.
    A new view centers its requested byte and clamps the final page.
    */
    let rows = console.height().saturating_sub(2);
    if saved.is_some() {
        restore_paged_position(&mut view, source.len(), rows);
    } else {
        paged_goto(&mut view, initial, source.len(), rows);
    }

    loop {
        /*
        Each frame validates descriptor and pathname identity before reading visible windows.
        The console publishes only complete rows from the validated source.
        */
        let lines = match source.validate().and_then(|()| {
            paged_frame(
                &view,
                &path,
                &source,
                console,
                editor::cp437(config.hex_delimiter),
            )
        }) {
            Ok(lines) => lines,
            Err(error) if source.editing() => {
                paged_edit_error(console, &mut source, &mut view, &error)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        console.draw(&lines)?;
        let key = console.key()?;

        /*
        The classifier accepts unmodified Hex characters and leaves Shift available for uppercase digits.
        A real non-Hex key closes the pending group before command dispatch.
        Resize events have code zero, so a resize cannot split a two-nibble group.
        */
        let hex_digit =
            source.editing() && key.control & 15 == 0 && key.character.is_ascii_hexdigit();
        if source.editing() && !hex_digit && key.code != 0 {
            source.end_hex_group();
            view.hex_start = None;
        }
        let ctrl = key.control & 12 != 0;

        /*
        Active edits keep source ownership during quit, switch, picker, and tool commands.
        Escape is the only command in this group that discards all in-memory changes.
        */
        if source.editing() && key.code == 27 {
            cancel_paged_edit(&mut source, &mut view, console.height().saturating_sub(2));
            continue;
        }
        if source.editing()
            && ((ctrl && matches!(key.code, 81 | 122 | 123))
                || key.code == 121
                || key.is_alt(b'O')
                || key.is_alt(b'P')
                || key.is_alt(b'N'))
        {
            console.modal(
                &lines,
                "Use Alt+S to save. Press Escape in the editor to cancel edits.",
            )?;
            continue;
        }
        if source.editing() && ctrl && key.code == 84 {
            console.modal(
                &lines,
                "Tools are unavailable. Use Alt+S to save. Press Escape in the editor to cancel.",
            )?;
            continue;
        }

        /*
        Ctrl+S publishes the logical layout to a new native path in either view mode.
        Failed or canceled Save As keeps the original source, path, edits, history, and cursor.
        */
        if ctrl && key.code == 83 {
            if let Some(name) = console.prompt(&lines, "Save As (new file)")? {
                let destination = PathBuf::from(name.trim().trim_matches('"'));
                let result = std::path::absolute(&destination)
                    .map_err(save::PagedSaveError::Retained)
                    .and_then(|destination| save::save_as_paged(&destination, &source));
                match result {
                    Ok(result) => {
                        source = result.source;
                        path = result.path;
                        let _backup = result.backup;
                        view.low_nibble = false;
                        view.hex_start = None;
                        restore_paged_position(
                            &mut view,
                            source.len(),
                            console.height().saturating_sub(2),
                        );
                        if *session_publish
                            && let Err(error) = config::SavedState::saved_path(&path)
                        {
                            disable_session(console, &error)?;
                            *session_publish = false;
                        }
                        if let Some(warning) = result.warning {
                            console.modal(&lines, &warning)?;
                        }
                    }
                    Err(save::PagedSaveError::Retained(error))
                    | Err(save::PagedSaveError::PublishedSaveAs(error)) => {
                        console.modal(&lines, &error.to_string())?;
                    }
                    Err(save::PagedSaveError::PublishedReplacement(error)) => {
                        console.modal(&lines, &error.to_string())?;
                        return Ok(close_unusable_paged_view(session_publish));
                    }
                }
            }
            continue;
        }

        /*
        Alt+S and legacy macro F9 replace the active paged file only during editing.
        Successful publication adopts a fresh descriptor and clears edit history through that new owner.
        */
        if source.editing() && (key.is_alt(b'S') || key.code == 120) {
            match save::replace_paged(&path, &source) {
                Ok(result) => {
                    source = result.source;
                    path = result.path;
                    let _backup = result.backup;
                    view.low_nibble = false;
                    view.hex_start = None;
                    restore_paged_position(
                        &mut view,
                        source.len(),
                        console.height().saturating_sub(2),
                    );
                    if let Some(warning) = result.warning {
                        console.modal(&lines, &warning)?;
                    }
                }
                Err(save::PagedSaveError::Retained(error))
                | Err(save::PagedSaveError::PublishedSaveAs(error)) => {
                    console.modal(&lines, &error.to_string())?;
                }
                Err(save::PagedSaveError::PublishedReplacement(error)) => {
                    console.modal(&lines, &error.to_string())?;
                    return Ok(close_unusable_paged_view(session_publish));
                }
            }
            continue;
        }

        /*
        Normal-mode quit and switch commands return the native path and display state.
        The outer lifecycle stores that bounded state before it opens another source.
        */
        if (ctrl && key.code == 81) || matches!(key.code, 27 | 121) {
            return Ok((EditorAction::Quit, Some(PagedClosed { path, view })));
        }
        if (ctrl && key.code == 123) || key.is_alt(b'N') {
            return Ok((EditorAction::Next, Some(PagedClosed { path, view })));
        }
        if (ctrl && key.code == 122) || key.is_alt(b'P') {
            return Ok((EditorAction::Previous, Some(PagedClosed { path, view })));
        }
        if key.is_alt(b'S') {
            console.modal(&lines, "There are no in-memory edits to save.")?;
            continue;
        }
        if ctrl && key.code == 84 {
            console.modal(
                &lines,
                "Analysis tools are unavailable for the bounded Hex view.",
            )?;
            continue;
        }

        /*
        The navigation map accepts terminal keys and lowercase movement alternatives.
        The bounded helper applies all movement without reading more source data.
        */
        let navigation = match key.code {
            37 => Some(Key::Left),
            39 => Some(Key::Right),
            38 => Some(Key::Up),
            40 => Some(Key::Down),
            36 => Some(if ctrl { Key::FileStart } else { Key::Home }),
            35 => Some(if ctrl { Key::FileEnd } else { Key::End }),
            33 => Some(Key::PageUp),
            34 => Some(Key::PageDown),
            _ if key.accepts_text() && !source.editing() => {
                match key.character.to_ascii_lowercase() {
                    'h' => Some(Key::Left),
                    'l' => Some(Key::Right),
                    'k' => Some(Key::Up),
                    'j' => Some(Key::Down),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(key) = navigation {
            let rows = console.height().saturating_sub(2);
            if source.editing() {
                paged_edit_navigate(&mut view, key, source.len(), rows);
            } else {
                paged_navigate(&mut view, key, source.len(), rows);
            }
            continue;
        }

        /*
        A hexadecimal character changes one selected nibble through the paged transaction path.
        Errors keep the source owner, logical spans, history, and last accepted cursor.
        */
        if hex_digit {
            if let Err(error) = paged_hex_digit(&mut source, &mut view, key.character) {
                paged_edit_error(console, &mut source, &mut view, &error)?;
            }
            continue;
        }

        /*
        Alt shortcuts manage help, edit entry, Goto, and the picker.
        Ctrl+Z and Ctrl+Y manage edit history.
        Legacy macro function-key records keep their historical contextual actions.
        Unsupported operations leave the paged source and display state unchanged.
        */
        match key.code {
            /*
            Help reports controls for the current mode and explains the in-memory edit limit.
            The modal does not change the source, history, or selected position.
            */
            code if key.is_alt(b'H') || code == 112 => {
                console.modal(
                    &lines,
                    if source.editing() {
                        "Alt+S saves. Ctrl+S saves as. Ctrl+Z undoes. Ctrl+Y redoes. Escape cancels."
                    } else {
                        "Paged Hex uses Alt+E Edit, Alt+G Goto, Alt+O Files, Alt+P/N Switch, and Ctrl+Q Quit."
                    },
                )?;
            }
            /*
            Redo and undo request one alternate logical layout from PagedFile.
            A successful result restores the matching u64 cursor, viewport, and nibble state.
            An error keeps every accepted edit state and makes explicit cancellation available.
            */
            code if source.editing()
                && ((code == 114 && key.control & 16 != 0)
                    || (code == 89 && key.control & 12 != 0)) =>
            {
                match source.redo() {
                    Ok(Some(cursor)) => view.restore_edit_cursor(
                        cursor,
                        source.len(),
                        console.height().saturating_sub(2),
                    ),
                    Ok(None) => {
                        console.modal(&lines, "The redo history is empty.")?;
                    }
                    Err(error) => {
                        paged_edit_error(console, &mut source, &mut view, &error)?;
                    }
                }
            }
            code if source.editing()
                && ((code == 114 && key.control & 16 == 0)
                    || (code == 90 && key.control & 12 != 0)) =>
            {
                match source.undo() {
                    Ok(Some(cursor)) => view.restore_edit_cursor(
                        cursor,
                        source.len(),
                        console.height().saturating_sub(2),
                    ),
                    Ok(None) => {
                        console.modal(&lines, "The undo history is empty.")?;
                    }
                    Err(error) => {
                        paged_edit_error(console, &mut source, &mut view, &error)?;
                    }
                }
            }
            /*
            Alt+E enters edit mode directly when no edit session exists.
            Source validation must pass before the new session accepts Hex input.
            Legacy macro F3 records use the same contextual entry action.
            */
            code if !source.editing() && (key.is_alt(b'E') || code == 114) => {
                match source.begin_edit() {
                    Ok(()) => {
                        view.low_nibble = false;
                        view.hex_start = None;
                    }
                    Err(error) => {
                        console.modal(&lines, &error.to_string())?;
                    }
                }
            }
            /*
            Goto parses one full u64 file offset and keeps the target inside logical bytes.
            The helper clears an interrupted nibble group before the next Hex input.
            */
            code if key.is_alt(b'G') || code == 116 => {
                if let Some(value) = console.prompt(&lines, "Goto file offset")? {
                    match cli::parse_number(value.as_bytes()) {
                        Ok((offset, _)) if offset < source.len() => {
                            paged_goto(
                                &mut view,
                                offset,
                                source.len(),
                                console.height().saturating_sub(2),
                            );
                        }
                        _ => {
                            console.modal(&lines, "Jump out of file")?;
                        }
                    }
                }
            }
            /*
            Alt+O selects another native path through the existing picker in normal mode.
            Legacy macro F9 records keep the same picker action.
            Other mapped Alt actions report the bounded-view limit without changing state.
            */
            code if key.is_alt(b'O') || code == 120 => {
                if let Some(next) =
                    select_file(console, path.parent().unwrap_or(Path::new(".")).to_owned())?
                {
                    return Ok((EditorAction::Pick(next), Some(PagedClosed { path, view })));
                }
            }
            code if (113..=119).contains(&code)
                || b"WAMLFRB".iter().copied().any(|letter| key.is_alt(letter)) =>
            {
                console.modal(
                    &lines,
                    if source.editing() {
                        "Command unavailable. Memory edits remain. Press Escape in the editor to cancel."
                    } else {
                        "This operation is unavailable for the bounded Hex view."
                    },
                )?;
            }
            _ => {}
        }
    }
}

/*
EditorAction tells the outer lifecycle whether to quit, switch, or open a picked native path.
The active view returns its state separately from this control result.
*/
enum EditorAction {
    Quit,
    Next,
    Previous,
    Pick(PathBuf),
}

/*
This function runs the established buffered Editor from bytes selected by the source lifecycle.
It returns the current native path and Editor state after quit or file selection.
*/
fn open_editor(
    console: &Console,
    mut path: PathBuf,
    source: (Vec<u8>, File),
    options: &cli::Options,
    config: &config::Config,
    saved_view: Option<&RuntimeView>,
    session_publish: &mut bool,
) -> io::Result<(EditorAction, Option<(PathBuf, Editor)>)> {
    /*
    The lifecycle supplies bytes from the descriptor that selected buffered storage.
    The view retains that descriptor as the accepted identity for replacement Save.
    This view preserves all established small-file behavior after that bounded open.
    */
    let (data, mut file) = source;
    /*
    Startup mode and offset use CLI choices before format conversion and configuration defaults.
    Invalid format offsets produce a notice and select file offset zero.
    */
    let mode = saved_view
        .map(|state| state.mode)
        .unwrap_or_else(|| startup_mode(options, config));
    let requested = options
        .offset
        .as_ref()
        .map(|offset| match offset.target {
            cli::OffsetTarget::File(value) => Ok(value),
            cli::OffsetTarget::Virtual(value) => format::virtual_to_file(&data, value),
            cli::OffsetTarget::End => Ok((data.len() as u64).wrapping_sub(1)),
            cli::OffsetTarget::EntryPoint => format::entry_point(&data),
        })
        .transpose();
    let mut initial = match requested {
        Ok(value) => value.unwrap_or(0),
        Err(error) => {
            console.modal(&[], &error)?;
            0
        }
    };
    if options.offset.is_some() && initial >= data.len() as u64 {
        console.modal(&[], "Jump out of file")?;
        initial = 0;
    }

    /*
    The Editor owns buffered bytes and a saved comparison copy.
    A runtime record restores only view metadata and validates its local-offset capability.
    */
    let mut saved = data.clone();
    let mut view = new_view(data, mode, initial, config).map_err(io::Error::other)?;
    if mode == Mode::Hex {
        view.goto(initial, console.height().saturating_sub(2));
    }
    if mode == Mode::Code {
        view.top = initial;
    }
    if let Some(state) = saved_view {
        if !state.local_offset {
            return Err(io::Error::other(
                "Saved global offset display is not reconstructed.",
            ));
        }
        view.mode = state.mode;
        view.offset = state.offset.min(view.data.len() as u64);
        view.top = state.top.min(view.data.len() as u64);
        view.code_bits = state.code_bits;
        view.real_mode = state.real_mode;
        view.wrap = state.wrap;
        view.expand_tabs = state.tab;
        view.text_column = state.text_column;
        view.delimiter = match state.line_feed {
            config::LineFeed::Cr => b"\r",
            config::LineFeed::Lf => b"\n",
            _ => b"\r\n",
        };
    }

    /*
    These values hold current navigation, search, and save state.
    Return history is bounded, while step history follows the current Code traversal.
    Save flags track disk state independently from view navigation.
    */
    let mut step_history = Vec::new();
    let mut return_history = VecDeque::new();
    let mut search: Option<operations::Pattern> = None;
    let mut updated = false;
    let mut writable = false;
    let mut decoder = None;
    loop {
        /*
        Each iteration derives current metadata, draws one frame, and reads one key.
        Leaving a hexadecimal group finalizes its pending edit before another command.
        */
        let metadata = view.metadata();
        let lines = frame(
            &view,
            &path,
            console,
            updated,
            writable,
            &metadata,
            &mut decoder,
        );
        console.draw(&lines)?;
        let key = console.key()?;
        let hex_digit = view.editing
            && view.mode == Mode::Hex
            && key.accepts_text()
            && key.character.is_ascii_hexdigit();
        if view.editing && !hex_digit && key.code != 0 {
            view.end_hex_group();
        }
        let ctrl = key.control & 12 != 0;

        /*
        Global commands quit, save under a new native path, or enter the workbench.
        Successful Save As renews the source identity before it accepts the new baseline.
        Save As updates session publication only after the native save succeeds.
        */
        if ctrl && key.code == 81 && !view.editing {
            return Ok((EditorAction::Quit, Some((path, view))));
        }
        if ctrl && key.code == 83 {
            if let Some(name) = console.prompt(&lines, "Save As (new file)")? {
                let destination = PathBuf::from(name.trim().trim_matches('"'));
                let result = std::path::absolute(&destination)
                    .and_then(|destination| save::save_as(&destination, &view.data));
                match result {
                    Ok((destination, published)) => {
                        path = destination;
                        file = published;
                        saved.clone_from(&view.data);
                        view.source_changed();
                        view.saved();
                        updated = true;
                        if *session_publish
                            && let Err(error) = config::SavedState::saved_path(&path)
                        {
                            disable_session(console, &error)?;
                            *session_publish = false;
                        }
                    }
                    Err(error) => {
                        let message = if error.kind() == io::ErrorKind::AlreadyExists {
                            format!("The destination already exists. Use a new file name. {error}")
                        } else {
                            error.to_string()
                        };
                        console.modal(&lines, &message)?;
                    }
                }
            }
            continue;
        }
        if ctrl && key.code == 84 {
            if workbench::tools(console, &mut view, &lines)? {
                return_history.clear();
            }
            step_history.clear();
            continue;
        }
        if key.is_alt(b'H') || key.code == 112 {
            workbench::help(console)?;
            continue;
        }

        /*
        Mapped repeat-search and file-switch commands run before ordinary navigation.
        Stored macro function-key records keep the corresponding legacy action.
        File switches return the complete active Editor for bounded runtime-state conversion.
        */
        let next_match = key.is_alt(b'R') || (key.code == 118 && !ctrl && key.control & 16 != 0);
        let previous_match = key.is_alt(b'B') || (key.code == 118 && ctrl);
        if !view.editing && (next_match || previous_match) {
            let start = if previous_match {
                (view.offset as usize).checked_sub(1)
            } else {
                (view.offset as usize).checked_add(1)
            };
            match search.as_ref() {
                Some(pattern) => {
                    match start.and_then(|start| pattern.find(&view.data, start, previous_match)) {
                        Some(offset) => {
                            workbench::jump(&mut view, offset, console.height().saturating_sub(2));
                            step_history.clear();
                        }
                        None => {
                            console.modal(&lines, "Not found")?;
                        }
                    }
                }
                None => {
                    console.modal(&lines, "Press Alt+F to enter a search pattern first.")?;
                }
            }
            continue;
        }
        if !view.editing {
            if (ctrl && key.code == 123) || key.is_alt(b'N') {
                return Ok((EditorAction::Next, Some((path, view))));
            }
            if (ctrl && key.code == 122) || key.is_alt(b'P') {
                return Ok((EditorAction::Previous, Some((path, view))));
            }
        }

        /*
        The navigation map sends Code movement through decoded instruction boundaries.
        Text and Hex movement use the established Editor navigation rules.
        */
        let navigation = match key.code {
            37 => Some(Key::Left),
            39 => Some(Key::Right),
            38 => Some(Key::Up),
            40 => Some(Key::Down),
            36 => Some(if ctrl { Key::FileStart } else { Key::Home }),
            35 => Some(if ctrl { Key::FileEnd } else { Key::End }),
            33 => Some(Key::PageUp),
            34 => Some(Key::PageDown),
            _ if key.accepts_text() && !view.editing => match key.character.to_ascii_lowercase() {
                'h' => Some(Key::Left),
                'l' => Some(Key::Right),
                'k' => Some(Key::Up),
                'j' => Some(Key::Down),
                _ => None,
            },
            _ => None,
        };
        if let Some(key) = navigation {
            /*
            Code movement advances through decoded instruction sizes and stores its reverse steps.
            Other modes delegate viewport correction to the Editor.
            */
            if view.mode == Mode::Code {
                let count = if matches!(key, Key::PageDown | Key::PageUp) {
                    console.height().saturating_sub(2)
                } else {
                    1
                };
                match key {
                    Key::Down | Key::Right | Key::PageDown => {
                        for _ in 0..count {
                            match decode_at(&view, view.offset, &metadata, &mut decoder) {
                                Ok((_address, instruction)) => {
                                    step_history.push(view.offset);
                                    view.offset = (view.offset + instruction.size as u64)
                                        .min(view.data.len() as u64);
                                    view.top = view.offset;
                                }
                                Err(error) => {
                                    console.modal(&lines, &error)?;
                                    break;
                                }
                            }
                        }
                    }
                    Key::Up | Key::Left | Key::PageUp => {
                        for _ in 0..count {
                            if let Some(offset) = step_history.pop() {
                                view.offset = offset;
                                view.top = offset;
                            }
                        }
                    }
                    Key::Home | Key::FileStart => {
                        view.offset = 0;
                        view.top = 0;
                        step_history.clear();
                    }
                    _ => {
                        console.modal(
                            &lines,
                            "This code-navigation operation is not reconstructed.",
                        )?;
                    }
                }
            } else {
                view.navigate(
                    key,
                    console.height().saturating_sub(2),
                    console.width().saturating_sub(1),
                );
            }
            continue;
        }

        /*
        Active Hex editing consumes a valid plain or Shift hexadecimal digit before shortcut dispatch.
        The remaining dispatch handles edit, search, mode, save, and analysis commands.
        */
        if hex_digit {
            if let Err(error) = view.hex_digit(key.character) {
                console.modal(&lines, &error)?;
            }
            continue;
        }
        match key.code {
            /*
            Enter follows one direct Code target and stores the current return position.
            Backspace restores the newest valid return position.
            */
            13 if !view.editing && view.mode == Mode::Code => {
                match direct_target_offset(&view, &metadata, &mut decoder) {
                    Ok(target) => {
                        if target != view.offset {
                            remember_return(&mut return_history, (view.offset, view.top));
                            view.offset = target;
                            view.top = target;
                            step_history.clear();
                        }
                    }
                    Err(error) => {
                        console.modal(&lines, &error)?;
                    }
                }
            }
            8 if !view.editing && view.mode == Mode::Code => {
                match take_return(&mut return_history, &view.data) {
                    Ok(Some((offset, top))) => {
                        view.offset = offset;
                        view.top = top;
                        step_history.clear();
                    }
                    Ok(None) => {
                        console.modal(&lines, "The branch return history is empty.")?;
                    }
                    Err(error) => {
                        console.modal(&lines, &error)?;
                    }
                }
            }
            /*
            Code editing prepares assembly bytes, validates their range, and builds a preview.
            Confirmed bytes enter one Editor replacement transaction.
            */
            code if view.editing
                && view.mode == Mode::Code
                && (code == 13 || code == 113 || key.is_alt(b'A')) =>
            {
                loop {
                    let metadata = view.metadata();
                    let lines = frame(
                        &view,
                        &path,
                        console,
                        updated,
                        writable,
                        &metadata,
                        &mut decoder,
                    );
                    let seed = assembly_seed(&view, &metadata).unwrap_or_default();
                    let Some(text) = console.prompt_seed(&lines, "Assembler", &seed)? else {
                        break;
                    };
                    let proposed = (|| {
                        let metadata = metadata.as_ref().map_err(Clone::clone)?;
                        let address = metadata.code_address(view.offset)?.0;
                        let architecture = metadata.decoder_architecture(view.code_bits)?;
                        let bytes = assembler::assemble_architecture(&text, architecture, address)?;
                        let start = usize::try_from(view.offset)
                            .map_err(|_| "The offset exceeds the address range.")?;
                        let end = start
                            .checked_add(bytes.len())
                            .ok_or("The instruction exceeds the address range.")?;
                        view.validate_raw_len(view.data.len().max(end))?;
                        let preview = assembly_preview(&view, metadata, &mut decoder, &bytes)?;
                        Ok::<_, String>((bytes, start, end, preview))
                    })();
                    match proposed {
                        Ok((bytes, start, end, preview)) => {
                            if !confirm_assembly(console, &preview)? {
                                break;
                            }
                            if let Err(error) =
                                view.replace_bytes(start, bytes, (end as u64, view.top))
                            {
                                console.modal(&lines, &error)?;
                                continue;
                            }
                        }
                        Err(error) => {
                            console.modal(&lines, &error)?;
                        }
                    }
                }
            }
            /*
            These edit-state commands cancel, quit, undo, redo, or enter editing.
            History failures produce notices and preserve current bytes.
            Legacy macro F3 records retain their historical contextual Undo and edit-entry actions.
            */
            27 if view.editing => view.cancel_edit(),
            27 | 121 if !view.editing => break,
            code if view.editing
                && ((code == 114 && key.control & 16 != 0)
                    || (code == 89 && key.control & 12 != 0)) =>
            {
                match view.redo() {
                    Ok(true) => {}
                    Ok(false) => {
                        console.modal(&lines, "The redo history is empty.")?;
                    }
                    Err(error) => {
                        console.modal(&lines, &error)?;
                    }
                }
            }
            code if view.editing
                && ((code == 114 && key.control & 16 == 0)
                    || (code == 90 && key.control & 12 != 0)) =>
            {
                match view.undo() {
                    Ok(true) => {}
                    Ok(false) => {
                        console.modal(&lines, "The undo history is empty.")?;
                    }
                    Err(error) => {
                        console.modal(&lines, &error)?;
                    }
                }
            }
            code if !view.editing && (key.is_alt(b'E') || code == 114) => {
                if let Err(error) = view.toggle_edit() {
                    console.modal(&lines, &error)?;
                } else {
                    writable = true;
                }
            }
            /*
            Alt+S publishes buffered edits through the guarded replacement path.
            Legacy macro F9 records keep the same save action.
            A successful save resets the saved comparison bytes and dirty state.
            The prepared descriptor becomes the accepted identity for the next Save.
            */
            code if view.editing && (key.is_alt(b'S') || code == 120) => {
                match save::replace(&path, &file, &saved, &view.data) {
                    Ok((_, published)) => {
                        file = published;
                        saved.clone_from(&view.data);
                        view.saved();
                        updated = true;
                    }
                    Err(error) => {
                        console.modal(&lines, &error.to_string())?;
                    }
                }
            }
            /*
            Mode selection rebuilds Text or Hex views and retains shared Code settings.
            The Code-width command resets decoder and navigation caches after a change.
            */
            code if !view.editing
                && (code == 115
                    || code == 13
                    || key.is_alt(b'M')
                    || (key.accepts_text() && key.character.eq_ignore_ascii_case(&'m'))) =>
            {
                if let Some(mode) = console.prompt(&lines, "Mode: T Text, H Hex, C Code")? {
                    match mode.to_ascii_uppercase().as_str() {
                        "T" | "1" => {
                            let raw_model = view.raw_model;
                            let code_bits = view.code_bits;
                            let real_mode = view.real_mode;
                            view = new_view(view.data, Mode::Text, view.offset, config)
                                .map_err(io::Error::other)?;
                            view.code_bits = code_bits;
                            view.real_mode = real_mode;
                            view.set_raw_model(raw_model).map_err(io::Error::other)?;
                        }
                        "H" | "2" => {
                            let raw_model = view.raw_model;
                            let code_bits = view.code_bits;
                            let real_mode = view.real_mode;
                            view = new_view(view.data, Mode::Hex, view.offset, config)
                                .map_err(io::Error::other)?;
                            view.code_bits = code_bits;
                            view.real_mode = real_mode;
                            view.set_raw_model(raw_model).map_err(io::Error::other)?;
                            view.goto(view.offset, console.height().saturating_sub(2));
                        }
                        "C" | "3" => {
                            view.mode = Mode::Code;
                            view.top = view.offset;
                            step_history.clear();
                        }
                        _ => {}
                    }
                }
            }
            _ if !view.editing
                && view.mode == Mode::Code
                && key.accepts_text()
                && key.character.eq_ignore_ascii_case(&'o') =>
            {
                match cycle_code_mode(&mut view) {
                    Ok(()) => {
                        decoder = None;
                        step_history.clear();
                        return_history.clear();
                    }
                    Err(error) => {
                        console.modal(&lines, &error)?;
                    }
                }
            }
            /*
            Goto parses one bounded file position.
            Search stores one valid pattern and moves to its first matching byte.
            */
            code if !view.editing && (key.is_alt(b'G') || code == 116) => {
                if let Some(value) = console.prompt(&lines, "Goto")? {
                    match cli::parse_number(value.as_bytes()) {
                        Ok((offset, _)) if offset < view.data.len() as u64 => {
                            view.goto(offset, console.height().saturating_sub(2));
                            if view.mode == Mode::Code {
                                view.top = offset;
                                step_history.clear();
                            }
                        }
                        _ => {
                            console.modal(&lines, "Jump out of file")?;
                        }
                    }
                }
            }
            code if !view.editing && (key.is_alt(b'F') || code == 118) => {
                if let Some(value) = console.prompt(
                    &lines,
                    if view.mode == Mode::Hex {
                        "Hex"
                    } else {
                        "ASCII"
                    },
                )? {
                    let pattern = if view.mode == Mode::Hex {
                        operations::parse_pattern(&value)
                    } else {
                        operations::Pattern::exact(value.into_bytes())
                    };
                    match pattern {
                        Ok(pattern) => {
                            let found = pattern.find(&view.data, view.offset as usize, false);
                            search = Some(pattern);
                            match found {
                                Some(offset) => {
                                    workbench::jump(
                                        &mut view,
                                        offset,
                                        console.height().saturating_sub(2),
                                    );
                                    step_history.clear();
                                }
                                None => {
                                    console.macro_notice();
                                    console.modal(&lines, "Not found")?;
                                }
                            }
                        }
                        Err(error) => {
                            console.modal(&lines, &error)?;
                        }
                    }
                }
            }
            /*
            Remaining mapped commands update display settings or return another native path.
            Legacy macro function-key records keep the corresponding contextual action.
            Other legacy function-key records report the existing reconstruction limit.
            */
            code if view.mode == Mode::Text && (key.is_alt(b'W') || code == 113) => {
                view.wrap = !view.wrap;
            }
            code if view.mode == Mode::Text && (key.is_alt(b'L') || code == 117) => {
                console.modal(&lines, "Alternate line-feed handling is not reconstructed.")?;
            }
            code if !view.editing && (key.is_alt(b'O') || code == 120) => {
                if let Some(next) =
                    select_file(console, path.parent().unwrap_or(Path::new(".")).to_owned())?
                {
                    return Ok((EditorAction::Pick(next), Some((path, view))));
                }
            }
            112..=123 => {
                console.modal(&lines, "This operation is not reconstructed.")?;
            }
            _ => {}
        }
    }
    Ok((EditorAction::Quit, Some((path, view))))
}

/*
This notice disables only session publication for the current application run.
The native file operation and the current in-memory editor state remain available.
Existing SAV bytes stay unchanged because the final publisher checks this state.
*/
fn disable_session(console: &Console, error: &str) -> io::Result<()> {
    console.modal(&[], &format!("Session disabled. {error}"))?;
    Ok(())
}

/*
This application lifecycle parses inputs, loads configuration and session state, then opens each selected source.
It publishes session bytes only after all native view operations finish.
*/
fn run() -> io::Result<()> {
    /*
    The startup section handles the native self-test before normal UTF-8 CLI parsing.
    Interactive operation then requires a terminal and creates the shared Console.
    */
    let raw_args: Vec<_> = std::env::args_os().skip(1).collect();
    if raw_args == [std::ffi::OsString::from("--self-test")] {
        /*
        These vectors assemble and decode x86, ARM, and Thumb through the bundled engines.
        Each comparison uses independent expected bytes for the selected architecture.
        */
        for (architecture, text, bytes) in [
            (format::Architecture::X86(16), "ret", &[0xc3][..]),
            (format::Architecture::X86(32), "nop", &[0x90][..]),
            (
                format::Architecture::X86(64),
                "mov rax,rbx",
                &[0x48, 0x89, 0xd8][..],
            ),
            (
                format::Architecture::Arm,
                "mov r0, r0",
                &[0x00, 0x00, 0xa0, 0xe1][..],
            ),
            (
                format::Architecture::Thumb,
                "movs r0, #1",
                &[0x01, 0x20][..],
            ),
        ] {
            let output = assembler::assemble_architecture(text, architecture, 0x1000)
                .map_err(io::Error::other)?;
            let instruction = match architecture {
                format::Architecture::X86(bits) => {
                    decoder::decode(bytes, 0, bits, 0x1000).map_err(io::Error::other)?
                }
                _ => {
                    decoder::Decoder::with_architecture(architecture, decoder::Syntax::Intel, false)
                        .and_then(|decoder| decoder.decode(bytes, 0, 0x1000))
                        .map_err(io::Error::other)?
                }
            };
            if output != bytes || instruction.size != bytes.len() {
                return Err(io::Error::other("The native instruction check failed."));
            }
        }
        /*
        ARM64 decoding uses the same native library without an assembler request.
        ARM64 assembly remains an explicit unsupported capability.
        */
        let arm64 = decoder::Decoder::with_architecture(
            format::Architecture::Arm64,
            decoder::Syntax::Intel,
            false,
        )
        .map_err(io::Error::other)?;
        let instruction = arm64
            .decode(&[0x1f, 0x20, 0x03, 0xd5], 0, 0x1000)
            .map_err(io::Error::other)?;
        if instruction.size != 4 {
            return Err(io::Error::other("The native instruction check failed."));
        }
        println!("Native self-test passed.");
        return Ok(());
    }
    let args: Vec<String> = raw_args
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| io::Error::other("A command argument is not valid UTF-8."))
        })
        .collect::<io::Result<_>>()?;
    let options = cli::parse(&args).map_err(|error| io::Error::other(error.to_string()))?;
    if options.help {
        println!("{}", cli::USAGE);
        return Ok(());
    }
    if console::redirected() {
        return Err(io::Error::other(
            "HView-Linux needs an interactive terminal.",
        ));
    }
    let console = Console::new()?;

    /*
    Configuration discovery checks the explicit file, portable sibling, and XDG locations in order.
    The selected settings define later view and session defaults.
    */
    let executable = std::env::current_exe()?;
    let portable = std::env::var_os("HVIEW_PORTABLE").as_deref() == Some(std::ffi::OsStr::new("1"));
    let ini = options.ini_file.as_ref().map(PathBuf::from).or_else(|| {
        config::configuration_paths(
            &executable,
            portable,
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )
        .into_iter()
        .find(|path| path.is_file())
    });
    let config = if let Some(path) = ini {
        config::load(&path).map_err(io::Error::other)?
    } else {
        config::Config::default()
    };
    let save_path = options
        .save_file
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&config.savefile));
    /*
    Session input remains separate from the permission to publish changed session bytes.
    A later path representation failure can disable publication without losing loaded state.
    The session reader retains the exact descriptor that supplies its accepted bytes.
    */
    let session_requested = config.savefile_at_exit || options.save_file.is_some();
    let saved_source = if session_requested {
        match File::open(&save_path).and_then(|mut file| {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok((bytes, file))
        }) {
            Ok(source) => Some(source),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let mut saved_state = if options.file_masks.is_empty()
        && session_requested
        && let Some((bytes, _)) = &saved_source
    {
        Some(config::parse_saved(bytes).map_err(io::Error::other)?)
    } else {
        None
    };

    /*
    Macro parsing and path selection occur before any source opens.
    Restored paths must identify existing Linux files without Windows or relative reinterpretation.
    */
    let mut playback = options
        .macro_file
        .as_ref()
        .map(|path| {
            fs::read(path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| macros::Playback::parse(&bytes))
        })
        .transpose()
        .map_err(io::Error::other)?;
    let mut paths = if let Some(state) = &saved_state {
        state
            .files
            .iter()
            .map(|file| {
                let path = restored_path(&file.path).map_err(io::Error::other)?;
                if !path.is_file() {
                    return Err(io::Error::other(format!(
                        "The saved file does not exist on Linux: {}",
                        display_path(path.as_os_str())
                    )));
                }
                Ok(path)
            })
            .collect::<io::Result<Vec<_>>>()?
    } else if options.file_masks.is_empty() {
        match select_file(&console, std::env::current_dir()?)? {
            Some(path) => vec![path],
            None => return Ok(()),
        }
    } else {
        files::expand(&options.file_masks).map_err(io::Error::other)?
    };
    if paths.is_empty() {
        let (width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        if let Some(line) = lines.first_mut() {
            *line = format!(
                "     {}",
                display_path(std::env::current_dir()?.as_os_str())
            );
        }
        let keys = " 1       2       3       4       5       6       7       8       9      10      11      12      ";
        if let Some(footer) = lines.last_mut() {
            *footer = format!(
                "{keys}{}",
                "▒".repeat(width.saturating_sub(keys.chars().count()))
            );
        }
        console.modal(&lines, "Couldn't open file")?;
        return Ok(());
    }
    /*
    Runtime records restore each visited file without keeping inactive file contents.
    Existing SAV records initialize the same bounded metadata before the first open.
    */
    let mut runtime_views = if let Some(state) = &saved_state {
        state
            .files
            .iter()
            .map(RuntimeView::from_saved)
            .map(Some)
            .collect()
    } else {
        vec![None; paths.len()]
    };
    /*
    Validate new session capacity and paths before any SAV mutation.
    A representation limit disables publication but does not block the native open.
    */
    let mut session_publish = session_requested;
    if session_publish && paths.len() > 24 {
        disable_session(&console, "A save state supports no more than 24 files.")?;
        session_publish = false;
    }
    if session_publish && saved_state.is_none() {
        for path in &paths {
            if let Err(error) = config::SavedState::saved_path(path) {
                disable_session(&console, &error)?;
                session_publish = false;
                break;
            }
        }
    }

    let mut index = saved_state.as_ref().map_or(0, |state| state.active_index);
    if let Some(playback) = playback.take() {
        console.start_macro(playback);
    }
    loop {
        /*
        One opened descriptor selects buffered or paged storage for the active path.
        The selected view returns native path state and content-free session metadata.
        */
        let Some(source) = open_source(&console, &paths[index])? else {
            break;
        };
        let saved_view = runtime_views.get(index).and_then(Option::as_ref);
        let (action, closed) = match source {
            paged::OpenedSource::Buffered { data, file, .. } => {
                let (action, view) = open_editor(
                    &console,
                    paths[index].clone(),
                    (data, file),
                    &options,
                    &config,
                    saved_view,
                    &mut session_publish,
                )?;
                (
                    action,
                    view.map(|(path, view)| ClosedView::Buffered(path, view)),
                )
            }
            paged::OpenedSource::Paged(source) => {
                let (action, closed) = open_paged_editor(
                    &console,
                    paths[index].clone(),
                    source,
                    &options,
                    &config,
                    saved_view,
                    &mut session_publish,
                )?;
                (action, closed.map(ClosedView::Paged))
            }
        };

        /*
        Session conversion occurs after the native view closes.
        A failed conversion keeps the path and editor result but disables SAV publication.
        Successful conversion updates only defined fields in the current session record.
        */
        if let Some(closed) = closed {
            let path = match &closed {
                ClosedView::Buffered(path, _) => path,
                ClosedView::Paged(closed) => &closed.path,
            };
            paths[index] = path.clone();
            let local_offset = runtime_views
                .get(index)
                .and_then(Option::as_ref)
                .map_or(config.show_offset_local, |view| view.local_offset);
            let runtime_view = match &closed {
                ClosedView::Buffered(_, view) => {
                    RuntimeView::from_editor(view, local_offset).map_err(io::Error::other)?
                }
                ClosedView::Paged(closed) => closed.runtime_view(),
            };
            runtime_views[index] = Some(runtime_view.clone());

            let saved_path = if session_publish {
                match config::SavedState::saved_path(path) {
                    Ok(path) => Some(path),
                    Err(error) => {
                        disable_session(&console, &error)?;
                        session_publish = false;
                        None
                    }
                }
            } else {
                None
            };
            if let Some(saved_path) = saved_path {
                let session_view = runtime_view.session_view(saved_path.clone());

                if let Some(state) = &mut saved_state {
                    if index == state.files.len() {
                        state
                            .add_session_view(&session_view, &config)
                            .map_err(io::Error::other)?;
                    } else if state.files[index].path != saved_path {
                        state
                            .update_path(index, &saved_path)
                            .map_err(io::Error::other)?;
                    }
                    state
                        .update_session_view(index, &session_view)
                        .map_err(io::Error::other)?;
                } else {
                    saved_state = Some(
                        config::SavedState::new_session_files(
                            &paths,
                            index,
                            &session_view,
                            &config,
                            startup_mode(&options, &config),
                            options.offset.as_ref(),
                        )
                        .map_err(io::Error::other)?,
                    );
                }
            }
        }

        /*
        The action changes only the selected native path index.
        Picker representation limits can disable sessions but cannot block file selection.
        */
        match action {
            EditorAction::Quit => break,
            EditorAction::Next => index = (index + 1) % paths.len(),
            EditorAction::Previous => index = (index + paths.len() - 1) % paths.len(),
            EditorAction::Pick(path) => {
                let canonical = path.canonicalize().ok();
                if let Some(found) = paths.iter().position(|p| {
                    *p == path
                        || canonical
                            .as_ref()
                            .is_some_and(|target| p.canonicalize().ok().as_ref() == Some(target))
                }) {
                    index = found;
                } else {
                    if session_publish && paths.len() >= 24 {
                        disable_session(&console, "A save state supports no more than 24 files.")?;
                        session_publish = false;
                    }
                    if session_publish && let Err(error) = config::SavedState::saved_path(&path) {
                        disable_session(&console, &error)?;
                        session_publish = false;
                    }
                    paths.push(path);
                    runtime_views.push(None);
                    index = paths.len() - 1;
                }
            }
        }
    }
    /*
    Publish SAV bytes only when all current paths have a supported representation.
    Disabled publication leaves the original bytes unchanged on disk.
    Replacement requires the retained session descriptor before staging any updated bytes.
    */
    if session_publish && let Some(state) = saved_state {
        let bytes = config::encode_saved(&state.payload).map_err(io::Error::other)?;
        if let Some((before, file)) = saved_source {
            save::replace(&save_path, &file, &before, &bytes)?;
        } else {
            save::save_as(&save_path, &bytes)?;
        }
    }
    Ok(())
}

/*
The process entry point reports one terminal-safe error and returns a failure status.
Successful application exits return without additional output.
*/
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", console::safe_text(&error.to_string()));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    /*
    These unit tests cover bounded navigation, visible-window reads, and display-only path escaping.
    Lifecycle terminal tests cover source switching and session publication.
    */
    use super::*;

    /*
    These writers build small PE and ELF fixtures for connected Code caller tests.
    Each test changes only the machine, mapping, or instruction bytes that it needs.
    */
    fn put_test_word(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_test_dword(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_test_qword(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn pe_code_fixture(plus: bool, machine: u16) -> Vec<u8> {
        let mut data = vec![0; 0x600];
        data[..2].copy_from_slice(b"MZ");
        put_test_dword(&mut data, 60, 128);
        data[128..132].copy_from_slice(b"PE\0\0");
        put_test_word(&mut data, 132, machine);
        put_test_word(&mut data, 134, 1);
        put_test_word(&mut data, 148, if plus { 240 } else { 224 });
        let optional = 152;
        put_test_word(&mut data, optional, if plus { 0x20b } else { 0x10b });
        put_test_dword(&mut data, optional + 16, 0x1000);
        if plus {
            put_test_dword(&mut data, optional + 24, 0x4000_0000);
            put_test_dword(&mut data, optional + 28, 1);
        } else {
            put_test_dword(&mut data, optional + 28, 0x40_0000);
        }
        put_test_dword(&mut data, optional + 32, 0x1000);
        put_test_dword(&mut data, optional + 36, 0x200);
        put_test_dword(&mut data, optional + 56, 0x2000);
        put_test_dword(&mut data, optional + 60, 0x200);
        let section = optional + if plus { 240 } else { 224 };
        put_test_dword(&mut data, section + 8, 0x200);
        put_test_dword(&mut data, section + 12, 0x1000);
        put_test_dword(&mut data, section + 16, 0x200);
        put_test_dword(&mut data, section + 20, 0x200);
        data
    }

    /*
    This fixture creates one mapped ELF image or one ELF relocatable source for Code caller tests.
    Mapped images use exact file bytes from 0x100 through 0x1FF at VA 0x400000.
    */
    fn elf_code_fixture(bits: u32, machine: u16, file_type: u16, entry: u64) -> Vec<u8> {
        let mut data = vec![0; 0x600];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = if bits == 32 { 1 } else { 2 };
        data[5] = 1;
        data[6] = 1;
        put_test_word(&mut data, 16, file_type);
        put_test_word(&mut data, 18, machine);
        put_test_dword(&mut data, 20, 1);
        let header_size = if bits == 32 { 52 } else { 64 };
        let program_size = if bits == 32 { 32 } else { 56 };
        let mapped = file_type != 1;

        /*
        The header section selects class-specific entry and program-table fields.
        Relocatable sources omit the program table and keep only File-domain Code locations.
        */
        if bits == 32 {
            put_test_dword(&mut data, 24, entry as u32);
            put_test_dword(&mut data, 28, if mapped { header_size as u32 } else { 0 });
            put_test_word(&mut data, 40, header_size as u16);
            put_test_word(&mut data, 42, if mapped { program_size as u16 } else { 0 });
            put_test_word(&mut data, 44, u16::from(mapped));
        } else {
            put_test_qword(&mut data, 24, entry);
            put_test_qword(&mut data, 32, if mapped { header_size as u64 } else { 0 });
            put_test_word(&mut data, 52, header_size as u16);
            put_test_word(&mut data, 54, if mapped { program_size as u16 } else { 0 });
            put_test_word(&mut data, 56, u16::from(mapped));
        }

        /*
        The mapped section writes one executable PT_LOAD with a 0x80-byte zero-fill tail.
        Later tests place architecture instructions in the declared file-backed range or a file gap.
        */
        if mapped {
            let at = header_size;
            put_test_dword(&mut data, at, 1);
            if bits == 32 {
                put_test_dword(&mut data, at + 4, 0x100);
                put_test_dword(&mut data, at + 8, 0x400000);
                put_test_dword(&mut data, at + 16, 0x100);
                put_test_dword(&mut data, at + 20, 0x180);
                put_test_dword(&mut data, at + 24, 5);
                put_test_dword(&mut data, at + 28, 0x100);
            } else {
                put_test_dword(&mut data, at + 4, 5);
                put_test_qword(&mut data, at + 8, 0x100);
                put_test_qword(&mut data, at + 16, 0x400000);
                put_test_qword(&mut data, at + 32, 0x100);
                put_test_qword(&mut data, at + 40, 0x180);
                put_test_qword(&mut data, at + 48, 0x100);
            }
        }
        data
    }

    /*
    This test moves a paged cursor across low and high u64 boundaries.
    Every key keeps the cursor inside the source and visible page.
    A valid saved top remains unchanged when the selected byte is visible.
    */
    #[test]
    fn paged_navigation_preserves_u64_positions_and_bounds() {
        let len = u64::from(u32::MAX) + 0x2000;
        let mut view = PagedView {
            offset: 0,
            top: 0,
            low_nibble: false,
            hex_start: None,
            code_bits: 64,
            real_mode: false,
            wrap: false,
            tab: false,
            line_feed: config::LineFeed::Lf,
            text_column: 0,
            local_offset: true,
        };
        paged_goto(&mut view, len - 0x101, len, 20);
        assert!(view.offset > u64::from(u32::MAX));
        assert!(view.offset >= view.top && view.offset < view.top + 20 * 16);
        paged_navigate(&mut view, Key::FileEnd, len, 20);
        assert_eq!(view.offset, len - 1);
        paged_navigate(&mut view, Key::Right, len, 20);
        assert_eq!(view.offset, len - 1);
        paged_navigate(&mut view, Key::FileStart, len, 20);
        assert_eq!((view.offset, view.top), (0, 0));
        paged_navigate(&mut view, Key::Left, len, 20);
        paged_navigate(&mut view, Key::Up, len, 20);
        assert_eq!(view.offset, 0);
        view.offset = 5;
        paged_navigate(&mut view, Key::Up, len, 20);
        assert_eq!(view.offset, 5);

        view.offset = 0x205;
        view.top = 0x200;
        let saved_top = view.top;
        let rows = 20;
        restore_paged_position(&mut view, len, rows);
        assert_eq!(view.top, saved_top);
    }

    /*
    This test drives the paged Hex helper through one grouped byte, undo, redo, and cancellation.
    It also verifies nibble movement and refuses a replacement at logical EOF.
    */
    #[test]
    fn paged_hex_edit_route_preserves_groups_cursors_and_eof() {
        use std::os::unix::fs::FileExt;

        /*
        A small regular source is sufficient because PagedFile itself does not require large-file classification.
        The fixture stays unchanged because all transaction bytes remain in memory.
        */
        let path = std::env::temp_dir().join(format!(
            "hview-paged-edit-route-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all_at(&[0x12, 0x34], 0).unwrap();
        file.sync_all().unwrap();
        drop(file);

        /*
        Two digits share one record and advance from the first high nibble to the next byte.
        The returned cursors restore the initial and final visible states with their matching bytes.
        */
        let mut source = paged::PagedFile::open(&path).unwrap();
        source.begin_edit().unwrap();
        let mut view = PagedView {
            offset: 0,
            top: 0,
            low_nibble: false,
            hex_start: None,
            code_bits: 64,
            real_mode: false,
            wrap: false,
            tab: false,
            line_feed: config::LineFeed::Lf,
            text_column: 0,
            local_offset: true,
        };
        paged_hex_digit(&mut source, &mut view, 'A').unwrap();
        assert_eq!((view.offset, view.low_nibble), (0, true));
        assert_eq!(&*source.read_window(0, 1).unwrap().bytes, &[0xa2]);
        paged_hex_digit(&mut source, &mut view, 'B').unwrap();
        assert_eq!((view.offset, view.low_nibble), (1, false));
        assert_eq!(&*source.read_window(0, 2).unwrap().bytes, &[0xab, 0x34]);

        let undo = source.undo().unwrap().unwrap();
        view.restore_edit_cursor(undo, source.len(), 20);
        assert_eq!((view.offset, view.top, view.low_nibble), (0, 0, false));
        assert_eq!(&*source.read_window(0, 2).unwrap().bytes, &[0x12, 0x34]);
        let redo = source.redo().unwrap().unwrap();
        view.restore_edit_cursor(redo, source.len(), 20);
        assert_eq!((view.offset, view.top, view.low_nibble), (1, 0, false));
        assert_eq!(&*source.read_window(0, 2).unwrap().bytes, &[0xab, 0x34]);

        /*
        Goto after a high nibble must clear the old group and select the destination high nibble.
        Undo then restores the destination cursor and the bytes before that separate operation.
        */
        view.offset = 0;
        view.low_nibble = false;
        paged_hex_digit(&mut source, &mut view, 'A').unwrap();
        source.end_hex_group();
        paged_goto(&mut view, 1, source.len(), 20);
        assert_eq!(
            (view.offset, view.low_nibble, view.hex_start),
            (1, false, None)
        );
        paged_hex_digit(&mut source, &mut view, 'C').unwrap();
        assert_eq!(&*source.read_window(0, 2).unwrap().bytes, &[0xab, 0xc4]);
        let undo = source.undo().unwrap().unwrap();
        view.restore_edit_cursor(undo, source.len(), 20);
        assert_eq!(&*source.read_window(0, 2).unwrap().bytes, &[0xab, 0x34]);

        /*
        Nibble movement follows the buffered editor at the first byte and can select logical EOF.
        EOF input fails before bytes, history, or cursor state change.
        */
        paged_edit_navigate(&mut view, Key::Left, source.len(), 20);
        assert_eq!((view.offset, view.low_nibble), (0, true));
        paged_edit_navigate(&mut view, Key::Right, source.len(), 20);
        paged_edit_navigate(&mut view, Key::Right, source.len(), 20);
        paged_edit_navigate(&mut view, Key::Right, source.len(), 20);
        assert_eq!((view.offset, view.low_nibble), (2, false));
        let before = source.read_window(0, 2).unwrap().bytes;
        assert!(paged_hex_digit(&mut source, &mut view, 'F').is_err());
        assert_eq!(source.read_window(0, 2).unwrap().bytes, before);
        assert_eq!((view.offset, view.low_nibble), (2, false));

        cancel_paged_edit(&mut source, &mut view, 20);
        assert!(!source.editing());
        assert!(!source.has_changes());
        assert_eq!(&*source.read_window(0, 2).unwrap().bytes, &[0x12, 0x34]);
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This sparse source makes a terminal-sized request cross the 64 KiB window boundary.
    The second bounded read must supply the first row after that boundary.
    */
    #[test]
    fn paged_rows_continue_after_one_read_window() {
        use std::os::unix::fs::FileExt;

        let path = std::env::temp_dir().join(format!(
            "hview-paged-rows-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(paged::BUFFERED_FILE_LIMIT + 1).unwrap();
        file.write_all_at(b"NEXT", paged::MAX_READ_BYTES as u64)
            .unwrap();
        file.sync_all().unwrap();
        let source = match paged::open_source(&path).unwrap() {
            paged::OpenedSource::Paged(source) => source,
            paged::OpenedSource::Buffered { .. } => panic!("The sparse source must be paged."),
        };
        let rows = paged_hex_rows(&source, 0, 4097, '-').unwrap();
        assert_eq!(rows.len(), 4097);
        assert!(rows[4096].contains("4E 45 58 54"));
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This test checks display-only escaping for invalid bytes and terminal controls.
    The native OsString remains available to file operations without text conversion.
    */
    #[test]
    fn native_path_display_escapes_invalid_and_control_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let path = std::ffi::OsString::from_vec(b"native-\xff-\x1b.bin".to_vec());
        assert_eq!(display_path(&path), "native-\\xFF-\\u{1B}.bin");
    }

    /*
    This manual benchmark measures buffered Code-frame preparation for raw and PE inputs.
    Warmup and batch medians reduce timing noise without affecting normal tests.
    */
    #[test]
    #[ignore = "Run the redraw preparation benchmark manually."]
    fn d01_redraw_preparation_benchmark() {
        const ROWS: usize = 28;
        const WARMUPS: usize = 5;
        const BATCHES: usize = 10;
        const PREPARATIONS_PER_BATCH: usize = 5;

        /*
        This helper warms the decoder cache and records one preparation time per batch.
        It prints median and percentile evidence for manual review.
        */
        fn measure(label: &str, view: &Editor) {
            let mut decoder = None;
            for _ in 0..WARMUPS {
                let metadata = format::Metadata::parse(std::hint::black_box(&view.data));
                std::hint::black_box(code_rows(
                    std::hint::black_box(view),
                    ROWS,
                    &metadata,
                    &mut decoder,
                ));
            }

            let mut samples = Vec::with_capacity(BATCHES);
            for _ in 0..BATCHES {
                let start = std::time::Instant::now();
                for _ in 0..PREPARATIONS_PER_BATCH {
                    let metadata = format::Metadata::parse(std::hint::black_box(&view.data));
                    std::hint::black_box(code_rows(
                        std::hint::black_box(view),
                        ROWS,
                        &metadata,
                        &mut decoder,
                    ));
                }
                samples.push(start.elapsed().as_nanos() / PREPARATIONS_PER_BATCH as u128);
            }
            samples.sort_unstable();
            let median = (samples[BATCHES / 2 - 1] + samples[BATCHES / 2]) / 2;
            let p95 = samples[(BATCHES * 95).div_ceil(100) - 1];
            println!(
                "D01 {label}: rows={ROWS} warmups={WARMUPS} batches={BATCHES} preparations_per_batch={PREPARATIONS_PER_BATCH} median_ns={median} p95_ns={p95}"
            );
        }

        let raw = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90].repeat(32);
        let mut raw_view = Editor::new(raw, Mode::Code, 0);
        raw_view.code_bits = 32;
        raw_view.pack_nops = false;
        raw_view.pack_int3 = false;

        let pe_data = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/windows-capstone-5.0.9.dll"),
        )
        .expect("Cannot read the PE benchmark workload.");
        let entry = format::entry_point(&pe_data).expect("Cannot read the PE entry point.");
        let bits = format::code_address(&pe_data, entry)
            .expect("Cannot read the PE code size.")
            .1;
        let mut pe_view = Editor::new(pe_data, Mode::Code, entry);
        pe_view.top = entry;
        pe_view.code_bits = bits;
        pe_view.pack_nops = false;
        pe_view.pack_int3 = false;

        measure("raw-x86", &raw_view);
        measure("capstone-pe-entry", &pe_view);
    }

    /*
    This test checks decoder reuse and replacement across architecture, syntax, and Real16 changes.
    Invalid x86 and Real16 requests must preserve the previous usable native handle.
    */
    #[test]
    fn decoder_for_reuses_and_replaces_decoder() {
        let mut decoder = None;
        assert_eq!(
            decoder_for(
                &mut decoder,
                format::Architecture::X86(32),
                decoder::Syntax::Intel,
                false,
            )
            .unwrap()
            .bits(),
            32
        );
        let first = decoder.as_ref().unwrap().native_handle();
        decoder_for(
            &mut decoder,
            format::Architecture::X86(32),
            decoder::Syntax::Intel,
            false,
        )
        .unwrap();
        assert_eq!(decoder.as_ref().unwrap().native_handle(), first);
        assert_eq!(
            decoder_for(
                &mut decoder,
                format::Architecture::X86(32),
                decoder::Syntax::Att,
                false,
            )
            .unwrap()
            .syntax(),
            decoder::Syntax::Att
        );
        let att = decoder.as_ref().unwrap().native_handle();
        assert_ne!(att, first);
        assert_eq!(
            decoder_for(
                &mut decoder,
                format::Architecture::X86(16),
                decoder::Syntax::Intel,
                false,
            )
            .unwrap()
            .bits(),
            16
        );
        let width16 = decoder.as_ref().unwrap().native_handle();
        assert_ne!(width16, att);
        assert!(
            decoder_for(
                &mut decoder,
                format::Architecture::X86(16),
                decoder::Syntax::Intel,
                true,
            )
            .unwrap()
            .real_mode()
        );
        let real16 = decoder.as_ref().unwrap().native_handle();
        assert_ne!(real16, width16);
        decoder_for(
            &mut decoder,
            format::Architecture::X86(16),
            decoder::Syntax::Intel,
            true,
        )
        .unwrap();
        assert_eq!(decoder.as_ref().unwrap().native_handle(), real16);
        assert_eq!(
            decoder_for(
                &mut decoder,
                format::Architecture::X86(64),
                decoder::Syntax::Intel,
                false,
            )
            .unwrap()
            .bits(),
            64
        );
        let retained = decoder.as_ref().unwrap().native_handle();
        assert!(
            decoder_for(
                &mut decoder,
                format::Architecture::X86(8),
                decoder::Syntax::Intel,
                false,
            )
            .is_err()
        );
        assert_eq!(decoder.as_ref().unwrap().native_handle(), retained);
        assert!(
            decoder_for(
                &mut decoder,
                format::Architecture::Arm,
                decoder::Syntax::Intel,
                true,
            )
            .is_err()
        );
        assert_eq!(decoder.as_ref().unwrap().native_handle(), retained);
        assert_eq!(
            decoder
                .as_ref()
                .unwrap()
                .decode(&[0x90], 0, 0)
                .unwrap()
                .text,
            "nop"
        );

        /*
        Each architecture change creates a new native handle while the prior handle remains live.
        An identical request reuses that handle and decodes through the selected engine.
        */
        for (architecture, bytes) in [
            (format::Architecture::Arm, &[0x00, 0x00, 0xa0, 0xe1][..]),
            (format::Architecture::Thumb, &[0x01, 0x20][..]),
            (format::Architecture::Arm64, &[0x1f, 0x20, 0x03, 0xd5][..]),
        ] {
            let previous = decoder.as_ref().unwrap().native_handle();
            let selected =
                decoder_for(&mut decoder, architecture, decoder::Syntax::Intel, false).unwrap();
            assert_eq!(selected.architecture(), architecture);
            let handle = selected.native_handle();
            assert_ne!(handle, previous);
            decoder_for(&mut decoder, architecture, decoder::Syntax::Intel, false).unwrap();
            assert_eq!(decoder.as_ref().unwrap().native_handle(), handle);
            assert_eq!(
                decoder
                    .as_ref()
                    .unwrap()
                    .decode(bytes, 0, 0x1000)
                    .unwrap()
                    .size,
                bytes.len()
            );
        }

        /*
        ARM64 retains the requested syntax as a cache property without applying an x86 option.
        A repeated request reuses the replacement handle.
        */
        let arm64 = decoder.as_ref().unwrap().native_handle();
        assert_eq!(
            decoder_for(
                &mut decoder,
                format::Architecture::Arm64,
                decoder::Syntax::Att,
                false,
            )
            .unwrap()
            .syntax(),
            decoder::Syntax::Att
        );
        let arm64_att = decoder.as_ref().unwrap().native_handle();
        assert_ne!(arm64_att, arm64);
        decoder_for(
            &mut decoder,
            format::Architecture::Arm64,
            decoder::Syntax::Att,
            false,
        )
        .unwrap();
        assert_eq!(decoder.as_ref().unwrap().native_handle(), arm64_att);
        assert!(
            decoder_for(
                &mut decoder,
                format::Architecture::Arm64,
                decoder::Syntax::Att,
                true,
            )
            .is_err()
        );
        assert_eq!(decoder.as_ref().unwrap().native_handle(), arm64_att);
        assert_eq!(
            decoder
                .as_ref()
                .unwrap()
                .decode(&[0x1f, 0x20, 0x03, 0xd5], 0, 0x1000)
                .unwrap()
                .text,
            "nop"
        );
    }

    /*
    This test checks assembly preview byte ranges, shorter replacements, overlap, and file growth.
    Preview generation must never change Editor bytes.
    */
    #[test]
    fn assembly_preview_covers_exact_overwritten_bytes_and_growth() {
        /*
        This helper creates one preview with metadata from the supplied Editor.
        Tests inspect the returned record without applying it.
        */
        fn preview(view: &Editor, replacement: &[u8]) -> AssemblyPreview {
            let metadata = view.metadata().unwrap();
            assembly_preview(view, &metadata, &mut None, replacement).unwrap()
        }

        let mut shorter = Editor::new(vec![0xb8, 1, 0, 0, 0, 0xc3], Mode::Code, 0);
        shorter.code_bits = 32;
        shorter
            .set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture: format::Architecture::X86(32),
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
        let before = shorter.data.clone();
        let result = preview(&shorter, &[0x90]);
        assert_eq!(shorter.data, before);
        assert_eq!(result.summary[0], "Assembly patch preview");
        assert!(result.summary[1].contains("Runtime address: 0000000000001000"));
        assert_eq!(result.summary[2], "Original bytes (5): B8 01 00 00 00");
        assert_eq!(result.summary[3], "Replacement bytes (1): 90");
        assert!(result.summary[4].contains("Replacement length delta: -4 bytes"));
        assert!(
            result
                .summary
                .iter()
                .any(|line| line.starts_with("Shorter replacement:"))
        );

        let mut longer = Editor::new(vec![0x90; 6], Mode::Code, 0);
        longer.code_bits = 32;
        let replacement = assembler::assemble("mov eax,1", 32, 0).unwrap();
        let result = preview(&longer, &replacement);
        assert_eq!(result.summary[2], "Original bytes (5): 90 90 90 90 90");
        assert_eq!(result.original.len(), 5);
        assert_eq!(result.proposed.len(), 1);
        assert!(result.summary[4].contains("Replacement length delta: +4 bytes"));

        let mut partial = Editor::new(vec![0x90, 0xbb, 1, 0, 0, 0, 0xc3], Mode::Code, 0);
        partial.code_bits = 32;
        let result = preview(&partial, &replacement);
        assert_eq!(result.summary[2], "Original bytes (5): 90 BB 01 00 00");
        assert!(result.summary.iter().any(
            |line| line == "Partial overlap: the final original instruction retains 1 byte(s)."
        ));

        let mut eof = Editor::new(vec![0x90], Mode::Code, 1);
        eof.code_bits = 32;
        eof.set_raw_model(Some(editor::RawModel {
            base: 0x2000,
            architecture: format::Architecture::X86(32),
            byte_order: editor::ByteOrder::Little,
        }))
        .unwrap();
        let result = preview(&eof, &[0xc3]);
        assert_eq!(result.summary[2], "Original bytes (0): <end of file>");
        assert!(result.summary[4].contains("File growth: +1 bytes"));
        assert!(result.original[0].contains("<end of file>"));
        assert!(result.proposed[0].contains("ret"));
        assert_eq!(
            (eof.data.as_slice(), eof.offset, eof.dirty),
            (&[0x90][..], 1, false)
        );
    }

    /*
    This test keeps the plain-file EOF assembly path separate from bounded Code locations.
    A mapped PE gap cannot provide a valid assembly address.
    */
    #[test]
    fn assembly_preview_accepts_plain_eof_and_rejects_pe_gaps() {
        for (data, offset, replacement, instruction) in [
            (&[][..], 0, &[0x90][..], "nop"),
            (&[0x90][..], 1, &[0xc3][..], "ret"),
        ] {
            let mut view = Editor::new(data.to_vec(), Mode::Code, offset);
            view.code_bits = 32;
            let preview =
                assembly_preview(&view, &view.metadata().unwrap(), &mut None, replacement).unwrap();
            assert!(preview.original[0].contains("<end of file>"));
            assert!(preview.proposed[0].contains(instruction));
        }

        let mut data = pe_code_fixture(false, 0x014c);
        put_test_dword(&mut data, 376 + 20, 0x300);
        let mut gap = Editor::new(data, Mode::Code, 0x250);
        gap.code_bits = 32;
        assert!(assembly_preview(&gap, &gap.metadata().unwrap(), &mut None, &[0x90]).is_err());
    }

    /*
    This test checks strict effective decoding for Real16, raw widths, and display syntax.
    Invalid replacement bytes remain unapplied.
    */
    #[test]
    fn assembly_preview_uses_strict_effective_decoding_and_syntax() {
        for syntax in [decoder::Syntax::Intel, decoder::Syntax::Att] {
            let mut view = Editor::new(vec![0x90; 8], Mode::Code, 0);
            view.code_bits = 16;
            view.real_mode = true;
            view.syntax = syntax;
            let metadata = view.metadata().unwrap();
            assert!(assembly_preview(&view, &metadata, &mut None, &[0x0f, 0x34]).is_err());

            view.set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture: format::Architecture::X86(16),
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            let metadata = view.metadata().unwrap();
            assert!(assembly_preview(&view, &metadata, &mut None, &[0x0f, 0x34]).is_ok());

            view.set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture: format::Architecture::X86(32),
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            let preview =
                assembly_preview(&view, &view.metadata().unwrap(), &mut None, &[0x89, 0xd8])
                    .unwrap();
            assert_eq!(
                preview.proposed[0].contains('%'),
                syntax == decoder::Syntax::Att
            );
        }

        let mut fallback = Editor::new(vec![0x90], Mode::Code, 0);
        fallback.code_bits = 32;
        fallback.invalid_code_bytes = true;
        let before = fallback.data.clone();
        assert!(
            assembly_preview(&fallback, &fallback.metadata().unwrap(), &mut None, &[0x0f]).is_err()
        );
        assert_eq!(fallback.data, before);

        fallback.offset = 1;
        fallback
            .set_raw_model(Some(editor::RawModel {
                base: u64::from(u32::MAX),
                architecture: format::Architecture::X86(32),
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
        assert!(
            assembly_preview(&fallback, &fallback.metadata().unwrap(), &mut None, &[0xc3]).is_err()
        );
        assert_eq!(
            (fallback.data.as_slice(), fallback.offset),
            (&[0x90][..], 1)
        );
    }

    /*
    This test checks summary wrapping and equal preview-column clipping.
    Both results must fit their requested terminal widths.
    */
    #[test]
    fn assembly_preview_wraps_summary_and_marks_truncated_columns() {
        let text = format!("Replacement bytes (15): {}", spaced_hex(&[0x90; 15]));
        let rows = wrap_text(&text, 60);
        assert!(rows.len() > 1);
        assert!(rows.iter().all(|row| row.chars().count() <= 60));
        assert_eq!(rows.join(" "), text);

        let columns = preview_columns(60, &"x".repeat(50), &"y".repeat(50));
        assert_eq!(columns.chars().count(), 60);
        assert_eq!(columns.matches("...").count(), 2);
    }

    /*
    This test resolves direct targets from current plain and supported ELF bytes.
    Indirect, truncated, and invalid instructions must not produce a target.
    */
    #[test]
    fn direct_navigation_uses_current_raw_and_elf_bytes() {
        for syntax in [decoder::Syntax::Intel, decoder::Syntax::Att] {
            let mut data = vec![0xe8, 5, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0xeb, 0xf6];
            let mut view = Editor::new(data.clone(), Mode::Code, 0);
            view.code_bits = 16;
            view.syntax = syntax;
            let mut decoder = None;
            let metadata = format::Metadata::parse(&view.data);
            assert_eq!(direct_target_offset(&view, &metadata, &mut decoder), Ok(8));

            data[1] = 2;
            view.data = data;
            let metadata = format::Metadata::parse(&view.data);
            assert_eq!(direct_target_offset(&view, &metadata, &mut decoder), Ok(5));

            /*
            The ELF section checks mapped VA navigation and File-domain gap navigation.
            Both targets retain the domain of their selected source instruction.
            */
            let mut elf = elf_code_fixture(32, 3, 2, 0x400010);
            elf[0x110..0x115].copy_from_slice(&[0xe8, 3, 0, 0, 0]);
            elf[0x250..0x255].copy_from_slice(&[0xe8, 3, 0, 0, 0]);
            let mut view = Editor::new(elf, Mode::Code, 0x110);
            view.code_bits = 32;
            view.syntax = syntax;
            let metadata = format::Metadata::parse(&view.data);
            assert_eq!(
                direct_target_offset(&view, &metadata, &mut decoder),
                Ok(0x118)
            );
            view.offset = 0x250;
            assert_eq!(
                direct_target_offset(&view, &metadata, &mut decoder),
                Ok(0x258)
            );
        }

        let mut view = Editor::new(vec![0xff, 0xd0], Mode::Code, 0);
        let mut decoder = None;
        let metadata = format::Metadata::parse(&view.data);
        assert!(direct_target_offset(&view, &metadata, &mut decoder).is_err());

        view.data = vec![0xe8, 0xff, 0x7f];
        let metadata = format::Metadata::parse(&view.data);
        assert!(direct_target_offset(&view, &metadata, &mut decoder).is_err());

        view.data = vec![0x0f];
        view.invalid_code_bytes = true;
        let metadata = format::Metadata::parse(&view.data);
        assert!(direct_target_offset(&view, &metadata, &mut decoder).is_err());

        let mut view = Editor::new(vec![0xeb, 2, 0x90, 0x90, 0xc3], Mode::Code, 0);
        view.code_bits = 16;
        view.real_mode = true;
        view.set_raw_model(Some(editor::RawModel {
            base: 0x10000,
            architecture: format::Architecture::X86(32),
            byte_order: editor::ByteOrder::Little,
        }))
        .unwrap();
        let metadata = view.metadata();
        assert_eq!(direct_target_offset(&view, &metadata, &mut decoder), Ok(4));
        assert!(!view.decode_real_mode());
    }

    /*
    This test keeps a File-domain PE branch inside one readable mapping gap.
    It also bounds explicit raw targets without changing the caller's cursor.
    */
    #[test]
    fn direct_navigation_preserves_file_domains_and_current_bounds() {
        let mut data = pe_code_fixture(false, 0x014c);
        put_test_dword(&mut data, 376 + 20, 0x300);
        data[0x250..0x252].copy_from_slice(&[0xeb, 0x02]);
        let mut gap = Editor::new(data, Mode::Code, 0x250);
        gap.code_bits = 32;
        let metadata = gap.metadata();
        assert_eq!(
            metadata
                .as_ref()
                .unwrap()
                .code_location(0x250)
                .unwrap()
                .domain,
            format::AddressDomain::File
        );
        assert_eq!(direct_target_offset(&gap, &metadata, &mut None), Ok(0x254));

        let mut raw = Editor::new(vec![0xeb, 0, 0x90], Mode::Code, 0);
        raw.code_bits = 32;
        raw.set_raw_model(Some(editor::RawModel {
            base: 0x1000,
            architecture: format::Architecture::X86(32),
            byte_order: editor::ByteOrder::Little,
        }))
        .unwrap();
        assert_eq!(
            direct_target_offset(&raw, &raw.metadata(), &mut None),
            Ok(2)
        );

        for bytes in [vec![0xeb, 2, 0x90, 0x90], vec![0xeb, 3, 0x90, 0x90]] {
            raw.data = bytes;
            raw.offset = 0;
            raw.top = 0;
            let before = (raw.offset, raw.top);
            assert!(direct_target_offset(&raw, &raw.metadata(), &mut None).is_err());
            assert_eq!((raw.offset, raw.top), before);
        }
    }

    /*
    This test replays the Windows high File-domain target correction for each affected engine.
    X86-64 keeps its complete target, while invalid source arithmetic returns an error.
    */
    #[test]
    fn file_domain_targets_restore_signed_low32_displacements() {
        let source = 0x1_0000_0010;
        for architecture in [
            format::Architecture::X86(16),
            format::Architecture::X86(32),
            format::Architecture::Arm,
            format::Architecture::Thumb,
        ] {
            assert_eq!(
                file_domain_target(architecture, source, 2, 0x16),
                Ok(0x1_0000_0016)
            );
            assert_eq!(
                file_domain_target(architecture, source, 2, 0x0c),
                Ok(0x1_0000_000c)
            );
        }
        assert_eq!(
            file_domain_target(format::Architecture::X86(64), source, 2, 0x16),
            Ok(0x16)
        );
        assert!(file_domain_target(format::Architecture::Arm, u64::MAX, 1, 0).is_err());
        assert!(file_domain_target(format::Architecture::Thumb, 0, 0, 0).is_err());
    }

    /*
    This test passes both established Real16 wrap positions through current direct navigation.
    The existing decoder result must map each branch back to file offset zero.
    */
    #[test]
    fn direct_navigation_preserves_real16_wrap_vectors() {
        let mut data = vec![0x90; 0x10002];
        data[0xfffe..0x10000].copy_from_slice(&[0xeb, 0]);
        data[0x10000..0x10002].copy_from_slice(&[0xeb, 0xfe]);
        let mut view = Editor::new(data, Mode::Code, 0xfffe);
        view.code_bits = 16;
        view.real_mode = true;
        let mut decoder = None;
        assert_eq!(
            direct_target_offset(&view, &view.metadata(), &mut decoder),
            Ok(0)
        );
        view.offset = 0x10000;
        assert_eq!(
            direct_target_offset(&view, &view.metadata(), &mut decoder),
            Ok(0)
        );
    }

    /*
    This test ignores stored Real16 state for automatic ARM-family PE decoders.
    The x86 width control must also preserve each effective ARM architecture.
    */
    #[test]
    fn automatic_pe_arm_decoders_ignore_real16_and_width_changes() {
        for (plus, machine, architecture, instruction) in [
            (
                false,
                0x01c0,
                format::Architecture::Arm,
                &[0x00, 0x00, 0xa0, 0xe1][..],
            ),
            (
                false,
                0x01c2,
                format::Architecture::Thumb,
                &[0x01, 0x20][..],
            ),
            (
                true,
                0xaa64,
                format::Architecture::Arm64,
                &[0x1f, 0x20, 0x03, 0xd5][..],
            ),
        ] {
            let mut data = pe_code_fixture(plus, machine);
            data[0x200..0x200 + instruction.len()].copy_from_slice(instruction);
            let mut view = Editor::new(data, Mode::Code, 0x200);
            view.code_bits = 16;
            view.real_mode = true;
            let metadata = view.metadata();
            let mut decoder = None;
            decode_at(&view, 0x200, &metadata, &mut decoder).unwrap();
            assert_eq!(decoder.as_ref().unwrap().architecture(), architecture);
            assert!(!decoder.as_ref().unwrap().real_mode());
            let before = (view.code_bits, view.real_mode);
            assert_eq!(
                cycle_code_mode(&mut view).unwrap_err(),
                "The current ARM architecture does not use x86 code widths."
            );
            assert_eq!((view.code_bits, view.real_mode), before);
        }
    }

    /*
    This test ignores stored Real16 state for automatic ARM-family ELF decoders.
    Manual x86 width and syntax settings remain effective for supported ELF x86 metadata.
    */
    #[test]
    fn automatic_elf_decoders_preserve_architecture_and_x86_settings() {
        /*
        The ARM section selects ARM, Thumb, and ARM64 only from checked ELF header facts.
        The x86 Real16 flag cannot enter any ARM-family native decoder.
        */
        for (bits, machine, entry, architecture, instruction) in [
            (
                32,
                40,
                0x400010,
                format::Architecture::Arm,
                &[0x00, 0x00, 0xa0, 0xe1][..],
            ),
            (
                32,
                40,
                0x400011,
                format::Architecture::Thumb,
                &[0x01, 0x20][..],
            ),
            (
                64,
                183,
                0x400010,
                format::Architecture::Arm64,
                &[0x1f, 0x20, 0x03, 0xd5][..],
            ),
        ] {
            let mut data = elf_code_fixture(bits, machine, 2, entry);
            data[0x110..0x110 + instruction.len()].copy_from_slice(instruction);
            let mut view = Editor::new(data, Mode::Code, 0x110);
            view.code_bits = 16;
            view.real_mode = true;
            let metadata = view.metadata();
            let mut decoder = None;
            decode_at(&view, 0x110, &metadata, &mut decoder).unwrap();
            assert_eq!(decoder.as_ref().unwrap().architecture(), architecture);
            assert!(!decoder.as_ref().unwrap().real_mode());
            assert!(cycle_code_mode(&mut view).is_err());
        }

        /*
        The x86 section keeps manual width, Real16, and explicit AT&T display configuration.
        ELF class does not replace the current automatic x86 width setting.
        */
        let mut data = elf_code_fixture(64, 62, 2, 0x400010);
        data[0x110] = 0x90;
        let mut view = Editor::new(data, Mode::Code, 0x110);
        view.code_bits = 16;
        view.real_mode = true;
        view.syntax = decoder::Syntax::Att;
        let metadata = view.metadata();
        let mut decoder = None;
        decode_at(&view, 0x110, &metadata, &mut decoder).unwrap();
        let decoder = decoder.unwrap();
        assert_eq!(decoder.architecture(), format::Architecture::X86(16));
        assert!(decoder.real_mode());
        assert_eq!(decoder.syntax(), decoder::Syntax::Att);
    }

    /*
    This test checks exact x86 and ARM64 PE gap header fields at the standard width.
    Architecture and FILE labels must not cover each other or the file offset.
    */
    #[test]
    fn pe_file_domain_headers_keep_all_fields_separate() {
        for (plus, machine, expected) in [
            (false, 0x014c, "a32   FILE 00000250│"),
            (true, 0xaa64, "ARM64 FILE 00000250│"),
        ] {
            let mut data = pe_code_fixture(plus, machine);
            let section = 152 + if plus { 240 } else { 224 };
            put_test_dword(&mut data, section + 20, 0x300);
            let metadata = format::Metadata::parse(&data).unwrap();
            let location = metadata.code_location(0x250).unwrap();
            let architecture = metadata.decoder_architecture(32).unwrap();
            let width = 80;
            let mut header = vec![' '; width];
            put(&mut header, width - 33, "00000250│HView-Linux 0.1.0");
            apply_code_header(
                &mut header,
                0x250,
                location,
                architecture,
                false,
                metadata.format_label(),
                false,
            );
            let header: String = header.into_iter().collect();
            assert!(header.contains(expected), "{header}");
        }
    }

    /*
    This test places ELF and FILE labels in mapped and gap Code headers.
    The architecture label and displayed address remain visible in both domains.
    */
    #[test]
    fn elf_code_headers_show_mapped_and_file_domains() {
        for (offset, expected) in [
            (0x110, "a32    00ELF.00400010"),
            (0x250, "a32   FILE 00000250│"),
        ] {
            let data = elf_code_fixture(32, 3, 2, 0x400010);
            let metadata = format::Metadata::parse(&data).unwrap();
            let location = metadata.code_location(offset).unwrap();
            let architecture = metadata.decoder_architecture(32).unwrap();
            let width = 80;
            let mut header = vec![' '; width];
            put(
                &mut header,
                width - 33,
                &format!("{offset:08X}│HView-Linux 0.1.0"),
            );
            apply_code_header(
                &mut header,
                offset,
                location,
                architecture,
                false,
                metadata.format_label(),
                false,
            );
            let header: String = header.into_iter().collect();
            assert!(header.contains(expected), "{header}");
        }
    }

    /*
    This test fills the bounded return history and validates last-in-first-out removal.
    An invalid current buffer must preserve the stored position.
    */
    #[test]
    fn return_history_is_bounded_and_preserves_positions() {
        let mut history = VecDeque::new();
        for offset in 0..=RETURN_HISTORY_LIMIT as u64 {
            remember_return(&mut history, (offset, offset.saturating_sub(10)));
        }
        assert_eq!(history.len(), RETURN_HISTORY_LIMIT);
        assert_eq!(history.front(), Some(&(1, 0)));
        assert_eq!(history.back(), Some(&(RETURN_HISTORY_LIMIT as u64, 246)));

        let data = vec![0; RETURN_HISTORY_LIMIT + 1];
        assert_eq!(take_return(&mut history, &data), Ok(Some((256, 246))));
        remember_return(&mut history, (4, 2));
        remember_return(&mut history, (8, 6));
        assert_eq!(take_return(&mut history, &data), Ok(Some((8, 6))));
        assert_eq!(take_return(&mut history, &data), Ok(Some((4, 2))));

        history.clear();
        remember_return(&mut history, (20, 0));
        let before = history.clone();
        assert!(take_return(&mut history, b"short").is_err());
        assert_eq!(history, before);
    }

    /*
    This test checks valid and invalid hexadecimal search input.
    Complete byte pairs become their exact binary values.
    */
    #[test]
    fn search_input_and_native_layout() {
        assert_eq!(hex_pattern("21 22").unwrap(), [0x21, 0x22]);
        assert!(hex_pattern("2").is_err());
        assert!(hex_pattern("xx").is_err());
    }

    /*
    This test keeps Intel assembly input independent from AT&T disassembly output.
    The active raw address model supplies the effective decoder architecture.
    */
    #[test]
    fn assembly_seed_stays_intel_with_att_display() {
        let mut view = Editor::new(vec![0x48, 0x89, 0xd8], Mode::Code, 0);
        view.code_bits = 16;
        view.real_mode = true;
        view.syntax = decoder::Syntax::Att;
        view.set_raw_model(Some(editor::RawModel {
            base: 0x1_0000_0000,
            architecture: format::Architecture::X86(64),
            byte_order: editor::ByteOrder::Little,
        }))
        .unwrap();
        let seed = assembly_seed(&view, &view.metadata()).unwrap();
        assert!(seed.contains("rax, rbx"));
        assert!(!seed.contains('%'));
    }

    /*
    This test keeps raw integer byte order separate from x86 instruction decoding.
    Both raw models decode identical bytes, while the integer inspector uses the selected order.
    */
    #[test]
    fn raw_byte_order_does_not_change_x86_decoding() {
        let data = vec![0x89, 0xd8, 0x01, 0x02];
        let mut texts = Vec::new();
        let mut integers = Vec::new();
        for byte_order in [editor::ByteOrder::Little, editor::ByteOrder::Big] {
            let mut view = Editor::new(data.clone(), Mode::Code, 0);
            view.set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture: format::Architecture::X86(32),
                byte_order,
            }))
            .unwrap();
            let instruction = decode_at(&view, 0, &view.metadata(), &mut None).unwrap().1;
            texts.push((instruction.size, instruction.text));
            integers.push(inspect::integers(&view.data, 0, Some(byte_order))[1].clone());
        }
        assert_eq!(texts[0], texts[1]);
        assert_ne!(integers[0], integers[1]);
    }

    /*
    This test sends each ARM-family raw model through current buffered Code display helpers.
    Nonzero file offsets and runtime bases prove that address mapping and engine selection stay together.
    */
    #[test]
    fn raw_arm_architectures_reach_buffered_code_consumers() {
        for (architecture, prefix, bytes, expected) in [
            (
                format::Architecture::Arm,
                4,
                &[0x00, 0x00, 0xa0, 0xe1][..],
                "mov          r0, r0",
            ),
            (
                format::Architecture::Thumb,
                2,
                &[0x01, 0x20][..],
                "movs         r0, #1",
            ),
            (
                format::Architecture::Arm64,
                4,
                &[0x1f, 0x20, 0x03, 0xd5][..],
                "nop",
            ),
        ] {
            /*
            The setup section places one independent instruction after a nonzero source prefix.
            Both byte-order models must select the same little-endian instruction engine.
            */
            let mut data = vec![0xff; prefix];
            data.extend_from_slice(bytes);
            let mut decoded = Vec::new();
            for byte_order in [editor::ByteOrder::Little, editor::ByteOrder::Big] {
                let mut view = Editor::new(data.clone(), Mode::Code, prefix as u64);
                view.top = prefix as u64;
                view.invalid_code_bytes = true;
                view.set_raw_model(Some(editor::RawModel {
                    base: 0x4000,
                    architecture,
                    byte_order,
                }))
                .unwrap();
                let metadata = view.metadata();
                let location = code_location(&metadata, prefix as u64).unwrap();
                assert_eq!(
                    (location.address, location.architecture, location.domain),
                    (
                        0x4000 + prefix as u64,
                        architecture,
                        format::AddressDomain::Va,
                    )
                );

                /*
                The decode section checks strict selection, display rows, and assembly seed text.
                Each result retains the selected runtime address and architecture-specific instruction size.
                */
                let instruction = decode_at(&view, prefix as u64, &metadata, &mut None)
                    .unwrap()
                    .1;
                assert_eq!(instruction.size, bytes.len());
                assert_eq!(instruction.text, expected);
                let rows = code_rows(&view, 1, &metadata, &mut None);
                assert!(rows[0].contains(expected.trim()));
                assert!(rows[0].contains(&format!("{:08X}", 0x4000 + prefix)));
                assert_eq!(assembly_seed(&view, &metadata).unwrap(), expected);
                decoded.push(instruction.text);
            }
            assert_eq!(decoded[0], decoded[1]);
        }

        /*
        The tail section sends one remaining byte through each fixed-width raw engine.
        The configured fallback clips one architecture unit without enabling x86 byte packing.
        */
        for architecture in [
            format::Architecture::Arm,
            format::Architecture::Thumb,
            format::Architecture::Arm64,
        ] {
            let mut view = Editor::new(vec![0x90], Mode::Code, 0);
            view.invalid_code_bytes = true;
            view.pack_nops = true;
            view.set_raw_model(Some(editor::RawModel {
                base: 0x4000,
                architecture,
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            let instruction = decode_at(&view, 0, &view.metadata(), &mut None).unwrap().1;
            assert_eq!(instruction.size, 1);
            assert_eq!(instruction.hex, "90");
            assert!(instruction.text.starts_with("db"));
        }
    }

    /*
    This test applies ARM and Thumb assembly through the current preview transaction path.
    ARM64 refuses assembly before preview and preserves the active editor state.
    */
    #[test]
    fn raw_arm_assembly_preview_preserves_transactions_and_arm64_refusal() {
        for (architecture, original, text, replacement) in [
            (
                format::Architecture::Arm,
                &[0x00, 0x00, 0xa0, 0xe1][..],
                "mov r0, #1",
                &[0x01, 0x00, 0xa0, 0xe3][..],
            ),
            (
                format::Architecture::Thumb,
                &[0x00, 0xbf][..],
                "movs r0, #1",
                &[0x01, 0x20][..],
            ),
        ] {
            /*
            The preparation section assembles at a nonzero file offset and runtime address.
            The preview must show exact bytes without changing the current buffer.
            */
            let prefix = architecture.alignment() as usize;
            let mut data = vec![0xff; prefix];
            data.extend_from_slice(original);
            let mut view = Editor::new(data.clone(), Mode::Code, prefix as u64);
            view.top = prefix as u64;
            view.set_raw_model(Some(editor::RawModel {
                base: 0x8000,
                architecture,
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            let address = 0x8000 + prefix as u64;
            let bytes = assembler::assemble_architecture(text, architecture, address).unwrap();
            assert_eq!(bytes, replacement);
            let preview =
                assembly_preview(&view, &view.metadata().unwrap(), &mut None, &bytes).unwrap();
            assert_eq!(view.data, data);
            assert!(preview.summary[1].contains(&format!("Runtime address: {address:016X}")));
            assert!(preview.proposed[0].contains("mov"));

            /*
            The transaction section applies the accepted bytes and checks Undo, Redo, and cancellation.
            Cancellation restores the complete original buffer after both history directions remain usable.
            */
            view.toggle_edit().unwrap();
            let end = prefix + bytes.len();
            view.replace_bytes(prefix, bytes, (end as u64, prefix as u64))
                .unwrap();
            assert_eq!(&view.data[prefix..end], replacement);
            assert!(view.undo().unwrap());
            assert_eq!(view.data, data);
            assert!(view.redo().unwrap());
            assert_eq!(&view.data[prefix..end], replacement);
            view.cancel_edit();
            assert_eq!(view.data, data);
        }

        /*
        The final section checks ARM64 refusal with an owned unsaved replacement.
        The error retains dirty bytes, cursor state, edit history, and the selected raw model.
        */
        let original = vec![0x1f, 0x20, 0x03, 0xd5];
        let edited = vec![0x20, 0x00, 0x80, 0x52];
        let mut arm64 = Editor::new(original.clone(), Mode::Code, 0);
        let raw = editor::RawModel {
            base: 0x1_4000_0000,
            architecture: format::Architecture::Arm64,
            byte_order: editor::ByteOrder::Little,
        };
        arm64.set_raw_model(Some(raw)).unwrap();
        arm64.toggle_edit().unwrap();
        arm64.replace_bytes(0, edited.clone(), (4, 0)).unwrap();
        let error = assembler::assemble_architecture(
            "nop",
            arm64
                .metadata()
                .unwrap()
                .decoder_architecture(arm64.code_bits)
                .unwrap(),
            0x1_4000_0000,
        )
        .unwrap_err();
        assert_eq!(error, "ARM64 assembly is unsupported.");
        assert_eq!(arm64.data, edited);
        assert_eq!((arm64.offset, arm64.top), (4, 0));
        assert!(arm64.editing);
        assert!(arm64.dirty);
        assert_eq!(arm64.raw_model, Some(raw));
        assert!(arm64.undo().unwrap());
        assert_eq!(arm64.data, original);
        assert!(arm64.redo().unwrap());
        assert_eq!(arm64.data, edited);
        arm64.cancel_edit();
        assert_eq!(arm64.data, original);
        assert_eq!(arm64.raw_model, Some(raw));
    }

    /*
    This test resolves raw ARM-family direct branches through current buffered navigation.
    BLX and indirect transfers remain targetless and cannot create a file target.
    */
    #[test]
    fn raw_arm_direct_targets_map_back_to_current_file_offsets() {
        /*
        The first table maps one direct branch for each ARM-family architecture.
        Nonzero source offsets prove that runtime targets return to exact file offsets.
        */
        for (architecture, prefix, branch, target) in [
            (
                format::Architecture::Arm,
                4,
                &[0x00, 0x00, 0x00, 0xea][..],
                12,
            ),
            (format::Architecture::Thumb, 2, &[0x01, 0xe0][..], 8),
            (
                format::Architecture::Arm64,
                4,
                &[0x01, 0x00, 0x00, 0x14][..],
                8,
            ),
        ] {
            let mut data = vec![0xff; 20];
            data[prefix..prefix + branch.len()].copy_from_slice(branch);
            let mut view = Editor::new(data, Mode::Code, prefix as u64);
            view.set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture,
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            assert_eq!(
                direct_target_offset(&view, &view.metadata(), &mut None),
                Ok(target)
            );
        }

        /*
        The second table sends BLX and an indirect return through the same current helper.
        None of these instructions can publish one direct file target.
        */
        for (architecture, bytes) in [
            (format::Architecture::Arm, &[0x02, 0x00, 0x00, 0xfa][..]),
            (format::Architecture::Thumb, &[0x00, 0xf0, 0x06, 0xe8][..]),
            (format::Architecture::Arm64, &[0xc0, 0x03, 0x5f, 0xd6][..]),
        ] {
            let mut view = Editor::new(bytes.to_vec(), Mode::Code, 0);
            view.set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture,
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            assert!(direct_target_offset(&view, &view.metadata(), &mut None).is_err());
        }
    }

    /*
    This test changes between three 32-bit raw architectures at one runtime base.
    The shared decoder cache must refresh Code text and direct targets for each architecture.
    */
    #[test]
    fn same_width_raw_architecture_changes_refresh_code_and_targets() {
        let mut data = vec![0x90; 20];
        data[0..2].copy_from_slice(&[0xeb, 0x06]);
        data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0xea]);
        data[8..10].copy_from_slice(&[0x01, 0xe0]);
        let mut view = Editor::new(data, Mode::Code, 0);
        let mut decoder = None;

        /*
        Each selection keeps base 1000 and changes only the architecture and file offset.
        Exact target offsets prove that the previous 32-bit engine does not remain cached.
        */
        for (architecture, offset, mnemonic, target) in [
            (format::Architecture::X86(32), 0, "jmp", 8),
            (format::Architecture::Arm, 4, "b", 12),
            (format::Architecture::Thumb, 8, "b", 14),
        ] {
            view.offset = offset;
            view.top = offset;
            view.set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture,
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            let metadata = view.metadata();
            let instruction = decode_at(&view, offset, &metadata, &mut decoder).unwrap().1;
            assert!(instruction.text.starts_with(mnemonic));
            assert!(code_rows(&view, 1, &metadata, &mut decoder)[0].contains(mnemonic));
            assert_eq!(
                direct_target_offset(&view, &metadata, &mut decoder),
                Ok(target)
            );
            assert_eq!(decoder.as_ref().unwrap().architecture(), architecture);
        }
    }

    /*
    This test cycles raw widths without changing the underlying Real16 setting.
    An invalid high raw base preserves the previous model.
    */
    #[test]
    fn raw_width_cycle_is_separate_from_the_underlying_real16_mode() {
        let mut view = Editor::new(vec![0x90], Mode::Code, 0);
        view.code_bits = 16;
        view.real_mode = true;
        view.set_raw_model(Some(editor::RawModel {
            base: 0x1000,
            architecture: format::Architecture::X86(32),
            byte_order: editor::ByteOrder::Big,
        }))
        .unwrap();

        cycle_code_mode(&mut view).unwrap();
        assert_eq!(
            view.raw_model.unwrap().architecture,
            format::Architecture::X86(64)
        );
        cycle_code_mode(&mut view).unwrap();
        assert_eq!(
            view.raw_model.unwrap().architecture,
            format::Architecture::X86(16)
        );
        assert!(!view.decode_real_mode());
        view.set_raw_model(None).unwrap();
        assert_eq!(
            view.metadata()
                .unwrap()
                .decoder_architecture(view.code_bits),
            Ok(format::Architecture::X86(16))
        );
        assert!(view.decode_real_mode());

        view.set_raw_model(Some(editor::RawModel {
            base: u64::from(u32::MAX) + 1,
            architecture: format::Architecture::X86(64),
            byte_order: editor::ByteOrder::Little,
        }))
        .unwrap();
        let before = view.raw_model;
        assert!(cycle_code_mode(&mut view).is_err());
        assert_eq!(view.raw_model, before);

        for architecture in [
            format::Architecture::Arm,
            format::Architecture::Thumb,
            format::Architecture::Arm64,
        ] {
            view.set_raw_model(Some(editor::RawModel {
                base: 0x1000,
                architecture,
                byte_order: editor::ByteOrder::Little,
            }))
            .unwrap();
            let before = view.raw_model;
            assert_eq!(
                cycle_code_mode(&mut view).unwrap_err(),
                "Use Ctrl+T, then R, to select a raw architecture."
            );
            assert_eq!(view.raw_model, before);
        }
    }

    /*
    This test permits invalid-byte display only when configuration enables fallback.
    The fallback consumes exactly one byte.
    */
    #[test]
    fn invalid_byte_fallback_is_explicit() {
        let metadata = format::Metadata::parse(&[0x0f]);
        let mut decoder = None;
        let mut view = Editor::new(vec![0x0f], Mode::Code, 0);
        assert!(decode_at(&view, 0, &metadata, &mut decoder).is_err());
        view.invalid_code_bytes = true;
        let (_, instruction) = decode_at(&view, 0, &metadata, &mut decoder).unwrap();
        assert_eq!((instruction.size, instruction.text.as_str()), (1, "db 0F"));
    }

    /*
    This test verifies that decoder errors cannot change or close an unsaved edit transaction.
    Code display and both preview paths must expose the original Capstone status.
    */
    #[test]
    fn invalid_byte_fallback_preserves_decoder_errors() {
        /*
        The setup section starts a real Code edit and records its unsaved state.
        The injected decoder keeps the real native handle but returns one deterministic error.
        */
        let original = vec![0x90, 0xc3];
        let mut view = Editor::new(original.clone(), Mode::Code, 0);
        view.code_bits = 32;
        view.invalid_code_bytes = true;
        view.toggle_edit().unwrap();
        view.replace_bytes(0, vec![0x0f], (1, 0)).unwrap();
        let edited = view.data.clone();
        let metadata = view.metadata();
        let mut cached = Some(decoder::Decoder::new(32).unwrap());
        cached.as_mut().unwrap().force_decode_error();
        /*
        The error section exercises selected decoding, Code rows, comparison rows, and assembly preview.
        Each call keeps error 17 and refuses the configured byte fallback.
        */
        let error = decode_at(&view, 0, &metadata, &mut cached).unwrap_err();
        assert!(error.contains("error 17"));

        let code = code_rows(&view, 1, &metadata, &mut cached);
        assert!(code[0].contains("error 17"));

        let metadata = metadata.unwrap();
        let rows = preview_rows(&view.data, 0, 1, &metadata, cached.as_ref().unwrap(), true);
        assert_eq!(rows.first_size, None);
        assert!(rows.rows[0].contains("error 17"));
        assert!(!rows.rows[0].contains("db"));
        let error = assembly_preview(&view, &metadata, &mut cached, &[0x90]).unwrap_err();
        assert!(error.contains("error 17"));

        /*
        The state section verifies the unsaved bytes, cursor, viewport, edit mode, and dirty flag.
        No decoder or preview error changes the transaction.
        */
        assert_eq!(
            (view.data.as_slice(), view.offset, view.top),
            (&edited[..], 1, 0)
        );
        assert!(view.editing);
        assert!(view.dirty);
        /*
        The history section verifies Undo and Redo after all error paths.
        Explicit cancel finally restores the original bytes and closes edit mode.
        */
        assert!(view.undo().unwrap());
        assert_eq!((view.data.as_slice(), view.offset), (&original[..], 0));
        assert!(view.editing);
        assert!(!view.dirty);
        assert!(view.redo().unwrap());
        assert_eq!((view.data.as_slice(), view.offset), (&edited[..], 1));
        assert!(view.editing);
        assert!(view.dirty);
        view.cancel_edit();
        assert_eq!(view.data, original);
        assert!(!view.editing);
        assert!(!view.dirty);
    }

    /*
    This test bounds packed NOP and INT3 runs and checks their independent flags.
    Disabled packing returns one decoded byte per instruction.
    */
    #[test]
    fn code_packing_respects_limits_and_settings() {
        for byte in [0x90, 0xcc] {
            let mut view = Editor::new(vec![byte; 20], Mode::Code, 0);
            let metadata = format::Metadata::parse(&view.data);
            let mut decoder = None;
            let packed = decode_at(&view, 0, &metadata, &mut decoder).unwrap().1;
            assert_eq!((packed.size, packed.hex.len()), (15, 30));
            assert_eq!(
                decode_at(&view, 15, &metadata, &mut decoder)
                    .unwrap()
                    .1
                    .size,
                5
            );
            if byte == 0x90 {
                view.pack_nops = false;
            } else {
                view.pack_int3 = false;
            }
            assert_eq!(
                decode_at(&view, 0, &metadata, &mut decoder).unwrap().1.size,
                1
            );
        }
    }

    /*
    This test accepts absolute Linux paths and literal Linux backslashes.
    Windows and relative saved path syntax must fail.
    */
    #[test]
    fn restored_paths_reject_windows_syntax() {
        assert_eq!(
            restored_path("/tmp/file.bin").unwrap(),
            Path::new("/tmp/file.bin")
        );
        assert_eq!(
            restored_path("/tmp/name\\part.bin").unwrap(),
            Path::new("/tmp/name\\part.bin")
        );
        assert!(restored_path("C:\\file.bin").is_err());
        assert!(restored_path("\\\\server\\file.bin").is_err());
        assert!(restored_path("folder\\file.bin").is_err());
        assert!(restored_path("relative.bin").is_err());
    }

    /*
    This test applies the unusable-view result before the final session publication gate.
    A replacement that published but cannot reopen must leave existing SAV bytes unchanged.
    */
    #[test]
    fn published_paged_replacement_disables_session_publication() {
        let folder = std::env::temp_dir().join(format!(
            "hview-paged-session-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&folder).unwrap();
        let path = folder.join("state.sav");
        std::fs::write(&path, b"existing SAV bytes").unwrap();

        let mut session_publish = true;
        let (action, closed) = close_unusable_paged_view(&mut session_publish);
        assert!(matches!(action, EditorAction::Quit));
        assert!(closed.is_none());
        if session_publish {
            std::fs::write(&path, b"stale SAV bytes").unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"existing SAV bytes");
        std::fs::remove_dir_all(folder).unwrap();
    }

    /*
    This test writes and reads one absolute Linux path that contains a backslash.
    Session conversion must preserve the literal path character.
    */
    #[test]
    fn native_backslash_path_roundtrips_through_a_session() {
        let folder = std::env::temp_dir().join(format!(
            "hview-backslash-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&folder).unwrap();
        let path = folder.join("name\\part.bin");
        std::fs::write(&path, b"data").unwrap();
        let view = Editor::new(b"data".to_vec(), Mode::Hex, 0);
        let state = config::SavedState::new_files(
            std::slice::from_ref(&path),
            0,
            &view,
            &config::Config::default(),
            Mode::Hex,
            None,
        )
        .unwrap();
        let parsed = config::parse_saved(&config::encode_saved(&state.payload).unwrap()).unwrap();
        assert_eq!(restored_path(&parsed.files[0].path).unwrap(), path);
        std::fs::remove_dir_all(folder).unwrap();
    }
}
