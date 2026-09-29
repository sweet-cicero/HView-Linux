/*
These standard path types keep configuration discovery separate from serialized path text.
Session publication converts native paths only at its checked persistence boundary.
*/
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/*
These constants identify native and legacy files plus the optional Real16 extension.
The parser preserves each established binary offset and signature.
*/
const SAVE_HEADER: &[u8; 16] = b"HViewSav\0\x04\0\0\0\0\x08\x20";
const NATIVE_INI_HEADER: &str = "[HView-Linux 1]";
const REAL16_EXTENSION: usize = 67544;
const REAL16_SIGNATURE: &[u8; 4] = b"R16\x01";
/*
These signatures permit imports from the frozen legacy INI and SAV formats.
They do not define pathname encoding or change native configuration parsing.
*/
const LEGACY_INI_HEADER: &[u8] = &[
    0x5b, 0x48, 0x69, 0x65, 0x77, 0x49, 0x6e, 0x69, 0x20, 0x35, 0x2e, 0x30, 0x33, 0x5d,
];
const LEGACY_SAVE_HEADER: &[u8; 16] = &[
    0x48, 0x69, 0x65, 0x77, 0x53, 0x61, 0x76, 0x65, 0, 4, 0, 0, 0, 0, 8, 0x20,
];

/*
AutoFlag stores explicit On or Off choices and a context-dependent Auto choice.
Configuration consumers supply the value used for Auto.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoFlag {
    Auto,
    On,
    Off,
}

/*
This implementation resolves an AutoFlag without modifying configuration state.
The caller supplies the context-specific automatic value.
*/
impl AutoFlag {
    /*
    This resolver returns the explicit flag value or its caller-supplied automatic value.
    It does not change the stored configuration.
    */
    pub fn resolve(self, auto: bool) -> bool {
        match self {
            Self::Auto => auto,
            Self::On => true,
            Self::Off => false,
        }
    }
}

/*
LineFeed records automatic detection or one explicit byte delimiter.
Editor creation resolves Auto before it stores a delimiter slice.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineFeed {
    Auto,
    CrLf,
    Cr,
    Lf,
}

/*
Config stores all implemented native and legacy configuration settings.
Later view and session builders copy only the fields that they own.
*/
#[derive(Debug)]
pub struct Config {
    pub start_mode: String,
    pub wrap: AutoFlag,
    pub tab: AutoFlag,
    pub line_feed: LineFeed,
    pub auto_code_size: bool,
    pub default_code_size: u32,
    pub disassembly_syntax: crate::decoder::Syntax,
    pub invalid_code_bytes: bool,
    pub opcode_show_bytes: usize,
    pub hex_delimiter: u8,
    pub show_offset_local: bool,
    pub pack_nops: bool,
    pub pack_int3: bool,
    pub savefile_at_exit: bool,
    pub savefile: String,
}

/*
The default configuration matches the current Linux startup behavior.
Intel syntax and local offsets remain active unless a valid file changes them.
*/
impl Default for Config {
    fn default() -> Self {
        Self {
            start_mode: "Text".into(),
            wrap: AutoFlag::Auto,
            tab: AutoFlag::Auto,
            line_feed: LineFeed::Auto,
            auto_code_size: true,
            default_code_size: 16,
            disassembly_syntax: crate::decoder::Syntax::Intel,
            invalid_code_bytes: false,
            opcode_show_bytes: 15,
            hex_delimiter: b'-',
            show_offset_local: true,
            pack_nops: true,
            pack_int3: true,
            savefile_at_exit: false,
            savefile: "hview-linux.sav".into(),
        }
    }
}

/*
TextOptions contains the resolved text classification and display settings for one byte buffer.
Config::new_view applies these values to a new Editor.
*/
#[derive(Debug)]
pub struct TextOptions {
    pub is_text: bool,
    pub wrap: bool,
    pub tab: bool,
    pub line_feed: LineFeed,
}

/*
These methods convert configuration into buffered Editor settings.
They keep text detection separate from general view construction.
*/
impl Config {
    /*
    This builder creates one buffered Editor and applies resolved configuration fields.
    It rejects unsupported UTF-16 only when the requested mode needs Text display.
    */
    pub fn new_view(
        &self,
        data: Vec<u8>,
        mode: crate::editor::Mode,
        offset: u64,
    ) -> Result<crate::editor::Editor, String> {
        /*
        Text inspection selects delimiter, wrap, and tab behavior before Editor creation.
        Non-Text modes can continue with binary defaults when text inspection fails.
        */
        use crate::editor::{Editor, Mode};
        let text = match self.text_options(&data) {
            Ok(text) => text,
            Err(error) if mode == Mode::Text => return Err(error),
            Err(_) => TextOptions {
                is_text: false,
                wrap: self.wrap.resolve(true),
                tab: self.tab.resolve(false),
                line_feed: LineFeed::CrLf,
            },
        };

        /*
        The next section copies common display and decoder settings into the new Editor.
        Format metadata can select a code width when automatic detection is enabled.
        */
        let mut view = Editor::new(data, mode, offset);
        view.wrap = text.wrap;
        view.expand_tabs = text.tab;
        view.is_text = text.is_text;
        view.syntax = self.disassembly_syntax;
        view.invalid_code_bytes = self.invalid_code_bytes;
        view.delimiter = match text.line_feed {
            LineFeed::Cr => b"\r",
            LineFeed::Lf => b"\n",
            _ => b"\r\n",
        };
        view.hex_delimiter = crate::editor::cp437(self.hex_delimiter);
        view.opcode_bytes = self.opcode_show_bytes;
        view.pack_nops = self.pack_nops;
        view.pack_int3 = self.pack_int3;
        let automatic = crate::format::code_address(&view.data, offset)
            .map(|value| value.1)
            .unwrap_or(self.default_code_size);
        view.code_bits = if self.auto_code_size && automatic != 16 {
            automatic
        } else {
            self.default_code_size
        };

        /*
        Text mode aligns the selected byte with its resolved visible row.
        Other modes keep the initial offset supplied by the caller.
        */
        if mode == Mode::Text {
            view.offset = offset;
            view.goto(offset, 1);
            view.offset = view.top;
        }
        Ok(view)
    }

    /*
    This classifier inspects a bounded prefix for text bytes and UTF-16 patterns.
    It resolves automatic line-feed, wrap, and tab choices for Editor creation.
    */
    pub fn text_options(&self, data: &[u8]) -> Result<TextOptions, String> {
        let sample = &data[..data.len().min(1024)];
        let is_text = !data.is_empty() && sample.iter().all(|&byte| byte >= 8);
        if utf16_text(sample) {
            return Err("UTF-16 text display is not supported. Use Hex or Code mode.".into());
        }
        let line_feed = if self.line_feed != LineFeed::Auto {
            self.line_feed
        } else if is_text {
            detect_line_feed(data)
        } else {
            LineFeed::CrLf
        };
        Ok(TextOptions {
            is_text,
            wrap: self.wrap.resolve(!is_text),
            tab: self.tab.resolve(is_text),
            line_feed,
        })
    }
}

/*
This detector recognizes UTF-16 byte-order marks and common zero-byte patterns.
It uses a bounded prefix and does not decode the complete text.
*/
fn utf16_text(data: &[u8]) -> bool {
    if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        return true;
    }
    let pairs = data.len().min(128) / 2;
    if pairs < 4 {
        return false;
    }
    let even_zero = data[..pairs * 2]
        .iter()
        .step_by(2)
        .filter(|&&byte| byte == 0)
        .count();
    let odd_zero = data[1..pairs * 2]
        .iter()
        .step_by(2)
        .filter(|&&byte| byte == 0)
        .count();
    let text_byte = |byte: &&u8| matches!(**byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e);
    let even_text = data[..pairs * 2]
        .iter()
        .step_by(2)
        .filter(text_byte)
        .count();
    let odd_text = data[1..pairs * 2]
        .iter()
        .step_by(2)
        .filter(text_byte)
        .count();
    (even_zero * 4 >= pairs * 3 && odd_text * 4 >= pairs * 3)
        || (odd_zero * 4 >= pairs * 3 && even_text * 4 >= pairs * 3)
}

/*
This detector returns the first line-feed style found in a bounded prefix.
CRLF remains the fallback when the sample has no delimiter.
*/
pub fn detect_line_feed(data: &[u8]) -> LineFeed {
    for pair in data[..data.len().min(512)].windows(2) {
        if pair[0] == b'\r' {
            return if pair[1] == b'\n' {
                LineFeed::CrLf
            } else {
                LineFeed::Cr
            };
        }
        if pair[0] == b'\n' {
            return LineFeed::Lf;
        }
    }
    LineFeed::CrLf
}

/*
This loader reads one selected INI file and passes its bytes to the shared parser.
The error identifies the file-read stage separately from parsing.
*/
pub fn load(path: &Path) -> Result<Config, String> {
    let data = std::fs::read(path).map_err(|error| format!("Cannot read the INI file: {error}"))?;
    parse(&data)
}

/*
This discovery helper returns configuration candidates in precedence order.
Portable mode stops after the executable sibling, while normal mode adds one XDG path.
*/
pub fn configuration_paths(
    executable: &Path,
    portable: bool,
    xdg_config_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Vec<PathBuf> {
    let mut paths = vec![executable.with_file_name("hview-linux.ini")];
    if portable {
        return paths;
    }
    if let Some(root) = xdg_config_home.filter(|root| Path::new(root).is_absolute()) {
        paths.push(PathBuf::from(root).join("hview-linux/hview-linux.ini"));
    } else if let Some(root) = home.filter(|root| !root.is_empty()) {
        paths.push(PathBuf::from(root).join(".config/hview-linux/hview-linux.ini"));
    }
    paths
}

/*
This parser accepts the native UTF-8 format and the frozen legacy byte format.
It validates each line before it changes the configuration result.
*/
pub fn parse(data: &[u8]) -> Result<Config, String> {
    /*
    The header prefix selects native or legacy decoding and line-ending rules.
    Native input must contain valid UTF-8 and no null character.
    */
    let native = data.starts_with(NATIVE_INI_HEADER.as_bytes());
    if !native
        && data
            .iter()
            .enumerate()
            .any(|(index, byte)| *byte == b'\n' && (index == 0 || data[index - 1] != b'\r'))
    {
        return Err(
            "ini-file (line 0): Use [HView-Linux 1] for UTF-8 and LF configuration files.".into(),
        );
    }
    let text = if native {
        std::str::from_utf8(data)
            .map_err(|_| "configuration (line 0): The file is not valid UTF-8.".to_owned())?
            .to_owned()
    } else {
        data.iter().map(|&byte| byte as char).collect()
    };
    if native && text.contains('\0') {
        return Err("configuration (line 0): The file contains a null character.".into());
    }
    let mut config = Config::default();
    let mut header = false;
    /*
    Native input accepts LF with an optional CR.
    The legacy reader splits physical lines only at CRLF and stops at isolated control delimiters.
    */
    let physical_lines: Vec<&str> = if native {
        text.split('\n').collect()
    } else {
        text.split("\r\n").collect()
    };
    for (index, physical) in physical_lines.into_iter().enumerate() {
        /*
        Each iteration removes comments outside quotes and skips an empty physical line.
        The local error helper adds the source format and line number.
        */
        let line_no = index + 1;
        let physical = if native {
            physical.strip_suffix('\r').unwrap_or(physical)
        } else {
            physical.split(['\r', '\n', '\0']).next().unwrap_or("")
        };
        let mut quoted = false;
        let end = physical
            .char_indices()
            .find_map(|(pos, c)| {
                if c == '"' {
                    quoted = !quoted;
                }
                if c == ';' && !quoted { Some(pos) } else { None }
            })
            .unwrap_or(physical.len());
        let line = physical[..end].trim_matches(|c: char| c.is_ascii_whitespace());
        if line.is_empty() {
            continue;
        }
        let error = |reason: &str| {
            let name = if native { "configuration" } else { "ini-file" };
            format!("{name} (line {line_no}): {reason}")
        };

        /*
        The first meaningful line must contain the selected format header.
        Later lines continue through keyword and value validation.
        */
        if !header {
            let valid = if native {
                line == NATIVE_INI_HEADER
            } else {
                line == "[HViewIni 5.03]" || line.as_bytes() == LEGACY_INI_HEADER
            };
            if !valid {
                return Err(error("Invalid header"));
            }
            header = true;
            continue;
        }

        /*
        Keyword validation uses the frozen checksum table and one native extension.
        Value helpers then parse numeric, word, flag, or Boolean forms consistently.
        */
        let key_end = line
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(line.len());
        let key = line[..key_end].to_ascii_uppercase();
        const KEYS: &[u32] = include!("../assets/config_keys.rs");
        if !KEYS.contains(&crate::checksum::checksum(key.as_bytes()))
            && !(native && key == "INVALIDCODE")
        {
            return Err(error("Invalid keyword"));
        }
        let rest = line[key_end..].trim_start_matches(|c: char| c.is_ascii_whitespace());
        let value = rest
            .strip_prefix('=')
            .ok_or_else(|| error("Syntax error"))?
            .trim_matches(|c: char| c.is_ascii_whitespace());
        let numeric = || parse_number(value).map_err(&error);
        let word = || -> Result<String, String> {
            let end = value
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(value.len());
            if !value[end..].trim().is_empty() {
                return Err(error("Syntax error"));
            }
            Ok(value[..end].to_ascii_uppercase())
        };
        let flag = || -> Result<AutoFlag, String> {
            match word()?.as_str() {
                "AUTO" => Ok(AutoFlag::Auto),
                "ON" => Ok(AutoFlag::On),
                "OFF" => Ok(AutoFlag::Off),
                _ => Err(error("Illegal value")),
            }
        };
        let boolean = || -> Result<bool, String> {
            match flag()? {
                AutoFlag::On => Ok(true),
                AutoFlag::Off => Ok(false),
                AutoFlag::Auto => Err(error("Illegal value")),
            }
        };

        /*
        This dispatch applies one validated setting to the result.
        Unsupported keywords and values stop parsing with their current line number.
        */
        match key.as_str() {
            "STARTMODE" => {
                config.start_mode = match word()?.as_str() {
                    "TEXT" => "Text",
                    "HEX" => "Hex",
                    "CODE" => "Code",
                    _ => return Err(error("Illegal value")),
                }
                .into()
            }
            "WRAP" => config.wrap = flag()?,
            "TAB" => config.tab = flag()?,
            "LINEFEED" => {
                config.line_feed = match word()?.as_str() {
                    "AUTO" => LineFeed::Auto,
                    "CRLF" => LineFeed::CrLf,
                    "CR" => LineFeed::Cr,
                    "LF" => LineFeed::Lf,
                    _ => return Err(error("Illegal value")),
                }
            }
            "AUTOCODESIZE" => config.auto_code_size = boolean()?,
            "DEFAULTCODESIZE" => {
                let number = numeric()?;
                if ![16, 32, 64].contains(&number) {
                    return Err(error("Illegal value"));
                }
                config.default_code_size = number;
            }
            "DISASSEMBLYSYNTAX" => {
                config.disassembly_syntax = match word()?.as_str() {
                    "INTEL" => crate::decoder::Syntax::Intel,
                    "ATT" => crate::decoder::Syntax::Att,
                    _ => return Err(error("Illegal value")),
                }
            }
            "INVALIDCODE" if native => {
                config.invalid_code_bytes = match word()?.as_str() {
                    "ERROR" => false,
                    "BYTE" => true,
                    _ => return Err(error("Illegal value")),
                }
            }
            "OPCODESHOWBYTES" => {
                let number = numeric()?;
                if number > 15 {
                    return Err(error("Illegal value"));
                }
                config.opcode_show_bytes = number as usize;
            }
            "HEXDELIMITERCHAR" => {
                let number = numeric()?;
                if !(1..=255).contains(&number) {
                    return Err(error("Illegal value"));
                }
                config.hex_delimiter = number as u8;
            }
            "SHOWOFFSET" => {
                config.show_offset_local = match word()?.as_str() {
                    "LOCAL" => true,
                    "GLOBAL" => false,
                    _ => return Err(error("Illegal value")),
                };
                if !config.show_offset_local {
                    return Err(error("ShowOffset=Global is not reconstructed."));
                }
            }
            "PACKNOPS" => config.pack_nops = boolean()?,
            "PACKINT3" => config.pack_int3 = boolean()?,
            "SAVEFILEATEXIT" => config.savefile_at_exit = boolean()?,
            "SAVEFILE" => {
                if !value.starts_with('"') {
                    return Err(error("Illegal value"));
                }
                let end = value[1..]
                    .find('"')
                    .map(|pos| pos + 1)
                    .ok_or_else(|| error("Syntax error"))?;
                if end + 1 != value.len() {
                    return Err(error("Syntax error"));
                }
                if !native && end - 1 > 260 {
                    return Err(error("Illegal value"));
                }
                if !native && !value[1..end].is_ascii() {
                    return Err(error("Non-ASCII save paths are not reconstructed."));
                }
                config.savefile = value[1..end].into();
            }
            _ => return Err(error(&format!("Setting {key} is not reconstructed."))),
        }
    }
    if !header {
        let name = if native { "configuration" } else { "ini-file" };
        return Err(format!("{name} (line 0): Invalid header"));
    }
    Ok(config)
}

/*
This numeric parser accepts signed decimal, octal, and hexadecimal configuration values.
It rejects trailing text and preserves the legacy wrapping result for negative values.
*/
fn parse_number(text: &str) -> Result<u32, &'static str> {
    let (negative, text) = if let Some(tail) = text.strip_prefix('-') {
        (true, tail)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    };
    let (radix, digits) = if text.starts_with("0x") || text.starts_with("0X") {
        (16, &text[2..])
    } else if text.starts_with('0') {
        (8, text)
    } else {
        (10, text)
    };
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    if end == 0 {
        return if text.is_empty() {
            Ok(0)
        } else {
            Err("Syntax error")
        };
    }
    if !digits[end..].trim().is_empty() {
        return Err("Syntax error");
    }
    let Ok(value) = u32::from_str_radix(&digits[..end], radix) else {
        return Ok(u32::MAX);
    };
    Ok(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/*
This decoder validates one SAV wrapper and returns its uncompressed legacy payload.
The bounded output size prevents an untrusted header from causing excessive allocation.
*/
pub fn decode_saved(data: &[u8]) -> Result<Vec<u8>, String> {
    /*
    The first section validates signatures and reads the fixed wrapper fields.
    Native SAV wrappers later require exact length and checksum matches.
    */
    let legacy = data.get(..16) == Some(LEGACY_SAVE_HEADER);
    if data.get(..16) != Some(SAVE_HEADER) && !legacy {
        return Err("The save file has an invalid signature.".into());
    }
    if data.get(16..20) != Some(b"BLZ\x01") || data.len() < 32 {
        return Err("The save file has an invalid BLZ header.".into());
    }
    let field = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    let size = field(20);
    let compressed_size = field(24);
    // ponytail: Save payloads are limited to 16 MiB. Add a caller limit for larger verified state formats.
    if size > 16 * 1024 * 1024 {
        return Err("The save payload exceeds the supported size limit.".into());
    }

    /*
    An uncompressed wrapper returns its exact payload after native integrity checks.
    Legacy input retains its established missing-checksum behavior.
    */
    if compressed_size == 0 {
        let output = data
            .get(32..32 + size)
            .ok_or("The save payload is truncated.")?;
        if !legacy {
            if data.len() != 32 + size {
                return Err("The save payload length is invalid.".into());
            }
            if crate::checksum::checksum(output) != field(28) as u32 {
                return Err("The save payload checksum is invalid.".into());
            }
        }
        return Ok(output.to_vec());
    }
    if compressed_size != data.len() - 32 {
        return Err("The save payload length is invalid.".into());
    }

    /*
    Compressed input uses the BLZ bit reader to append literals or prior-byte matches.
    Every distance and length must remain inside the declared output.
    */
    let mut reader = Bits {
        data: &data[32..],
        pos: 0,
        tag: 0,
        remaining: 0,
    };
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| "Cannot allocate the save payload.")?;
    if size != 0 {
        output.push(reader.byte()?);
    }
    while output.len() < size {
        if !reader.bit()? {
            output.push(reader.byte()?);
            continue;
        }
        let length = reader
            .number()?
            .checked_add(2)
            .ok_or("Invalid BLZ match length.")?;
        let high = reader.number()?;
        let low = reader.byte()? as usize;
        let distance = high
            .checked_mul(256)
            .and_then(|value| value.checked_add(low))
            .and_then(|value| value.checked_sub(511))
            .ok_or("Invalid BLZ match distance.")?;
        if distance == 0 || distance > output.len() || length > size - output.len() {
            return Err("The save payload has an invalid match.".into());
        }
        for _ in 0..length {
            output.push(output[output.len() - distance]);
        }
    }

    /*
    The final checksum validates the complete reconstructed payload before publication.
    A successful result owns exactly the declared byte count.
    */
    if crate::checksum::checksum(&output) != field(28) as u32 {
        return Err("The save payload checksum is invalid.".into());
    }
    Ok(output)
}

/*
SavedFile contains parsed view metadata for one legacy session slot.
The payload remains in SavedState so updates can preserve unknown bytes.
*/
#[derive(Debug)]
pub struct SavedFile {
    pub path: String,
    pub mode: u32,
    pub offset: u64,
    pub top: u64,
    pub code_bits: u32,
    pub real_mode: bool,
    pub wrap: bool,
    pub tab: bool,
    pub line_feed: LineFeed,
    pub text_column: usize,
    pub local_offset: bool,
}

/*
SessionView carries file-view state without any file contents.
Buffered and paged views convert into this record before SAV mutation.
The path remains a checked legacy string only inside the persistence boundary.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionView {
    pub(crate) path: String,
    pub(crate) mode: crate::editor::Mode,
    pub(crate) offset: u64,
    pub(crate) top: u64,
    pub(crate) code_bits: u32,
    pub(crate) real_mode: bool,
    pub(crate) wrap: bool,
    pub(crate) tab: bool,
    pub(crate) line_feed: LineFeed,
    pub(crate) text_column: usize,
    pub(crate) local_offset: bool,
}

/*
These constructors create content-free view records from active or inactive sources.
The records become SAV fields only through SavedState methods.
*/
impl SessionView {
    /*
    This conversion copies the existing buffered view fields into bounded session state.
    It resolves the editor delimiter before the SAV writer changes any payload bytes.
    */
    pub(crate) fn from_editor(
        path: String,
        view: &crate::editor::Editor,
        local_offset: bool,
    ) -> Result<Self, String> {
        let line_feed = match view.delimiter {
            b"\r\n" => LineFeed::CrLf,
            b"\r" => LineFeed::Cr,
            b"\n" => LineFeed::Lf,
            _ => return Err("The saved line-feed mode is not reconstructed.".into()),
        };
        Ok(Self {
            path,
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
    This constructor gives an unopened file the same configured initial view fields.
    A later open validates and clamps the recorded u64 position against the current source.
    */
    fn initial(path: String, config: &Config, mode: crate::editor::Mode, offset: u64) -> Self {
        Self {
            path,
            mode,
            offset,
            top: match mode {
                crate::editor::Mode::Hex => offset / 16 * 16,
                crate::editor::Mode::Code => offset,
                crate::editor::Mode::Text => 0,
            },
            code_bits: config.default_code_size,
            real_mode: false,
            wrap: config.wrap.resolve(true),
            tab: config.tab.resolve(false),
            line_feed: match config.line_feed {
                LineFeed::Cr | LineFeed::Lf | LineFeed::CrLf => config.line_feed,
                LineFeed::Auto => LineFeed::CrLf,
            },
            text_column: 0,
            local_offset: config.show_offset_local,
        }
    }
}

/*
SavedState owns parsed file records and the original mutable legacy payload.
Writers update defined fields in place so unknown payload bytes remain available.
*/
#[derive(Debug)]
pub struct SavedState {
    pub active_index: usize,
    pub files: Vec<SavedFile>,
    pub payload: Vec<u8>,
}

/*
These methods construct and update defined legacy session fields.
They preserve unknown payload data and reject unsupported paths before mutation.
*/
impl SavedState {
    /*
    Both storage forms use one bounded session-record path.
    The active buffered wrapper preserves its existing Editor-facing API.
    Inactive small files keep their prior content-based initialization.
    Inactive large files use captured length without a complete-file read.
    */
    #[cfg(test)]
    pub fn new_files(
        paths: &[std::path::PathBuf],
        active_index: usize,
        view: &crate::editor::Editor,
        config: &Config,
        startup_mode: crate::editor::Mode,
        startup_offset: Option<&crate::cli::Offset>,
    ) -> Result<Self, String> {
        if paths.is_empty() || paths.len() > 24 || active_index >= paths.len() {
            return Err("A save state supports 1 to 24 files and a valid active index.".into());
        }
        let active_path = Self::saved_path(&paths[active_index])?;
        let current = SessionView::from_editor(active_path, view, config.show_offset_local)?;
        Self::new_session_files(
            paths,
            active_index,
            &current,
            config,
            startup_mode,
            startup_offset,
        )
    }

    /*
    This constructor creates one SAV record per native path without retaining file contents.
    The selected view supplies its current u64 state.
    Each inactive source selects buffered or paged initialization from one opened descriptor.
    */
    pub(crate) fn new_session_files(
        paths: &[std::path::PathBuf],
        active_index: usize,
        current: &SessionView,
        config: &Config,
        startup_mode: crate::editor::Mode,
        startup_offset: Option<&crate::cli::Offset>,
    ) -> Result<Self, String> {
        if paths.is_empty() || paths.len() > 24 || active_index >= paths.len() {
            return Err("A save state supports 1 to 24 files and a valid active index.".into());
        }
        let active_path = Self::saved_path(&paths[active_index])?;
        if current.path != active_path {
            return Err("The saved view path does not match the selected file.".into());
        }

        /*
        This section converts each native path before any SAV payload exists.
        Inactive files receive bounded initial state from their selected storage form.
        */
        let mut views = Vec::with_capacity(paths.len());
        for (index, path) in paths.iter().enumerate() {
            let text_path = Self::saved_path(path)?;
            if index == active_index {
                views.push(current.clone());
            } else {
                views.push(initial_session_view(
                    path,
                    text_path,
                    config,
                    startup_mode,
                    startup_offset,
                )?);
            }
        }

        /*
        The final section creates each fixed session slot and selects the active record.
        The shared writer applies the current u64 view metadata last.
        */
        let mut state = Self::new_session_single(&views[0], config)?;
        for view in &views[1..] {
            state.add_session_view_in_place(view, config)?;
        }
        state.write_session_view(active_index, current)?;
        Ok(state)
    }

    /*
    This wrapper converts a buffered Editor before it adds one SAV record.
    Existing callers keep their current API and serialized fields.
    */
    #[cfg(test)]
    pub fn add_file(
        &mut self,
        path: &str,
        view: &crate::editor::Editor,
        config: &Config,
    ) -> Result<usize, String> {
        let session = SessionView::from_editor(path.to_owned(), view, config.show_offset_local)?;
        self.add_session_view_in_place(&session, config)
    }

    /*
    This helper appends one content-free session record.
    It builds the new record before it changes the retained SAV payload.
    */
    fn add_session_view_in_place(
        &mut self,
        view: &SessionView,
        config: &Config,
    ) -> Result<usize, String> {
        let index = self.files.len();
        if index >= 24 {
            return Err("A save state supports no more than 24 files.".into());
        }
        let base = 8 + index * 2814;
        if self.payload.len() < base + 2814 {
            return Err("The saved file record is truncated.".into());
        }
        let record = Self::new_session_single(view, config)?;
        set_real16(&mut self.payload, index, view.real_mode)?;
        self.payload[base..base + 2814].copy_from_slice(&record.payload[8..8 + 2814]);
        self.files.extend(record.files);
        put32(&mut self.payload, 4, self.files.len() as u32);
        Ok(index)
    }

    /*
    Paged callers add their small view record through this public crate boundary.
    The caller validates path representation before it requests this mutation.
    */
    pub(crate) fn add_session_view(
        &mut self,
        view: &SessionView,
        config: &Config,
    ) -> Result<usize, String> {
        self.add_session_view_in_place(view, config)
    }

    /*
    This validator enforces the current legacy ASCII path field limit.
    Later OEM support will replace this temporary non-ASCII limit.
    */
    pub fn validate_path(path: &str) -> Result<(), String> {
        if !path.is_ascii() || path.len() >= 260 || path.as_bytes().contains(&0) {
            return Err("The saved path must contain fewer than 260 ASCII bytes.".into());
        }
        Ok(())
    }

    /*
    This converter makes one native path absolute before legacy string validation.
    A failed conversion returns without mutating session state.
    */
    pub fn saved_path(path: &Path) -> Result<String, String> {
        let absolute = std::path::absolute(path)
            .map_err(|error| format!("Cannot make the saved path absolute: {error}"))?;
        let text = absolute
            .to_str()
            .ok_or("The saved path is not valid UTF-8.")?;
        Self::validate_path(text)?;
        Ok(text.into())
    }

    /*
    This updater validates a replacement path before changing its record bytes.
    It clears the fixed field and copies only the new path bytes.
    */
    pub fn update_path(&mut self, index: usize, path: &str) -> Result<(), String> {
        Self::validate_path(path)?;
        let file = self
            .files
            .get_mut(index)
            .ok_or("The saved file index is invalid.")?;
        let base = 8 + index * 2814;
        let raw_path = self
            .payload
            .get_mut(base..base + 260)
            .ok_or("The saved file record is truncated.")?;
        raw_path.fill(0);
        raw_path[..path.len()].copy_from_slice(path.as_bytes());
        file.path = path.into();
        Ok(())
    }

    /*
    This shared writer changes only defined fields in one existing SAV record.
    Unknown payload bytes remain unchanged.
    The active index changes only after all supplied fields pass validation.
    */
    fn write_session_view(&mut self, index: usize, view: &SessionView) -> Result<(), String> {
        Self::validate_path(&view.path)?;
        if ![16, 32, 64].contains(&view.code_bits) {
            return Err("The saved code width must be 16, 32, or 64 bits.".into());
        }
        if view.line_feed == LineFeed::Auto {
            return Err("The saved line-feed mode is not reconstructed.".into());
        }
        let file = self
            .files
            .get_mut(index)
            .ok_or("The saved file index is invalid.")?;
        if file.path != view.path {
            return Err("The saved view path does not match the selected file.".into());
        }
        let base = 8 + index * 2814;
        if self.payload.len() < base + 2814 {
            return Err("The saved file record is truncated.".into());
        }

        /*
        The metadata section updates the in-memory record and matching fixed payload fields.
        Real16 uses its separate bitmap while unknown record bytes remain unchanged.
        */
        set_real16(&mut self.payload, index, view.real_mode)?;
        file.mode = match view.mode {
            crate::editor::Mode::Text => 1,
            crate::editor::Mode::Hex => 2,
            crate::editor::Mode::Code => 3,
        };
        file.offset = view.offset;
        file.top = view.top;
        file.code_bits = view.code_bits;
        file.real_mode = view.real_mode;
        file.wrap = view.wrap;
        file.tab = view.tab;
        file.line_feed = view.line_feed;
        file.text_column = view.text_column;
        file.local_offset = view.local_offset;
        self.active_index = index;
        put32(&mut self.payload, 0, index as u32);
        for (offset, value) in [(352, file.top), (376, file.offset)] {
            self.payload[base + offset..base + offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (2772, file.mode),
            (
                2776,
                match file.line_feed {
                    LineFeed::CrLf => 0,
                    LineFeed::Cr => 1,
                    LineFeed::Lf => 2,
                    LineFeed::Auto => unreachable!(),
                },
            ),
            (2780, file.text_column as u32),
            (2784, file.code_bits),
            (2792, if file.local_offset { u32::MAX } else { 0 }),
        ] {
            put32(&mut self.payload, base + offset, value);
        }
        self.payload[base + 2808] = if file.wrap { b'Y' } else { b'N' };
        self.payload[base + 2809] = if file.tab { b'Y' } else { b'N' };
        Ok(())
    }

    /*
    This wrapper preserves the existing buffered update interface.
    It copies the stored path and offset-display setting before mutable payload access.
    */
    #[cfg(test)]
    pub fn update_view(
        &mut self,
        index: usize,
        view: &crate::editor::Editor,
    ) -> Result<(), String> {
        let file = self
            .files
            .get(index)
            .ok_or("The saved file index is invalid.")?;
        let session = SessionView::from_editor(file.path.clone(), view, file.local_offset)?;
        self.write_session_view(index, &session)
    }

    /*
    This entry point updates one paged session record without file bytes.
    The shared writer preserves the same fields and unknown payload data.
    */
    pub(crate) fn update_session_view(
        &mut self,
        index: usize,
        view: &SessionView,
    ) -> Result<(), String> {
        self.write_session_view(index, view)
    }

    /*
    This buffered wrapper preserves all existing constructors and tests.
    It converts the Editor before the shared content-free constructor runs.
    */
    #[cfg(test)]
    pub fn new_single(
        path: &str,
        view: &crate::editor::Editor,
        config: &Config,
    ) -> Result<Self, String> {
        let session = SessionView::from_editor(path.to_owned(), view, config.show_offset_local)?;
        Self::new_session_single(&session, config)
    }

    /*
    This constructor applies a small view record to one empty SAV payload.
    The following empty-payload helper retains the exact legacy layout.
    */
    fn new_session_single(view: &SessionView, config: &Config) -> Result<Self, String> {
        let mut state = Self::empty_single(&view.path, config)?;
        state.write_session_view(0, view)?;
        Ok(state)
    }

    /*
    This helper creates the established legacy payload and its unchanged default ranges.
    It writes no view-specific fields until the shared session writer runs.
    */
    fn empty_single(path: &str, config: &Config) -> Result<Self, String> {
        Self::validate_path(path)?;
        /*
        The original layout allocates 67,578 state bytes and 36,208 empty history bytes.
        Initial fixed fields follow the frozen Windows payload offsets.
        */
        let mut payload = vec![0; 105916];
        put32(&mut payload, 4, 1);
        payload[8..8 + path.len()].copy_from_slice(path.as_bytes());
        /*
        These ranges contain empty position lists and block selections.
        The all-one value marks each unused entry in the legacy layout.
        */
        for (start, end) in [(408, 1384), (2664, 2672), (2720, 2744), (2752, 2760)] {
            payload[8 + start..8 + end].fill(0xff);
        }
        for (offset, value) in [
            (2704, 1),
            (2712, 1),
            (2768, 1),
            (2772, 1),
            (2784, 16),
            (2800, 1),
        ] {
            put32(&mut payload, 8 + offset, value);
        }
        put32(
            &mut payload,
            8 + 2792,
            if config.show_offset_local {
                u32::MAX
            } else {
                0
            },
        );
        payload[8 + 2811] = 0xff;
        put32(&mut payload, 67556, config.opcode_show_bytes as u32);
        /*
        These defaults come from address 0x416A10 and the pristine data tables.
        The final parse verifies that the constructed payload remains readable.
        */
        put32(&mut payload, 67564, 1);
        put32(&mut payload, 67572, 1);
        put32(&mut payload, 67578, 1);
        payload[67802] = b'*';
        put32(&mut payload, 67802 + 1862, u32::MAX);
        put32(&mut payload, 67802 + 1866, 4);
        put32(&mut payload, 67802 + 1870, 1);
        parse_saved(&encode_saved(&payload)?)
    }
}

/*
This helper initializes one inactive file without retaining its contents.
Small files keep content-based mode behavior.
Large files keep only configured fields and a u64 startup position.
*/
fn initial_session_view(
    path: &Path,
    text_path: String,
    config: &Config,
    startup_mode: crate::editor::Mode,
    startup_offset: Option<&crate::cli::Offset>,
) -> Result<SessionView, String> {
    /*
    The common source selector classifies one opened descriptor before initialization.
    Buffered and paged files resolve startup offsets from their current logical bytes.
    Inactive buffered records need no Save descriptor because this function retains only view metadata.
    */
    match crate::paged::open_source(path)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?
    {
        crate::paged::OpenedSource::Buffered { data, .. } => {
            let initial_offset = session_offset(&data, startup_offset);
            let mut initial = config.new_view(data, startup_mode, initial_offset)?;
            initial.top = match startup_mode {
                crate::editor::Mode::Hex => initial_offset / 16 * 16,
                crate::editor::Mode::Code => initial_offset,
                crate::editor::Mode::Text => initial.top,
            };
            SessionView::from_editor(text_path, &initial, config.show_offset_local)
        }
        crate::paged::OpenedSource::Paged(file) => Ok(SessionView::initial(
            text_path,
            config,
            startup_mode,
            session_offset_for_paged(&file, startup_offset),
        )),
    }
}

/*
This helper resolves startup offsets for one inactive buffered file.
It permits format conversion because the complete small byte buffer is available.
*/
fn session_offset(data: &[u8], offset: Option<&crate::cli::Offset>) -> u64 {
    let requested = offset.and_then(|offset| {
        match offset.target {
            crate::cli::OffsetTarget::File(value) => Ok(value),
            crate::cli::OffsetTarget::Virtual(value) => crate::format::virtual_to_file(data, value),
            crate::cli::OffsetTarget::EntryPoint => crate::format::entry_point(data),
            crate::cli::OffsetTarget::End => Ok((data.len() as u64).wrapping_sub(1)),
        }
        .ok()
    });
    requested
        .filter(|value| *value < data.len() as u64)
        .unwrap_or(0)
}

/*
This helper resolves one inactive paged startup offset without reading complete source contents.
File and End requests use only length, while virtual and entry requests parse bounded metadata.
*/
fn session_offset_for_paged(
    file: &crate::paged::PagedFile,
    offset: Option<&crate::cli::Offset>,
) -> u64 {
    let requested = offset.and_then(|offset| match offset.target {
        crate::cli::OffsetTarget::File(value) => Some(value),
        crate::cli::OffsetTarget::End => Some(file.len().saturating_sub(1)),
        crate::cli::OffsetTarget::Virtual(value) => crate::format::Metadata::read_from(file)
            .and_then(|metadata| metadata.legacy_virtual_offset(value))
            .ok(),
        crate::cli::OffsetTarget::EntryPoint => crate::format::Metadata::read_from(file)
            .and_then(|metadata| metadata.entry_offset())
            .ok(),
    });
    requested.filter(|value| *value < file.len()).unwrap_or(0)
}

/*
This helper writes one little-endian 32-bit field at a verified legacy payload offset.
Callers validate payload size before they use the helper.
*/
fn put32(payload: &mut [u8], offset: usize, value: u32) {
    payload[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/*
This reader returns the optional Real16 bitmap from its fixed extension.
A nonzero unsupported high byte rejects a corrupt file map.
*/
fn real16_bitmap(payload: &[u8]) -> Result<u32, String> {
    let extension = payload
        .get(REAL16_EXTENSION..REAL16_EXTENSION + 8)
        .ok_or("The save payload is too short for the Real16 extension.")?;
    if &extension[..4] != REAL16_SIGNATURE {
        return Ok(0);
    }
    let bitmap = u32::from_le_bytes(extension[4..8].try_into().unwrap());
    if bitmap >> 24 != 0 {
        return Err("The save payload has an invalid Real16 file bitmap.".into());
    }
    Ok(bitmap)
}

/*
This writer enables or disables one file bit in the Real16 extension.
It creates the signature only when an empty extension first needs Real16.
*/
fn set_real16(payload: &mut [u8], index: usize, enabled: bool) -> Result<(), String> {
    let extension = payload
        .get_mut(REAL16_EXTENSION..REAL16_EXTENSION + 8)
        .ok_or("The save payload is too short for the Real16 extension.")?;
    if &extension[..4] != REAL16_SIGNATURE {
        if !enabled {
            return Ok(());
        }
        if extension.iter().any(|byte| *byte != 0) {
            return Err(
                "The save payload extension area is in use. Real16 cannot be saved.".into(),
            );
        }
        extension[..4].copy_from_slice(REAL16_SIGNATURE);
    }
    let mut bitmap = u32::from_le_bytes(extension[4..8].try_into().unwrap());
    if enabled {
        bitmap |= 1 << index;
    } else {
        bitmap &= !(1 << index);
    }
    extension[4..8].copy_from_slice(&bitmap.to_le_bytes());
    Ok(())
}

/*
This parser converts a validated SAV wrapper into bounded file metadata records.
It retains the complete payload for later field updates and unknown-byte preservation.
*/
pub fn parse_saved(data: &[u8]) -> Result<SavedState, String> {
    /*
    The first section validates payload size, active index, file count, and Real16 extension.
    These values bound every following record slice.
    */
    let payload = decode_saved(data)?;
    if payload.len() < 69708 {
        return Err("The save payload is too short for this HView version.".into());
    }
    let read32 = |pos| u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
    let read64 = |pos| u64::from_le_bytes(payload[pos..pos + 8].try_into().unwrap());
    let active_index = read32(0) as usize;
    let count = read32(4) as usize;
    if count == 0 || count > 24 || active_index >= count {
        return Err("The save file has an invalid file index or count.".into());
    }
    let real16 = real16_bitmap(&payload)?;
    let mut files = Vec::with_capacity(count);
    for index in 0..count {
        /*
        Each iteration validates one fixed path, mode, width, line-feed, and architecture record.
        Valid fields become content-free SavedFile metadata.
        */
        let base = 8 + index * 2814;
        let raw_path = &payload[base..base + 260];
        let end = raw_path
            .iter()
            .position(|&byte| byte == 0)
            .ok_or("The saved file path has no terminator.")?;
        if !raw_path[..end].is_ascii() {
            return Err("Non-ASCII saved file paths are not reconstructed.".into());
        }
        let mode = read32(base + 2772);
        let code_bits = read32(base + 2784);
        if !(1..=3).contains(&mode) || ![16, 32, 64].contains(&code_bits) {
            return Err("The saved file has an unsupported mode or code width.".into());
        }
        let real_mode = real16 & (1 << index) != 0;
        if real_mode && code_bits != 16 {
            return Err("The saved Real16 view has an invalid code width.".into());
        }
        let line_feed = match read32(base + 2776) {
            0 => LineFeed::CrLf,
            1 => LineFeed::Cr,
            2 => LineFeed::Lf,
            _ => return Err("The saved line-feed mode is not reconstructed.".into()),
        };
        if read32(base + 2800) != 1 {
            return Err("The saved decoder architecture is not reconstructed.".into());
        }
        if read32(base + 2792) == 0 {
            return Err("The saved global offset display is not reconstructed.".into());
        }
        files.push(SavedFile {
            path: String::from_utf8(raw_path[..end].to_vec()).unwrap(),
            mode,
            offset: read64(base + 376),
            top: read64(base + 352),
            code_bits,
            real_mode,
            wrap: payload[base + 2808] == b'Y',
            tab: payload[base + 2809] == b'Y',
            line_feed,
            text_column: read32(base + 2780) as usize,
            local_offset: read32(base + 2792) != 0,
        });
    }
    Ok(SavedState {
        active_index,
        files,
        payload,
    })
}

/*
This encoder wraps an unchanged legacy payload in the native SAV header.
It stores an uncompressed body with exact length and checksum fields.
*/
pub fn encode_saved(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > 16 * 1024 * 1024 {
        return Err("The save payload exceeds the supported size limit.".into());
    }
    let mut encoded = Vec::with_capacity(payload.len() + 32);
    encoded.extend_from_slice(SAVE_HEADER);
    encoded.extend_from_slice(b"BLZ\x01");
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&0u32.to_le_bytes());
    encoded.extend_from_slice(&crate::checksum::checksum(payload).to_le_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

/*
Bits tracks byte position and remaining tag bits during BLZ decompression.
Its methods reject truncated input and overflowing encoded numbers.
*/
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    tag: u16,
    remaining: u8,
}

/*
These methods consume BLZ bytes, control bits, and variable-length numbers in order.
Each method advances only its owned reader state.
*/
impl Bits<'_> {
    /*
    This reader consumes one byte and advances the input position.
    It returns a truncation error when no byte remains.
    */
    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or("The save payload is truncated.")?;
        self.pos += 1;
        Ok(byte)
    }

    /*
    This reader reloads a 16-bit tag when necessary and returns its next high bit.
    The shifted tag and remaining count preserve later bit order.
    */
    fn bit(&mut self) -> Result<bool, String> {
        if self.remaining == 0 {
            self.tag = u16::from_le_bytes([self.byte()?, self.byte()?]);
            self.remaining = 16;
        }
        self.remaining -= 1;
        let bit = self.tag & 0x8000 != 0;
        self.tag <<= 1;
        Ok(bit)
    }

    /*
    This reader decodes one variable-length BLZ number from paired control bits.
    Checked multiplication rejects a value that exceeds the host range.
    */
    fn number(&mut self) -> Result<usize, String> {
        let mut value = 1usize;
        loop {
            value = value
                .checked_mul(2)
                .ok_or("The BLZ number exceeds the supported range.")?;
            value += usize::from(self.bit()?);
            if !self.bit()? {
                return Ok(value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /*
    These tests cover configuration parsing, text detection, SAV layout, Real16, and bounded sessions.
    Each fixture uses controlled bytes or disposable files.
    */
    use super::*;

    /*
    This test checks legacy parsing, text classification, line feeds, and numeric forms.
    Each assertion isolates one accepted default or rejected value.
    */
    #[test]
    fn ini_and_text_detection() {
        let config = parse(b" ; comment\r\n [HViewIni 5.03]\r\n StartMode=Hex ; comment\r\nDefaultCodesize=020\r\nHexDelimiterChar=0x7C\r\nOpcodeShowBytes=3\r\n").unwrap();
        assert_eq!(
            (
                config.start_mode.as_str(),
                config.default_code_size,
                config.hex_delimiter,
                config.opcode_show_bytes
            ),
            ("Hex", 16, b'|', 3)
        );
        assert!(
            parse(b"[HViewIni 5.03]\nStartMode=Hex\n")
                .unwrap_err()
                .contains("HView-Linux 1")
        );
        assert_eq!(
            parse(b"[HViewIni 5.03]\r\nStartMode=Hex\r\nStartMode=Text")
                .unwrap()
                .start_mode,
            "Text"
        );
        assert_eq!(
            parse(b"[hviewini 5.03]\r\n").unwrap_err(),
            "ini-file (line 1): Invalid header"
        );
        assert_eq!(
            parse(b"[HViewIni 5.03]\r\nMadeUp=1").unwrap_err(),
            "ini-file (line 2): Invalid keyword"
        );
        assert_eq!(
            parse(b"[HViewIni 5.03]\r\nDefaultCodesize=24").unwrap_err(),
            "ini-file (line 2): Illegal value"
        );
        assert!(
            parse(b"[HViewIni 5.03]\r\nBeep=On")
                .unwrap_err()
                .contains("not reconstructed")
        );
        assert!(
            parse(b"[HViewIni 5.03]\r\nStartMode Hex")
                .unwrap_err()
                .ends_with("Syntax error")
        );
        let options = config.text_options(b"Alpha").unwrap();
        assert!(!options.wrap && options.tab && options.is_text);
        let options = config
            .text_options(&(0..=255).collect::<Vec<u8>>())
            .unwrap();
        assert!(options.wrap && !options.tab && !options.is_text);
        assert!(config.text_options(b"\xff\xfeA\0B\0C\0D\0").is_err());
        assert!(config.text_options(b"A\0B\0C\0D\0").is_err());
        assert!(!config.text_options(&[0; 32]).unwrap().is_text);
        assert!(
            config
                .new_view(vec![0; 32], crate::editor::Mode::Text, 0)
                .is_ok()
        );
        assert_eq!(detect_line_feed(b"a\rb"), LineFeed::Cr);
        assert_eq!(detect_line_feed(b"a\nb"), LineFeed::Lf);
        assert_eq!(detect_line_feed(b"a\r\nb"), LineFeed::CrLf);
        assert_eq!(detect_line_feed(b"a\n"), LineFeed::CrLf);
        assert_eq!(parse_number("-4294967296"), Ok(u32::MAX));
        assert_eq!(
            parse(b"[HViewIni 5.03]\r\nSavefile=\"a;b.sav\"")
                .unwrap()
                .savefile,
            "a;b.sav"
        );
    }

    /*
    This test confirms Intel as the default syntax and AT&T as an explicit option.
    It also keeps invalid-byte fallback unavailable in legacy configuration.
    */
    #[test]
    fn disassembly_syntax_defaults_to_intel_and_accepts_att() {
        assert_eq!(
            Config::default().disassembly_syntax,
            crate::decoder::Syntax::Intel
        );
        let config = parse(b"[HViewIni 5.03]\r\nDisassemblySyntax=ATT").unwrap();
        assert_eq!(config.disassembly_syntax, crate::decoder::Syntax::Att);
        assert!(parse(b"[HViewIni 5.03]\r\nDisassemblySyntax=MASM").is_err());
        assert!(!Config::default().invalid_code_bytes);
        assert!(parse(b"[HViewIni 5.03]\r\nInvalidCode=Byte").is_err());
    }

    /*
    This test checks native UTF-8 text, LF lines, native extensions, and invalid encodings.
    Valid non-ASCII native configuration text remains unchanged.
    */
    #[test]
    fn native_configuration_uses_utf8_and_lf() {
        let config = parse(
            "[HView-Linux 1]\nStartMode=Code\nDisassemblySyntax=ATT\nInvalidCode=Byte\nSaveFile=\"résumé.sav\"\n"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(config.start_mode, "Code");
        assert_eq!(config.disassembly_syntax, crate::decoder::Syntax::Att);
        assert!(config.invalid_code_bytes);
        assert_eq!(config.savefile, "résumé.sav");
        assert!(parse(b"[HView-Linux 1]\nDisassemblySyntax=MASM\n").is_err());
        assert!(parse(b"[HView-Linux 1]\nInvalidCode=Skip\n").is_err());
        let mut invalid = b"[HView-Linux 1]\n;".to_vec();
        invalid.push(0xff);
        assert!(parse(&invalid).unwrap_err().contains("valid UTF-8"));
    }

    /*
    This test checks explicit, portable, XDG, and HOME configuration discovery order.
    Relative XDG paths fall back to the HOME location.
    */
    #[test]
    fn configuration_paths_use_defined_precedence() {
        let executable = Path::new("/opt/hview-linux/bin/hview-linux");
        assert_eq!(
            configuration_paths(
                executable,
                false,
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/user")),
            ),
            [
                PathBuf::from("/opt/hview-linux/bin/hview-linux.ini"),
                PathBuf::from("/xdg/hview-linux/hview-linux.ini"),
            ]
        );
        assert_eq!(
            configuration_paths(executable, false, None, Some(OsStr::new("/home/user"))),
            [
                PathBuf::from("/opt/hview-linux/bin/hview-linux.ini"),
                PathBuf::from("/home/user/.config/hview-linux/hview-linux.ini"),
            ]
        );
        assert_eq!(
            configuration_paths(
                executable,
                true,
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/user")),
            ),
            [PathBuf::from("/opt/hview-linux/bin/hview-linux.ini")]
        );
        for xdg in [OsStr::new("relative"), OsStr::new("")] {
            assert_eq!(
                configuration_paths(executable, false, Some(xdg), Some(OsStr::new("/home/user")),),
                [
                    PathBuf::from("/opt/hview-linux/bin/hview-linux.ini"),
                    PathBuf::from("/home/user/.config/hview-linux/hview-linux.ini"),
                ]
            );
        }
    }

    /*
    This test checks known SAV fixtures, wrapper integrity, and basic parsed file metadata.
    Re-encoding must return the exact original payload.
    */
    #[test]
    fn original_save_payloads() {
        let first = decode_saved(include_bytes!("../tests/fixtures/offset-10.sav")).unwrap();
        let second = decode_saved(include_bytes!("../tests/fixtures/offset-20.sav")).unwrap();
        assert_eq!(first.len(), 105916);
        assert_eq!(second.len(), first.len());
        assert!(
            first[REAL16_EXTENSION..REAL16_EXTENSION + 8]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(u64::from_le_bytes(first[384..392].try_into().unwrap()), 16);
        assert_eq!(u64::from_le_bytes(second[384..392].try_into().unwrap()), 32);
        assert!(decode_saved(b"HViewSav").is_err());
        let mut damaged = include_bytes!("../tests/fixtures/offset-10.sav").to_vec();
        damaged[28] ^= 1;
        assert!(decode_saved(&damaged).unwrap_err().contains("checksum"));
        damaged.truncate(40);
        assert!(decode_saved(&damaged).is_err());
        let state = parse_saved(include_bytes!("../tests/fixtures/offset-10.sav")).unwrap();
        assert_eq!(state.active_index, 0);
        assert!(!state.files.is_empty());
        assert!(state.files[0].path.ends_with("fixture.bin"));
        assert_eq!(
            (
                state.files[0].mode,
                state.files[0].offset,
                state.files[0].code_bits
            ),
            (2, 16, 16)
        );
        assert_eq!(decode_saved(&encode_saved(&first).unwrap()).unwrap(), first);
        let mut empty = first;
        put32(&mut empty, 4, 0);
        assert!(parse_saved(&encode_saved(&empty).unwrap()).is_err());
    }

    /*
    This test checks native output headers and frozen legacy import signatures.
    Native integrity errors remain strict while legacy checksum behavior remains compatible.
    */
    #[test]
    fn new_headers_and_legacy_imports() {
        assert_eq!(Config::default().savefile, "hview-linux.sav");
        let mut ini = LEGACY_INI_HEADER.to_vec();
        ini.extend_from_slice(b"\r\nStartMode=Hex\r\n");
        assert_eq!(parse(&ini).unwrap().start_mode, "Hex");

        let legacy = include_bytes!("../tests/fixtures/offset-10.sav");
        assert_eq!(&legacy[..16], LEGACY_SAVE_HEADER);
        let payload = decode_saved(legacy).unwrap();
        let encoded = encode_saved(&payload).unwrap();
        assert_eq!(&encoded[..16], SAVE_HEADER);
        assert_eq!(decode_saved(&encoded).unwrap(), payload);
        assert_eq!(parse_saved(&encoded).unwrap().payload, payload);
        let mut damaged = encoded.clone();
        damaged[32] ^= 1;
        assert_eq!(
            decode_saved(&damaged).unwrap_err(),
            "The save payload checksum is invalid."
        );
        let mut damaged_header = encoded.clone();
        damaged_header[28] ^= 1;
        assert_eq!(
            decode_saved(&damaged_header).unwrap_err(),
            "The save payload checksum is invalid."
        );
        let mut extended = encoded.clone();
        extended.push(0);
        assert_eq!(
            decode_saved(&extended).unwrap_err(),
            "The save payload length is invalid."
        );
        assert_eq!(
            decode_saved(&encoded[..encoded.len() - 1]).unwrap_err(),
            "The save payload is truncated."
        );

        /*
        Legacy uncompressed imports retain their original checksum policy.
        The converted native wrapper then keeps the same payload.
        */
        damaged[..16].copy_from_slice(LEGACY_SAVE_HEADER);
        assert_eq!(decode_saved(&damaged).unwrap(), damaged[32..]);
        let mut imported = encoded;
        imported[..16].copy_from_slice(LEGACY_SAVE_HEADER);
        assert_eq!(parse_saved(&imported).unwrap().payload, payload);
    }

    /*
    This test changes one saved view and checks that unrelated payload bytes remain identical.
    It also checks multi-file construction and invalid indexes.
    */
    #[test]
    fn saved_view_update_preserves_other_state() {
        use crate::editor::{Editor, Mode};
        let mut view = Editor::new((0..=255).collect(), Mode::Hex, 48);
        let mut state =
            SavedState::new_single("C:\\fixture.bin", &view, &Config::default()).unwrap();
        assert_eq!(state.files[0].offset, 48);
        assert_eq!(state.files[0].mode, 2);
        state.payload[69708] = 0x53;
        let before = state.payload.clone();
        view.offset = 64;
        state.update_view(0, &view).unwrap();
        let differences: Vec<_> = before
            .iter()
            .zip(&state.payload)
            .enumerate()
            .filter_map(|(index, (left, right))| (left != right).then_some(index))
            .collect();
        assert_eq!(differences, vec![384]);
        let parsed = parse_saved(&encode_saved(&state.payload).unwrap()).unwrap();
        assert_eq!(parsed.files[0].offset, 64);
        assert_eq!(parsed.payload[69708], 0x53);
        assert!(state.update_view(24, &view).is_err());
        assert!(SavedState::new_single("bad\0path", &view, &Config::default()).is_err());
        let directory = Path::new(file!())
            .parent()
            .unwrap()
            .join("../tests/fixtures");
        let paths = vec![
            directory.join("offset-10.sav"),
            directory.join("offset-20.sav"),
        ];
        let state =
            SavedState::new_files(&paths, 1, &view, &Config::default(), Mode::Hex, None).unwrap();
        let parsed = parse_saved(&encode_saved(&state.payload).unwrap()).unwrap();
        assert_eq!(parsed.active_index, 1);
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files[0].offset, 0);
        assert_eq!(parsed.files[1].offset, 64);
        assert_eq!(parsed.files[1].mode, 2);
        assert!(SavedState::new_files(&[], 0, &view, &Config::default(), Mode::Hex, None).is_err());
    }

    /*
    This test enables and disables Real16 without changing legacy code widths or unknown extension bytes.
    A conflicting extension prevents unsafe publication.
    */
    #[test]
    fn real16_session_extension_preserves_legacy_widths_and_unknown_data() {
        use crate::editor::{Editor, Mode};
        let mut view = Editor::new(vec![0x90], Mode::Code, 0);
        view.real_mode = true;
        let mut state =
            SavedState::new_single("/tmp/real16.bin", &view, &Config::default()).unwrap();
        assert_eq!(state.files[0].code_bits, 16);
        assert!(state.files[0].real_mode);
        assert_eq!(
            &state.payload[REAL16_EXTENSION..REAL16_EXTENSION + 4],
            REAL16_SIGNATURE
        );
        let parsed = parse_saved(&encode_saved(&state.payload).unwrap()).unwrap();
        assert!(parsed.files[0].real_mode);

        view.real_mode = false;
        state.update_view(0, &view).unwrap();
        assert!(!state.files[0].real_mode);
        let parsed = parse_saved(&encode_saved(&state.payload).unwrap()).unwrap();
        assert!(!parsed.files[0].real_mode);

        let mut ordinary =
            SavedState::new_single("/tmp/ordinary.bin", &view, &Config::default()).unwrap();
        ordinary.payload[REAL16_EXTENSION] = 0x7a;
        let before = ordinary.payload.clone();
        ordinary.update_view(0, &view).unwrap();
        assert_eq!(ordinary.payload[REAL16_EXTENSION], 0x7a);
        view.real_mode = true;
        assert!(ordinary.update_view(0, &view).is_err());
        assert_eq!(ordinary.payload, before);
    }

    /*
    This test gives inactive UTF-16 files the same non-Text view defaults as active files.
    Explicit offsets and unsupported Text mode remain distinct.
    */
    #[test]
    fn inactive_utf16_files_use_the_same_view_options() {
        use crate::editor::Mode;
        let data: Vec<u8> = "\u{feff}Alpha beta gamma delta epsilon zeta eta theta\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let path = std::env::temp_dir().join(format!(
            "hview-config-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, &data).unwrap();
        let paths = vec![std::path::PathBuf::from("C:\\active.bin"), path.clone()];
        let results: Vec<_> = [("Hex", Mode::Hex), ("Code", Mode::Code)]
            .into_iter()
            .map(|(name, mode)| {
                let config = Config {
                    start_mode: name.into(),
                    default_code_size: 32,
                    wrap: AutoFlag::Off,
                    tab: AutoFlag::On,
                    ..Config::default()
                };
                let view = config.new_view(data.to_vec(), mode, 0).unwrap();
                SavedState::new_files(&paths, 0, &view, &config, mode, None)
            })
            .collect();
        let explicit_hex = Config::default();
        let hex_view = explicit_hex.new_view(vec![0], Mode::Hex, 0).unwrap();
        let explicit_offset = crate::cli::Offset {
            mode: 2,
            target: crate::cli::OffsetTarget::File(1),
        };
        let explicit_hex_state = SavedState::new_files(
            &paths,
            0,
            &hex_view,
            &explicit_hex,
            Mode::Hex,
            Some(&explicit_offset),
        )
        .unwrap();
        assert!(explicit_hex_state.files.iter().all(|file| file.mode == 2));
        assert_eq!(explicit_hex_state.files[1].offset, 1);
        std::fs::remove_file(path).unwrap();
        for (result, expected_mode) in results.into_iter().zip([2, 3]) {
            let state = result.unwrap();
            let parsed = parse_saved(&encode_saved(&state.payload).unwrap()).unwrap();
            assert_eq!(parsed.files.len(), 2);
            for file in parsed.files {
                assert_eq!(file.mode, expected_mode);
                assert_eq!(file.code_bits, 32);
                assert!(!file.wrap && file.tab);
                assert_eq!(file.line_feed, LineFeed::CrLf);
            }
        }
        assert!(
            Config::default()
                .new_view(data.to_vec(), Mode::Text, 0)
                .is_err()
        );
    }

    /*
    This test checks startup offsets and visible tops for inactive Hex and Code files.
    Each temporary file is removed after its session state is built.
    */
    #[test]
    fn inactive_session_offsets_keep_the_selected_bytes_visible() {
        use crate::editor::{Editor, Mode};
        let path = std::env::temp_dir().join(format!(
            "hview-offset-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, vec![0; 2048]).unwrap();
        let paths = vec![PathBuf::from("active.bin"), path.clone()];
        let offset = crate::cli::Offset {
            mode: 0,
            target: crate::cli::OffsetTarget::File(0x301),
        };
        for mode in [Mode::Hex, Mode::Code] {
            let view = Editor::new(vec![0; 2048], mode, 0);
            let state =
                SavedState::new_files(&paths, 0, &view, &Config::default(), mode, Some(&offset))
                    .unwrap();
            assert_eq!(state.files[1].offset, 0x301);
            assert_eq!(
                state.files[1].top,
                if mode == Mode::Hex { 0x300 } else { 0x301 }
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    /*
    This sparse inactive source verifies bounded session initialization above 64 MiB.
    The End startup position remains a full u64 value without a complete-file buffer.
    */
    #[test]
    fn large_inactive_session_uses_length_only_state() {
        use crate::editor::{Editor, Mode};
        use std::fs::OpenOptions;

        let path = std::env::temp_dir().join(format!(
            "hview-large-session-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let len = crate::paged::BUFFERED_FILE_LIMIT + 1;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len)
            .unwrap();
        let active = std::path::absolute("active.bin").unwrap();
        let paths = vec![active, path.clone()];
        let view = Editor::new(vec![0], Mode::Hex, 0);
        let offset = crate::cli::Offset {
            mode: 2,
            target: crate::cli::OffsetTarget::End,
        };
        let state = SavedState::new_files(
            &paths,
            0,
            &view,
            &Config::default(),
            Mode::Hex,
            Some(&offset),
        )
        .unwrap();
        assert_eq!(state.files[1].offset, len - 1);
        assert_eq!(state.files[1].top, (len - 1) / 16 * 16);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This content-free record verifies that legacy SAV fields retain high u64 positions.
    Encoding and parsing must not narrow the active paged offset or top value.
    */
    #[test]
    fn paged_session_record_preserves_u64_positions() {
        let path = std::path::absolute("high-offset.bin").unwrap();
        let saved_path = SavedState::saved_path(&path).unwrap();
        let offset = u64::from(u32::MAX) + 0x1234;
        let current = SessionView {
            path: saved_path,
            mode: crate::editor::Mode::Hex,
            offset,
            top: offset / 16 * 16,
            code_bits: 64,
            real_mode: false,
            wrap: false,
            tab: true,
            line_feed: LineFeed::Lf,
            text_column: 7,
            local_offset: true,
        };
        let state = SavedState::new_session_files(
            &[path],
            0,
            &current,
            &Config::default(),
            crate::editor::Mode::Hex,
            None,
        )
        .unwrap();
        let parsed = parse_saved(&encode_saved(&state.payload).unwrap()).unwrap();
        assert_eq!(parsed.files[0].offset, offset);
        assert_eq!(parsed.files[0].top, offset / 16 * 16);
        assert_eq!(parsed.files[0].code_bits, 64);
        assert_eq!(parsed.files[0].line_feed, LineFeed::Lf);
    }

    /*
    This test checks selected-file updates, new session slots, and path replacement.
    Defined fields change while retained saved records keep their independent state.
    */
    #[test]
    fn selected_files_and_new_paths_preserve_saved_records() {
        use crate::editor::{Editor, Mode};
        let config = Config::default();
        let mut view = Editor::new(vec![0; 256], Mode::Hex, 16);
        let mut state = SavedState::new_single("C:\\original.bin", &view, &config).unwrap();
        state.payload[8 + 1000] = 0x37;
        state.payload[69708] = 0x53;
        let original = state.payload[8..8 + 2814].to_vec();
        let history = state.payload[67544..].to_vec();
        let index = state.add_file("C:\\selected.bin", &view, &config).unwrap();
        assert_eq!(index, 1);
        view.offset = 64;
        state.update_view(index, &view).unwrap();
        state.update_path(index, "C:\\copy.bin").unwrap();
        assert_eq!(&state.payload[8..8 + 2814], original);
        assert_eq!(&state.payload[67544..], history);
        let parsed = parse_saved(&encode_saved(&state.payload).unwrap()).unwrap();
        assert_eq!(parsed.active_index, 1);
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files[1].path, "C:\\copy.bin");
        assert_eq!(parsed.files[1].offset, 64);
        assert_eq!(parsed.payload, state.payload);

        let before = state.payload.clone();
        assert!(state.add_file("bad\0path", &view, &config).is_err());
        assert!(state.update_path(index, "bad\0path").is_err());
        assert!(state.update_path(24, "C:\\missing.bin").is_err());
        assert_eq!(state.payload, before);
        assert_eq!(state.files.len(), 2);
        assert_eq!(state.files[index].path, "C:\\copy.bin");
        for index in 2..24 {
            assert_eq!(
                state.add_file(&format!("C:\\file-{index}.bin"), &view, &config),
                Ok(index)
            );
        }
        let before = state.payload.clone();
        assert!(state.add_file("C:\\overflow.bin", &view, &config).is_err());
        assert_eq!(state.files.len(), 24);
        assert_eq!(state.active_index, 1);
        assert_eq!(state.payload, before);
        put32(&mut state.payload, 0, 0);
        for count in 1..=24 {
            put32(&mut state.payload, 4, count);
            assert_eq!(
                parse_saved(&encode_saved(&state.payload).unwrap())
                    .unwrap()
                    .files
                    .len(),
                count as usize
            );
        }
    }
}
