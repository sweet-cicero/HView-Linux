/*
This module maps file offsets and runtime addresses for supported executable formats.
The shared architecture contract gives decoder and assembler callers one validated source of machine facts.
*/
use crate::paged::PagedFile;

const OUTSIDE: &str = "Offset is out of file";
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const EM_ARM: u16 = 40;

/*
These ELF limits match the supported little-endian header forms and bound all metadata work.
The entry limits protect allocation, and the byte limit protects paged program-table reads.
The structure text limit also bounds escaped names across all retained browser rows.
*/
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF32_HEADER_SIZE: usize = 52;
const ELF64_HEADER_SIZE: usize = 64;
const ELF32_PROGRAM_SIZE: usize = 32;
const ELF64_PROGRAM_SIZE: usize = 56;
const ELF32_SECTION_SIZE: usize = 40;
const ELF64_SECTION_SIZE: usize = 64;
const ELF_MAX_ENTRIES: usize = 100_000;
const ELF_MAX_LOAD_SEGMENTS: usize = 256;
const ELF_MAX_PROGRAM_BYTES: u64 = 8 * 1024 * 1024;
const ELF_MAX_STRUCTURE_TEXT_BYTES: usize = 16 * 1024 * 1024;
const ELF_RESERVED_INDEX_START: usize = 0xff00;

/*
Architecture identifies the instruction family and the effective code width.
Each engine validates a directly constructed x86 value before it uses the width.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86(u32),
    Arm,
    Thumb,
    Arm64,
}

impl Architecture {
    /*
    This constructor accepts only widths that the x86 engines support.
    Callers can use the remaining methods for bounded instruction and alignment decisions.
    */
    pub fn x86(bits: u32) -> Result<Self, String> {
        matches!(bits, 16 | 32 | 64)
            .then_some(Self::X86(bits))
            .ok_or_else(|| "The x86 code width must be 16, 32, or 64 bits.".into())
    }

    /*
    This fact returns the compatibility width used by existing Code display and session data.
    X86 stores its checked width, ARM and Thumb use 32, and ARM64 uses 64.
    */
    pub const fn bits(self) -> u32 {
        match self {
            Self::X86(bits) => bits,
            Self::Arm | Self::Thumb => 32,
            Self::Arm64 => 64,
        }
    }

    /*
    This fact supplies the compact Code header label for each checked architecture.
    Invalid direct x86 variants use a generic label until an engine boundary rejects them.
    */
    pub const fn label(self) -> &'static str {
        match self {
            Self::X86(16) => "a16",
            Self::X86(32) => "a32",
            Self::X86(64) => "a64",
            Self::X86(_) => "x86",
            Self::Arm => "ARM",
            Self::Thumb => "THUMB",
            Self::Arm64 => "ARM64",
        }
    }

    /*
    This fact gives the natural instruction alignment for each architecture family.
    X86 permits each byte, ARM and ARM64 use four bytes, and Thumb uses two bytes.
    Native inspection entry points can accept unaligned runtime addresses.
    */
    pub const fn alignment(self) -> u64 {
        match self {
            Self::X86(_) => 1,
            Self::Arm | Self::Arm64 => 4,
            Self::Thumb => 2,
        }
    }

    /*
    This fact bounds one native decoder input without selecting an engine.
    X86 permits 15 bytes, while the recorded ARM families need at most four bytes.
    */
    pub const fn max_instruction_bytes(self) -> usize {
        match self {
            Self::X86(_) => 15,
            Self::Arm | Self::Thumb | Self::Arm64 => 4,
        }
    }

    /*
    This fact validates a returned instruction length for the checked architecture family.
    X86 uses 1 through 15 bytes, ARM and ARM64 use four, and Thumb uses two or four.
    */
    pub const fn valid_instruction_bytes(self, size: usize) -> bool {
        match self {
            Self::X86(_) => size >= 1 && size <= 15,
            Self::Arm | Self::Arm64 => size == 4,
            Self::Thumb => size == 2 || size == 4,
        }
    }
}

/*
AddressDomain states how a CodeLocation address relates to the source bytes.
Raw models and mapped executable bytes use virtual addresses, while unmapped source bytes use file offsets.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressDomain {
    File,
    Va,
}

/*
CodeLocation joins one mapped address with its compatibility width, checked architecture, and address domain.
Callers can retain all four fields or use the older tuple wrapper.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeLocation {
    pub address: u64,
    pub bits: u32,
    pub architecture: Architecture,
    pub domain: AddressDomain,
}

/*
These readers decode fixed-width executable fields after they validate the requested source range.
Malformed input produces the existing executable-header error.
*/

fn word(data: &[u8], at: usize) -> Result<u16, String> {
    let end = at
        .checked_add(2)
        .ok_or("The executable header range exceeds the address range.")?;
    Ok(u16::from_le_bytes(
        data.get(at..end)
            .ok_or("The executable header is incomplete.")?
            .try_into()
            .unwrap(),
    ))
}

fn dword(data: &[u8], at: usize) -> Result<u32, String> {
    let end = at
        .checked_add(4)
        .ok_or("The executable header range exceeds the address range.")?;
    Ok(u32::from_le_bytes(
        data.get(at..end)
            .ok_or("The executable header is incomplete.")?
            .try_into()
            .unwrap(),
    ))
}

/*
This reader decodes one little-endian 64-bit ELF or PE field after a checked range lookup.
The later parser gives the field a format-specific error when the enclosing range is invalid.
*/
fn qword(data: &[u8], at: usize) -> Result<u64, String> {
    let end = at
        .checked_add(8)
        .ok_or("The executable header range exceeds the address range.")?;
    Ok(u64::from_le_bytes(
        data.get(at..end)
            .ok_or("The executable header is incomplete.")?
            .try_into()
            .unwrap(),
    ))
}

/*
Section stores exact PE file and virtual ranges from one section-table record.
Pe combines validated header fields, sections, and logical file length for later address conversion.
*/
struct Section {
    rva: u32,
    raw: u32,
    raw_size: u32,
    virtual_span: u32,
}

struct Pe {
    entry: u32,
    machine: u16,
    bits: u32,
    image_base: u64,
    header_size: u32,
    sections: Vec<Section>,
    file_len: u64,
}

/*
ElfHeader stores the resolved ELF header counts and table geometry.
ElfSegment stores one PT_LOAD map or one browser program header with its original table location.
*/
#[derive(Clone, Copy)]
struct ElfHeader {
    bits: u32,
    file_type: u16,
    machine: u16,
    entry: u64,
    program_offset: u64,
    section_offset: u64,
    program_size: usize,
    program_count: usize,
    section_size: usize,
    section_count: usize,
    section_names: usize,
}

#[derive(Clone, Copy)]
struct ElfSegment {
    header: u64,
    segment_type: u32,
    flags: u32,
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
    align: u64,
}

/*
Elf joins the checked header, PT_LOAD mappings, and logical file length.
Buffered and paged constructors create the same record before address callers use it.
*/
struct Elf {
    header: ElfHeader,
    segments: Vec<ElfSegment>,
    file_len: u64,
}

/*
Raw stores the explicit runtime base and validated architecture.
Checked conversions protect both the 64-bit range and the selected linear-address range.
*/
#[derive(Clone, Copy)]
struct Raw {
    base: u64,
    architecture: Architecture,
}

impl Raw {
    /*
    This conversion adds a file offset to the configured runtime base.
    X86(16), X86(32), ARM, and Thumb use the 32-bit linear-address limit.
    X86(64) and ARM64 use the checked 64-bit address range.
    */
    fn address(self, offset: u64) -> Result<u64, String> {
        let address = self
            .base
            .checked_add(offset)
            .ok_or("The raw address exceeds the 64-bit address range.")?;
        if self.architecture.bits() != 64 && address > u64::from(u32::MAX) {
            return Err("The raw address exceeds the 32-bit linear address range.".into());
        }
        Ok(address)
    }

    /*
    This reverse conversion subtracts the runtime base after width validation.
    An address below the base has no raw file offset.
    */
    fn offset(self, address: u64) -> Result<u64, String> {
        if self.architecture.bits() != 64 && address > u64::from(u32::MAX) {
            return Err("The raw address exceeds the 32-bit linear address range.".into());
        }
        address
            .checked_sub(self.base)
            .ok_or_else(|| "The address is below the raw runtime base.".into())
    }
}

/*
Metadata selects parsed ELF or PE mapping, plain-file behavior, or an explicit raw architecture mapping.
Callers reuse the value for code addresses, navigation, and address conversion.
*/
pub struct Metadata {
    pe: Option<Pe>,
    elf: Option<Elf>,
    raw: Option<Raw>,
    file_len: Option<u64>,
    entry_offset: Option<u64>,
}

/*
These methods construct metadata and expose checked mapping operations.
Each operation preserves the error that identifies an unsupported machine or missing byte.
*/
impl Metadata {
    /*
    This parser selects checked ELF or PE metadata from current buffered bytes.
    A malformed executable header stops metadata construction.
    */
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let elf = data
            .starts_with(ELF_MAGIC)
            .then(|| Elf::read(data))
            .transpose()?;
        let pe = if elf.is_none() {
            pe_header(data)?
                .map(|header| Pe::read(data, header))
                .transpose()?
        } else {
            None
        };
        let entry_offset = if let Some(elf) = &elf {
            elf.entry_offset()?
        } else {
            match &pe {
                Some(pe) => pe.rva_to_file(pe.entry),
                None if data.starts_with(b"MZ") || data.starts_with(b"ZM") => {
                    Some(dos_entry(data)?)
                }
                None => Some(0),
            }
        };
        Ok(Self {
            pe,
            elf,
            raw: None,
            file_len: Some(data.len() as u64),
            entry_offset,
        })
    }

    /*
    This parser reads bounded ELF or PE metadata from current paged logical bytes.
    Distant tables do not allocate or read the bytes before each requested range.
    */
    pub(crate) fn read_from(file: &PagedFile) -> Result<Self, String> {
        let prefix_len = usize::try_from(file.len().min(64)).unwrap();
        let prefix = file
            .read_window(0, prefix_len)
            .map_err(|error| error.to_string())?;
        let elf = prefix
            .bytes
            .starts_with(ELF_MAGIC)
            .then(|| Elf::read_from(file, &prefix.bytes))
            .transpose()?;
        let header = if elf.is_none() {
            paged_pe_header(file, &prefix.bytes)?
        } else {
            None
        };
        if elf.is_none()
            && header.is_none()
            && !prefix.bytes.starts_with(b"MZ")
            && !prefix.bytes.starts_with(b"ZM")
        {
            return Err(
                "Virtual and entry-point offsets are unavailable for large files. HView-Linux will use file offset zero."
                    .into(),
            );
        }
        let pe = header
            .map(|offset| Pe::read_from(file, offset))
            .transpose()?;
        let entry_offset = if let Some(elf) = &elf {
            elf.entry_offset()?
        } else {
            match &pe {
                Some(pe) => pe.rva_to_file(pe.entry),
                None if prefix.bytes.starts_with(b"MZ") || prefix.bytes.starts_with(b"ZM") => {
                    Some(dos_entry(&prefix.bytes)?)
                }
                None => Some(0),
            }
        };
        file.validate().map_err(|error| error.to_string())?;
        Ok(Self {
            pe,
            elf,
            raw: None,
            file_len: Some(file.len()),
            entry_offset,
        })
    }

    /*
    This compatibility constructor validates an explicit raw x86 base and width.
    The architecture constructor supplies the shared implementation.
    */
    #[allow(dead_code, reason = "L07.1 keeps this x86 compatibility entry")]
    pub fn raw(base: u64, bits: u32) -> Result<Self, String> {
        let architecture = Architecture::x86(bits)
            .map_err(|_| "Raw x86 code width must be 16, 32, or 64 bits.".to_owned())?;
        Self::raw_architecture(base, architecture)
    }

    /*
    This constructor validates one explicit raw architecture and its base address.
    Raw metadata takes priority because the constructor stores no parsed executable mapping.
    */
    pub fn raw_architecture(base: u64, architecture: Architecture) -> Result<Self, String> {
        if let Architecture::X86(bits) = architecture {
            Architecture::x86(bits)?;
        }
        let raw = Raw { base, architecture };
        raw.address(0)?;
        Ok(Self {
            pe: None,
            elf: None,
            raw: Some(raw),
            file_len: None,
            entry_offset: Some(0),
        })
    }

    /*
    This query returns an address, architecture, and domain for one existing code mapping.
    ELF and PE gaps keep their file address so Code display can show each source byte.
    */
    pub fn code_location(&self, file_offset: u64) -> Result<CodeLocation, String> {
        if self.file_len.is_some_and(|len| file_offset >= len) {
            return Err(OUTSIDE.into());
        }
        if let Some(raw) = self.raw {
            return Ok(CodeLocation {
                address: raw.address(file_offset)?,
                bits: raw.architecture.bits(),
                architecture: raw.architecture,
                domain: AddressDomain::Va,
            });
        }
        if let Some(pe) = &self.pe {
            let architecture = pe.architecture()?;
            return Ok(match pe.file_to_virtual(file_offset) {
                Some(address) => CodeLocation {
                    address,
                    bits: architecture.bits(),
                    architecture,
                    domain: AddressDomain::Va,
                },
                None => CodeLocation {
                    address: file_offset,
                    bits: architecture.bits(),
                    architecture,
                    domain: AddressDomain::File,
                },
            });
        }
        if let Some(elf) = &self.elf {
            let architecture = elf.architecture()?;
            return Ok(match elf.file_to_virtual(file_offset)? {
                Some(address) => CodeLocation {
                    address,
                    bits: architecture.bits(),
                    architecture,
                    domain: AddressDomain::Va,
                },
                None => CodeLocation {
                    address: file_offset,
                    bits: architecture.bits(),
                    architecture,
                    domain: AddressDomain::File,
                },
            });
        }
        Ok(CodeLocation {
            address: file_offset,
            bits: 16,
            architecture: Architecture::X86(16),
            domain: AddressDomain::File,
        })
    }

    /*
    This compatibility wrapper preserves the existing address and width tuple.
    New callers can retain the address domain when their operation requires it.
    */
    pub fn code_address(&self, file_offset: u64) -> Result<(u64, u32), String> {
        if let Some(raw) = self.raw {
            return raw
                .address(file_offset)
                .map(|address| (address, raw.architecture.bits()));
        }
        if let Some(pe) = &self.pe {
            let architecture = pe.architecture()?;
            return pe
                .file_to_virtual(file_offset)
                .map(|address| (address, architecture.bits()))
                .ok_or_else(|| OUTSIDE.into());
        }
        if let Some(elf) = &self.elf {
            let architecture = elf.architecture()?;
            if elf.header.file_type == 1 {
                return (file_offset < elf.file_len)
                    .then_some((file_offset, architecture.bits()))
                    .ok_or_else(|| OUTSIDE.into());
            }
            return elf
                .file_to_virtual(file_offset)?
                .map(|address| (address, architecture.bits()))
                .ok_or_else(|| OUTSIDE.into());
        }
        Ok((file_offset, 16))
    }

    /*
    This query selects the decoder architecture for current Code consumers.
    An explicit raw model supplies its architecture, while AUTO keeps the configured x86 width.
    */
    pub fn decoder_architecture(&self, fallback_bits: u32) -> Result<Architecture, String> {
        if let Some(raw) = self.raw {
            return match raw.architecture {
                Architecture::X86(bits) => Architecture::x86(bits),
                architecture => Ok(architecture),
            };
        }
        if let Some(pe) = &self.pe {
            return match pe.architecture()? {
                architecture @ (Architecture::Arm | Architecture::Thumb | Architecture::Arm64) => {
                    Ok(architecture)
                }
                Architecture::X86(_) => Architecture::x86(fallback_bits),
            };
        }
        if let Some(elf) = &self.elf {
            return match elf.architecture()? {
                architecture @ (Architecture::Arm | Architecture::Thumb | Architecture::Arm64) => {
                    Ok(architecture)
                }
                Architecture::X86(_) => Architecture::x86(fallback_bits),
            };
        }
        Architecture::x86(fallback_bits)
    }

    /*
    This navigation query validates a source file byte before returning its runtime address.
    Mapped executable sources require a virtual address, while ELF relocatable sources use file offsets.
    */
    #[cfg(test)]
    pub fn navigation_address(&self, data: &[u8], file_offset: u64) -> Result<u64, String> {
        if let Some(raw) = self.raw {
            let offset = usize::try_from(file_offset)
                .map_err(|_| "The branch source exceeds the address range.")?;
            data.get(offset)
                .ok_or("The branch source is outside the current buffer.")?;
            return raw.address(file_offset);
        }
        if let Some(pe) = &self.pe {
            pe.architecture()?;
            let offset = usize::try_from(file_offset)
                .map_err(|_| "The branch source exceeds the address range.")?;
            data.get(offset)
                .ok_or("The branch source is outside the current buffer.")?;
            return pe
                .file_to_virtual(file_offset)
                .ok_or_else(|| "The branch source has no virtual address.".into());
        }
        if let Some(elf) = &self.elf {
            let offset = usize::try_from(file_offset)
                .map_err(|_| "The branch source exceeds the address range.")?;
            data.get(offset)
                .ok_or("The branch source is outside the current buffer.")?;
            if elf.header.file_type == 1 {
                return Ok(file_offset);
            }
            return elf
                .file_to_virtual(file_offset)?
                .ok_or_else(|| "The branch source has no virtual address.".into());
        }
        if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
            return convert_address(data, AddressKind::File, file_offset)?
                .va
                .ok_or_else(|| "The branch source has no virtual address.".into());
        }
        let offset = usize::try_from(file_offset)
            .map_err(|_| "The branch source exceeds the address range.")?;
        data.get(offset)
            .map(|_| file_offset)
            .ok_or_else(|| "The branch source is outside the current buffer.".into())
    }

    /*
    This navigation query maps a runtime address back to one source file byte.
    Raw, ELF, PE, and plain sources retain their established bounds.
    */
    #[cfg(test)]
    pub fn navigation_offset(&self, data: &[u8], address: u64) -> Result<u64, String> {
        if let Some(raw) = self.raw {
            let offset = raw.offset(address)?;
            let index = usize::try_from(offset)
                .map_err(|_| "The branch target exceeds the address range.")?;
            data.get(index)
                .ok_or("The branch target is outside the current buffer.")?;
            return Ok(offset);
        }
        if let Some(pe) = &self.pe {
            pe.architecture()?;
            let offset = pe
                .va_to_file(address)
                .ok_or("The branch target has no file byte.")?;
            let index = usize::try_from(offset)
                .map_err(|_| "The branch target exceeds the address range.")?;
            data.get(index)
                .ok_or("The branch target is outside the current buffer.")?;
            return Ok(offset);
        }
        if let Some(elf) = &self.elf {
            if elf.header.file_type == 1 {
                let index = usize::try_from(address)
                    .map_err(|_| "The branch target exceeds the address range.")?;
                data.get(index)
                    .ok_or("The branch target is outside the current buffer.")?;
                return Ok(address);
            }
            let offset = elf
                .virtual_to_file(address)?
                .ok_or("The branch target has no file byte.")?;
            let index = usize::try_from(offset)
                .map_err(|_| "The branch target exceeds the address range.")?;
            data.get(index)
                .ok_or("The branch target is outside the current buffer.")?;
            return Ok(offset);
        }
        if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
            let offset = convert_address(data, AddressKind::Va, address)?
                .file_offset
                .ok_or("The branch target has no file byte.")?;
            return u64::try_from(offset)
                .map_err(|_| "The branch target exceeds the address range.".into());
        }
        let offset =
            usize::try_from(address).map_err(|_| "The branch target exceeds the address range.")?;
        data.get(offset)
            .map(|_| address)
            .ok_or_else(|| "The branch target is outside the current buffer.".into())
    }

    /*
    This conversion maps one address through its explicit domain and checks the logical file length.
    Strict VA users cannot reinterpret the same number as an RVA.
    */
    pub(crate) fn target_offset(&self, domain: AddressDomain, target: u64) -> Result<u64, String> {
        let offset = match domain {
            AddressDomain::File => target,
            AddressDomain::Va => {
                if let Some(raw) = self.raw {
                    raw.offset(target)?
                } else if let Some(pe) = &self.pe {
                    pe.va_to_file(target).ok_or(OUTSIDE)?
                } else if let Some(elf) = &self.elf {
                    elf.virtual_to_file(target)?.ok_or(OUTSIDE)?
                } else {
                    return Err("The file has no virtual address mapping.".into());
                }
            }
        };
        if self.file_len.is_some_and(|len| offset >= len) {
            return Err(OUTSIDE.into());
        }
        Ok(offset)
    }

    /*
    This compatibility conversion accepts either an RVA or a preferred-base VA for PE startup input.
    ELF accepts only a strict VA, while two different PE mappings produce an ambiguity error.
    */
    pub(crate) fn legacy_virtual_offset(&self, value: u64) -> Result<u64, String> {
        if self.raw.is_some() {
            return self.target_offset(AddressDomain::Va, value);
        }
        if let Some(pe) = &self.pe {
            return pe.legacy_virtual_to_file(value);
        }
        if let Some(elf) = &self.elf {
            return elf.virtual_to_file(value)?.ok_or_else(|| OUTSIDE.into());
        }
        self.target_offset(AddressDomain::File, value)
    }

    /*
    This query returns the parsed entry file offset after a final logical-length check.
    Callers can use the result without reading the complete paged source.
    */
    pub(crate) fn entry_offset(&self) -> Result<u64, String> {
        self.entry_offset
            .filter(|offset| self.file_len.is_none_or(|len| *offset < len))
            .ok_or_else(|| OUTSIDE.into())
    }

    /*
    This label identifies parsed ELF or PE metadata for paged startup and focused checks.
    Raw and plain sources keep their existing display behavior.
    */
    pub(crate) fn format_label(&self) -> Option<&'static str> {
        self.raw
            .map(|_| "RAW")
            .or_else(|| self.pe.as_ref().map(|_| "PE"))
            .or_else(|| self.elf.as_ref().map(|_| "ELF"))
    }

    /*
    These capability facts let the address tool offer only domains that the selected metadata supports.
    ELF relocatable files have no VA, and all ELF forms have no RVA.
    */
    pub(crate) fn has_rva(&self) -> bool {
        self.pe.is_some()
    }

    pub(crate) fn has_va(&self) -> bool {
        self.raw.is_some()
            || self.pe.is_some()
            || self
                .elf
                .as_ref()
                .is_some_and(|elf| elf.header.file_type != 1)
    }

    /*
    This general conversion returns all available raw, ELF, or PE address domains.
    Raw models reject RVA requests because they define no image-relative base.
    */
    pub fn convert_address(
        &self,
        data: &[u8],
        kind: AddressKind,
        value: u64,
    ) -> Result<PeAddress, String> {
        let Some(raw) = self.raw else {
            return if let Some(elf) = &self.elf {
                elf.convert_address(kind, value, Some(data.len() as u64))
            } else {
                convert_address(data, kind, value)
            };
        };
        match kind {
            AddressKind::File => {
                let file_offset = usize::try_from(value)
                    .map_err(|_| "The file offset exceeds the address range.")?;
                data.get(file_offset)
                    .ok_or("The file offset has no file byte.")?;
                Ok(PeAddress {
                    file_offset: Some(file_offset),
                    rva: None,
                    va: Some(raw.address(value)?),
                })
            }
            AddressKind::Va => {
                let offset = raw.offset(value)?;
                let file_offset = usize::try_from(offset)
                    .map_err(|_| "The file offset exceeds the address range.")?;
                data.get(file_offset)
                    .ok_or("The converted file offset has no file byte.")?;
                Ok(PeAddress {
                    file_offset: Some(file_offset),
                    rva: None,
                    va: Some(value),
                })
            }
            AddressKind::Rva => Err("Raw address mode has no RVA.".into()),
        }
    }
}

/*
These PE readers collect bounded header parts before they use one shared validator.
The resulting map uses exact declared file ranges and checked virtual ranges.
*/
impl Pe {
    /*
    This selector validates each supported PE machine and optional-header width pair.
    ARMNT remains an explicit capability error for Code operations.
    */
    fn architecture(&self) -> Result<Architecture, String> {
        match (self.machine, self.bits) {
            (0x014c, 32) => Ok(Architecture::X86(32)),
            (IMAGE_FILE_MACHINE_ARM, 32) => Ok(Architecture::Arm),
            (IMAGE_FILE_MACHINE_THUMB, 32) => Ok(Architecture::Thumb),
            (IMAGE_FILE_MACHINE_ARMNT, 32) => Err("PE ARMNT code decoding is unsupported.".into()),
            (0x8664, 64) => Ok(Architecture::X86(64)),
            (0xaa64, 64) => Ok(Architecture::Arm64),
            _ => Err("The PE processor is unsupported for code decoding.".into()),
        }
    }

    /*
    This buffered reader slices only the COFF header, required optional fields, and section table.
    Checked offsets prevent malformed headers from wrapping a slice range.
    */
    fn read(data: &[u8], header: usize) -> Result<Self, String> {
        let count_at = header
            .checked_add(6)
            .ok_or("The COFF header offset exceeds the address range.")?;
        let count = usize::from(word(data, count_at)?);
        if count > 96 {
            return Err("The PE section count exceeds the Windows limit of 96.".into());
        }
        let optional_size_at = header
            .checked_add(20)
            .ok_or("The COFF header offset exceeds the address range.")?;
        let optional_size = usize::from(word(data, optional_size_at)?);
        let optional = header
            .checked_add(24)
            .ok_or("The optional-header offset exceeds the address range.")?;
        let table = optional
            .checked_add(optional_size)
            .ok_or("The section-table offset exceeds the address range.")?;
        let table_size = count
            .checked_mul(40)
            .ok_or("The section-table range exceeds the address range.")?;
        let table_end = table
            .checked_add(table_size)
            .ok_or("The section-table range exceeds the address range.")?;
        let coff = data
            .get(header..optional)
            .ok_or("The executable header is incomplete.")?;
        let optional_prefix_end = optional
            .checked_add(64)
            .ok_or("The optional-header range exceeds the address range.")?;
        let optional_data = data
            .get(optional..optional_prefix_end)
            .ok_or("The executable header is incomplete.")?;
        let sections = data
            .get(table..table_end)
            .ok_or("The PE section table is incomplete.")?;
        Self::from_parts(
            data.len() as u64,
            u32::try_from(header)
                .map_err(|_| "The PE header offset exceeds the PE address range.")?,
            optional_size,
            coff,
            optional_data,
            sections,
        )
    }

    /*
    This paged reader requests the same three bounded parts through current logical spans.
    The 96-section limit keeps the largest section-table request below 64 KiB.
    */
    fn read_from(file: &PagedFile, header: u32) -> Result<Self, String> {
        let mut coff = [0; 24];
        read_paged_exact(file, u64::from(header), &mut coff, "executable header")?;
        let count = usize::from(word(&coff, 6)?);
        if count > 96 {
            return Err("The PE section count exceeds the Windows limit of 96.".into());
        }
        let optional_size = usize::from(word(&coff, 20)?);
        if optional_size < 64 {
            return Err("The PE optional header is incomplete.".into());
        }
        let optional_offset = u64::from(header)
            .checked_add(24)
            .ok_or("The optional-header offset exceeds the address range.")?;
        let mut optional = [0; 64];
        read_paged_exact(file, optional_offset, &mut optional, "executable header")?;
        let table = optional_offset
            .checked_add(optional_size as u64)
            .ok_or("The section-table offset exceeds the address range.")?;
        let table_size = count
            .checked_mul(40)
            .ok_or("The section-table range exceeds the address range.")?;
        let mut sections = vec![0; table_size];
        read_paged_exact(file, table, &mut sections, "PE section table")?;
        Self::from_parts(
            file.len(),
            header,
            optional_size,
            &coff,
            &optional,
            &sections,
        )
    }

    /*
    This shared validator checks header geometry and every exact section range.
    No alignment rounding or direct-map shortcut changes a declared file position.
    */
    fn from_parts(
        file_len: u64,
        header: u32,
        optional_size: usize,
        coff: &[u8],
        optional: &[u8],
        sections: &[u8],
    ) -> Result<Self, String> {
        /*
        The header section checks size limits, class fields, and the complete section table.
        Validated header facts then initialize the immutable mapping record.
        */
        let count = usize::from(word(coff, 6)?);
        if count > 96 {
            return Err("The PE section count exceeds the Windows limit of 96.".into());
        }
        if optional_size < 64 {
            return Err("The PE optional header is incomplete.".into());
        }
        let magic = word(optional, 0)?;
        let (bits, image_base) = match magic {
            0x10b => (32, u64::from(dword(optional, 28)?)),
            0x20b => (
                64,
                u64::from(dword(optional, 24)?) | (u64::from(dword(optional, 28)?) << 32),
            ),
            _ => return Err("The PE optional-header type is unsupported.".into()),
        };
        let header_size = dword(optional, 60)?;
        if header_size == 0 || u64::from(header_size) > file_len {
            return Err("The PE header range is outside the file.".into());
        }
        checked_pe_va(bits, image_base, u64::from(header_size - 1), "PE header")?;
        let expected_section_bytes = count
            .checked_mul(40)
            .ok_or("The section-table range exceeds the address range.")?;
        if sections.len() != expected_section_bytes {
            return Err("The PE section table is incomplete.".into());
        }
        let optional_size = u64::try_from(optional_size)
            .map_err(|_| "The section-table offset exceeds the address range.")?;
        let table = u64::from(header)
            .checked_add(24)
            .and_then(|at| at.checked_add(optional_size))
            .ok_or("The section-table offset exceeds the address range.")?;
        let table_end = table
            .checked_add(expected_section_bytes as u64)
            .ok_or("The section-table range exceeds the address range.")?;
        if table_end > u64::from(header_size) {
            return Err("The section table exceeds the declared PE headers.".into());
        }
        let mut pe = Self {
            entry: dword(optional, 16)?,
            machine: word(coff, 4)?,
            bits,
            image_base,
            header_size,
            sections: Vec::with_capacity(count),
            file_len,
        };

        /*
        The section loop validates each file range, virtual range, and preferred virtual address.
        A zero raw size creates a virtual-only range without a source byte.
        */
        for index in 0..count {
            let at = index * 40;
            let virtual_size = dword(sections, at + 8)?;
            let rva = dword(sections, at + 12)?;
            let raw_size = dword(sections, at + 16)?;
            let raw = dword(sections, at + 20)?;
            let virtual_span = virtual_size.max(raw_size);
            let virtual_end = u64::from(rva)
                .checked_add(u64::from(virtual_span))
                .ok_or("A section virtual range exceeds the address range.")?;
            if virtual_end > u64::from(u32::MAX) + 1 {
                return Err("A section virtual range exceeds the PE address range.".into());
            }
            if virtual_span != 0 {
                if rva < header_size {
                    return Err("A section virtual range overlaps the PE headers.".into());
                }
                checked_pe_va(bits, image_base, virtual_end - 1, "section")?;
            }
            if raw_size != 0 {
                if raw == 0 {
                    return Err("A section with raw bytes has a zero file offset.".into());
                }
                if raw < header_size {
                    return Err("A section raw range overlaps the PE headers.".into());
                }
                let raw_end = u64::from(raw)
                    .checked_add(u64::from(raw_size))
                    .ok_or("A section raw range exceeds the address range.")?;
                if raw_end > file_len {
                    return Err("The section raw data range is outside the file.".into());
                }
            }
            pe.sections.push(Section {
                rva,
                raw,
                raw_size,
                virtual_span,
            });
        }

        /*
        The final section rejects aliases that would give one byte two raw or virtual meanings.
        A valid map then supplies all buffered and paged consumers.
        */
        for (index, left) in pe.sections.iter().enumerate() {
            for right in &pe.sections[index + 1..] {
                if ranges_overlap(left.raw, left.raw_size, right.raw, right.raw_size) {
                    return Err("Two section raw ranges overlap.".into());
                }
                if ranges_overlap(left.rva, left.virtual_span, right.rva, right.virtual_span) {
                    return Err("Two section virtual ranges overlap.".into());
                }
            }
        }
        Ok(pe)
    }

    /*
    This mapping returns only header bytes and declared section raw bytes.
    A virtual-only tail has no file byte.
    */
    fn rva_to_file(&self, rva: u32) -> Option<u64> {
        if rva < self.header_size {
            return Some(u64::from(rva));
        }
        for section in &self.sections {
            let Some(delta) = rva.checked_sub(section.rva) else {
                continue;
            };
            if delta < section.virtual_span && delta < section.raw_size {
                return u64::from(section.raw).checked_add(u64::from(delta));
            }
        }
        None
    }

    /*
    This strict reverse mapping accepts only a preferred-base virtual address.
    Branch targets use this path and never retry the value as an RVA.
    */
    fn va_to_file(&self, address: u64) -> Option<u64> {
        let rva = address.checked_sub(self.image_base)?;
        self.rva_to_file(u32::try_from(rva).ok()?)
    }

    /*
    This compatibility path accepts an RVA or a preferred-base virtual address.
    Different valid results make the input ambiguous.
    */
    fn legacy_virtual_to_file(&self, address: u64) -> Result<u64, String> {
        let mut mapped = None;
        let va_rva = address
            .checked_sub(self.image_base)
            .and_then(|value| u32::try_from(value).ok());
        let bare_rva = u32::try_from(address).ok();
        for rva in [va_rva, bare_rva].into_iter().flatten() {
            let Some(offset) = self.rva_to_file(rva) else {
                continue;
            };
            if mapped.is_some_and(|previous| previous != offset) {
                return Err("The value has ambiguous RVA and VA mappings.".into());
            }
            mapped = Some(offset);
        }
        mapped.ok_or_else(|| OUTSIDE.into())
    }

    /*
    This mapping returns a virtual address only for a declared header or section source byte.
    File gaps and overlays remain valid File-domain bytes.
    */
    fn file_to_virtual(&self, offset: u64) -> Option<u64> {
        if offset >= self.file_len {
            return None;
        }
        if offset < u64::from(self.header_size) {
            return checked_pe_va(self.bits, self.image_base, offset, "header byte").ok();
        }
        for section in &self.sections {
            let Some(delta) = offset.checked_sub(u64::from(section.raw)) else {
                continue;
            };
            if delta >= u64::from(section.raw_size) || delta >= u64::from(section.virtual_span) {
                continue;
            }
            let rva = u64::from(section.rva).checked_add(delta)?;
            return checked_pe_va(self.bits, self.image_base, rva, "section byte").ok();
        }
        None
    }
}

/*
This helper adds an RVA to the preferred image base with the selected PE width limit.
Each mapping caller receives an error before an invalid virtual address becomes visible.
*/
fn checked_pe_va(bits: u32, image_base: u64, rva: u64, what: &str) -> Result<u64, String> {
    let address = image_base
        .checked_add(rva)
        .ok_or_else(|| format!("The {what} virtual address exceeds the address range."))?;
    if bits == 32 && address > u64::from(u32::MAX) {
        return Err(format!(
            "The {what} virtual address exceeds the PE32 address range."
        ));
    }
    Ok(address)
}

/*
These paged helpers preserve I/O errors and identify incomplete format ranges.
Each exact read uses one current logical window and verifies its returned length.
*/
fn read_paged_exact(
    file: &PagedFile,
    offset: u64,
    output: &mut [u8],
    name: &str,
) -> Result<(), String> {
    let end = offset
        .checked_add(output.len() as u64)
        .filter(|end| *end <= file.len())
        .ok_or_else(|| format!("The {name} is incomplete."))?;
    debug_assert!(end >= offset);
    let window = file
        .read_window(offset, output.len())
        .map_err(|error| error.to_string())?;
    if window.bytes.len() != output.len() {
        return Err(format!("The {name} is incomplete."));
    }
    output.copy_from_slice(&window.bytes);
    Ok(())
}

/*
This detector reads a distant executable signature without reading the intervening bytes.
It preserves recognized unsupported formats and returns no PE header for plain or ELF sources.
*/
fn paged_pe_header(file: &PagedFile, prefix: &[u8]) -> Result<Option<u32>, String> {
    if prefix.starts_with(b"\x7fELF") {
        return Ok(None);
    }
    if prefix.starts_with(b"NetWare Loadable Module\x1a") {
        return Err("This executable format is unsupported.".into());
    }
    if [b"NE", b"LE", b"LX"]
        .iter()
        .any(|magic| prefix.starts_with(*magic))
    {
        return Err("NE, LE, and LX executable formats are unsupported.".into());
    }
    if !prefix.starts_with(b"MZ") && !prefix.starts_with(b"ZM") {
        return Ok(None);
    }
    let Some(header) = prefix
        .get(60..64)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
    else {
        return Ok(None);
    };
    if u64::from(header) >= file.len() {
        return Ok(None);
    }
    let length = usize::try_from((file.len() - u64::from(header)).min(4)).unwrap();
    let signature = file
        .read_window(u64::from(header), length)
        .map_err(|error| error.to_string())?;
    if &*signature.bytes == b"PE\0\0" {
        return Ok(Some(header));
    }
    if [b"NE", b"LE", b"LX"]
        .iter()
        .any(|magic| signature.bytes.starts_with(*magic))
    {
        return Err("NE, LE, and LX executable formats are unsupported.".into());
    }
    Ok(None)
}

/*
This helper calculates the retained DOS entry file offset from its segment and instruction fields.
Buffered and paged metadata use the same checked fixed-width readers.
*/
fn dos_entry(data: &[u8]) -> Result<u64, String> {
    Ok(u64::from(word(data, 20)?) + 16 * (u64::from(word(data, 8)?) + u64::from(word(data, 22)?)))
}

/*
ElfHeader parses the fixed ELF header and resolves standard or extended table counts.
The resolved record gives both buffered and paged readers the same checked table geometry.
*/
impl ElfHeader {
    fn parse(data: &[u8], file_len: u64) -> Result<Self, String> {
        /*
        The identification section selects a supported class, byte order, and ELF version.
        The complete fixed header must exist before later fields are read.
        */
        if !data.starts_with(ELF_MAGIC) {
            return Err("The file is not an ELF file.".into());
        }
        let bits = match data.get(4) {
            Some(1) => 32,
            Some(2) => 64,
            Some(_) => return Err("The ELF class is unsupported.".into()),
            None => return Err("The ELF identification is incomplete.".into()),
        };
        match data.get(5) {
            Some(1) => {}
            Some(2) => return Err("Big-endian ELF files are unsupported.".into()),
            Some(_) => return Err("The ELF byte order is unsupported.".into()),
            None => return Err("The ELF identification is incomplete.".into()),
        }
        if data.get(6) != Some(&1) {
            return Err("The ELF identification version is unsupported.".into());
        }
        let expected_header = if bits == 32 {
            ELF32_HEADER_SIZE
        } else {
            ELF64_HEADER_SIZE
        };
        if data.len() < expected_header || file_len < expected_header as u64 {
            return Err("The ELF header is incomplete.".into());
        }

        /*
        The common section accepts relocatable, executable, and shared-object images only.
        Class-specific offsets then select the entry and table fields.
        */
        let file_type = word(data, 16)?;
        if !matches!(file_type, 1..=3) {
            return Err("The ELF file type is unsupported.".into());
        }
        if dword(data, 20)? != 1 {
            return Err("The ELF header version is unsupported.".into());
        }
        let (
            entry,
            program_offset,
            section_offset,
            header_size_at,
            program_size_at,
            program_count_at,
            section_size_at,
            section_count_at,
            section_names_at,
        ) = if bits == 32 {
            (
                u64::from(dword(data, 24)?),
                u64::from(dword(data, 28)?),
                u64::from(dword(data, 32)?),
                40,
                42,
                44,
                46,
                48,
                50,
            )
        } else {
            (
                qword(data, 24)?,
                qword(data, 32)?,
                qword(data, 40)?,
                52,
                54,
                56,
                58,
                60,
                62,
            )
        };
        if usize::from(word(data, header_size_at)?) != expected_header {
            return Err("The ELF header size is invalid.".into());
        }

        /*
        The table section checks required entry sizes and count-to-offset agreement.
        Extended counts remain unresolved until a validated section header zero is available.
        */
        let expected_program = if bits == 32 {
            ELF32_PROGRAM_SIZE
        } else {
            ELF64_PROGRAM_SIZE
        };
        let program_size = usize::from(word(data, program_size_at)?);
        let program_count = usize::from(word(data, program_count_at)?);
        let section_size = usize::from(word(data, section_size_at)?);
        let section_count = usize::from(word(data, section_count_at)?);
        let section_names = usize::from(word(data, section_names_at)?);
        if program_count != 0 && program_size < expected_program {
            return Err("The ELF program-header entry size is invalid.".into());
        }
        if program_count == 0 && program_offset != 0 {
            return Err("The ELF program-header count is zero for a nonzero table offset.".into());
        }
        if program_count != 0 && program_offset == 0 {
            return Err("The ELF program-header table has a zero file offset.".into());
        }
        if program_count != 0 && program_offset < expected_header as u64 {
            return Err("The ELF program-header table overlaps the ELF header.".into());
        }
        Ok(Self {
            bits,
            file_type,
            machine: word(data, 18)?,
            entry,
            program_offset,
            section_offset,
            program_size,
            program_count,
            section_size,
            section_count,
            section_names,
        })
    }

    /*
    This fact identifies each header value that uses canonical data from section header zero.
    The buffered or paged constructor reads that section only when one value requires it.
    */
    fn needs_section_zero(self) -> bool {
        self.program_count == 0xffff
            || (self.section_count == 0 && self.section_offset != 0)
            || self.section_names == 0xffff
    }

    fn resolve_counts(&mut self, section_zero: Option<&[u8]>) -> Result<(), String> {
        /*
        The extended-count section reads canonical values only from section header zero.
        A nonzero section type or a short-form extended value is invalid.
        */
        let extended_programs = self.program_count == 0xffff;
        let extended_sections = self.section_count == 0 && self.section_offset != 0;
        let extended_names = self.section_names == 0xffff;
        if self.needs_section_zero() {
            let section =
                section_zero.ok_or("The ELF extended counts require section header 0.")?;
            if dword(section, 4)? != 0 {
                return Err("ELF section header 0 has a nonzero type.".into());
            }
            let (size, link, info) = if self.bits == 32 {
                (
                    u64::from(dword(section, 20)?),
                    dword(section, 24)?,
                    dword(section, 28)?,
                )
            } else {
                (
                    qword(section, 32)?,
                    dword(section, 40)?,
                    dword(section, 44)?,
                )
            };
            if extended_programs {
                self.program_count = info as usize;
                if self.program_count < 0xffff {
                    return Err("The ELF extended program-header count is not canonical.".into());
                }
            }
            if extended_sections {
                self.section_count = usize::try_from(size)
                    .map_err(|_| "The ELF section-header count is too large.")?;
                if self.section_count == 0 {
                    return Err("The ELF extended section-header count is zero.".into());
                }
                if self.section_count < ELF_RESERVED_INDEX_START {
                    return Err("The ELF extended section-header count is not canonical.".into());
                }
            }
            if extended_names {
                self.section_names = link as usize;
                if self.section_names < ELF_RESERVED_INDEX_START {
                    return Err("The ELF extended section-name index is not canonical.".into());
                }
            }
        }

        /*
        The final count section enforces allocation limits and complete table descriptions.
        The next parser stage can calculate table ends without unbounded arithmetic.
        */
        if self.program_count > ELF_MAX_ENTRIES {
            return Err(format!(
                "The ELF program-header count exceeds the limit of {ELF_MAX_ENTRIES}."
            ));
        }
        if self.section_count > ELF_MAX_ENTRIES {
            return Err(format!(
                "The ELF section-header count exceeds the limit of {ELF_MAX_ENTRIES}."
            ));
        }
        let expected_program = if self.bits == 32 {
            ELF32_PROGRAM_SIZE
        } else {
            ELF64_PROGRAM_SIZE
        };
        let expected_section = if self.bits == 32 {
            ELF32_SECTION_SIZE
        } else {
            ELF64_SECTION_SIZE
        };
        if self.program_count != 0
            && (self.program_offset == 0 || self.program_size < expected_program)
        {
            return Err("The ELF program-header table is invalid.".into());
        }
        if (self.program_count as u64)
            .checked_mul(self.program_size as u64)
            .is_none_or(|bytes| bytes > ELF_MAX_PROGRAM_BYTES)
        {
            return Err("The ELF program-header table exceeds the 8 MiB limit.".into());
        }
        if self.section_count == 0 {
            if self.section_offset != 0 || self.section_names != 0 {
                return Err("The ELF section-header table is invalid.".into());
            }
        } else {
            if self.section_offset == 0 || self.section_size < expected_section {
                return Err("The ELF section-header table is invalid.".into());
            }
            if self.section_names >= self.section_count && self.section_names != 0 {
                return Err("The ELF section-name index is outside the section table.".into());
            }
        }
        Ok(())
    }
}

/*
This helper calculates one complete ELF table range inside the logical file.
Zero-count tables keep their validated zero offsets, and nonzero tables use checked multiplication.
*/
fn checked_elf_table(
    offset: u64,
    count: usize,
    size: usize,
    file_len: u64,
    what: &str,
) -> Result<u64, String> {
    let bytes = (count as u64)
        .checked_mul(size as u64)
        .ok_or_else(|| format!("The ELF {what} range exceeds the address range."))?;
    offset
        .checked_add(bytes)
        .filter(|&end| end <= file_len)
        .ok_or_else(|| format!("The ELF {what} range is outside the file."))
}

/*
This helper validates one nonempty file-backed executable section range.
The returned temporary range proves both checked ends without adding a stored section index.
*/
fn elf_executable_section(
    data: &[u8],
    header: &ElfHeader,
    file_len: u64,
) -> Result<Option<std::ops::Range<u64>>, String> {
    let section_type = dword(data, 4)?;
    let (flags, offset, size) = if header.bits == 32 {
        (
            u64::from(dword(data, 8)?),
            u64::from(dword(data, 16)?),
            u64::from(dword(data, 20)?),
        )
    } else {
        (qword(data, 8)?, qword(data, 24)?, qword(data, 32)?)
    };
    if flags & 4 == 0 || section_type == 8 || size == 0 {
        return Ok(None);
    }
    let end = offset
        .checked_add(size)
        .filter(|&end| end <= file_len)
        .ok_or("An executable ELF section range is outside the file.")?;
    Ok(Some(offset..end))
}

/*
This helper returns a validated section header zero only when extended counts need it.
The returned slice belongs to the current buffered source and contains one full declared entry.
*/
fn elf_section_zero<'a>(data: &'a [u8], header: &ElfHeader) -> Result<Option<&'a [u8]>, String> {
    if !header.needs_section_zero() {
        return Ok(None);
    }
    let expected = if header.bits == 32 {
        ELF32_SECTION_SIZE
    } else {
        ELF64_SECTION_SIZE
    };
    if header.section_size < expected || header.section_offset == 0 {
        return Err("The ELF extended counts require a valid section header 0.".into());
    }
    if header.section_offset
        < if header.bits == 32 {
            ELF32_HEADER_SIZE as u64
        } else {
            ELF64_HEADER_SIZE as u64
        }
    {
        return Err("ELF section header 0 overlaps the ELF header.".into());
    }
    let start = usize::try_from(header.section_offset)
        .map_err(|_| "The ELF section-header table offset exceeds the address range.")?;
    let end = start
        .checked_add(header.section_size)
        .ok_or("The ELF section-header table range exceeds the address range.")?;
    data.get(start..end)
        .map(Some)
        .ok_or_else(|| "The ELF section-header table is incomplete.".into())
}

/*
ElfSegment reads one class-specific program entry and validates PT_LOAD geometry.
Non-load entries remain available to the buffered structure browser.
*/
impl ElfSegment {
    fn parse(data: &[u8], header: &ElfHeader, index: usize) -> Result<Self, String> {
        /*
        The location section calculates the original program-header file offset with checked arithmetic.
        Structure rows later use this offset when a program has no file data.
        */
        let entry_offset = (index as u64)
            .checked_mul(header.program_size as u64)
            .and_then(|value| header.program_offset.checked_add(value))
            .ok_or("The ELF program-header offset exceeds the address range.")?;
        /*
        The field section decodes the class-specific order into one common segment record.
        The validator then applies PT_LOAD rules without class-specific branches.
        */
        let (segment_type, flags, offset, address, file_size, memory_size, align) =
            if header.bits == 32 {
                (
                    dword(data, 0)?,
                    dword(data, 24)?,
                    u64::from(dword(data, 4)?),
                    u64::from(dword(data, 8)?),
                    u64::from(dword(data, 16)?),
                    u64::from(dword(data, 20)?),
                    u64::from(dword(data, 28)?),
                )
            } else {
                (
                    dword(data, 0)?,
                    dword(data, 4)?,
                    qword(data, 8)?,
                    qword(data, 16)?,
                    qword(data, 32)?,
                    qword(data, 40)?,
                    qword(data, 48)?,
                )
            };
        Ok(Self {
            header: entry_offset,
            segment_type,
            flags,
            offset,
            address,
            file_size,
            memory_size,
            align,
        })
    }

    fn validate(self, bits: u32, file_len: u64) -> Result<(), String> {
        /*
        The core mapping section ignores non-PT_LOAD programs after their fixed fields parse.
        The buffered browser applies its separate rules to all visible programs.
        */
        if self.segment_type != 1 {
            return Ok(());
        }
        /*
        The range section checks exact file and virtual ends before later mapping arithmetic.
        ELF32 permits an end equal to 2^32 but rejects a larger end.
        */
        let file_end = self
            .offset
            .checked_add(self.file_size)
            .filter(|&end| end <= file_len)
            .ok_or("An ELF segment file range is outside the file.")?;
        let memory_end = self
            .address
            .checked_add(self.memory_size)
            .ok_or("An ELF segment virtual range exceeds the address range.")?;
        if bits == 32
            && (file_end > u64::from(u32::MAX) + 1 || memory_end > u64::from(u32::MAX) + 1)
        {
            return Err("An ELF32 segment range exceeds the 32-bit address range.".into());
        }
        /*
        The geometry section validates the declared alignment and file-to-memory size relation.
        A successful segment can enter the bounded alias checks in the shared constructor.
        */
        if self.align > 1
            && (!self.align.is_power_of_two()
                || self.offset % self.align != self.address % self.align)
        {
            return Err("An ELF segment has invalid alignment.".into());
        }
        if self.file_size > self.memory_size {
            return Err("An ELF PT_LOAD file size exceeds its memory size.".into());
        }
        Ok(())
    }
}

/*
This layout check prevents tables from covering the fixed header or each other.
It runs after extended counts produce the final table ends.
*/
fn validate_elf_table_layout(
    header: &ElfHeader,
    program_end: u64,
    section_end: u64,
) -> Result<(), String> {
    let header_size = if header.bits == 32 {
        ELF32_HEADER_SIZE as u64
    } else {
        ELF64_HEADER_SIZE as u64
    };
    if header.section_count != 0 && header.section_offset < header_size {
        return Err("The ELF section-header table overlaps the ELF header.".into());
    }
    if header.program_count != 0
        && header.section_count != 0
        && elf_ranges_overlap(
            (header.section_offset, section_end),
            (header.program_offset, program_end),
        )
    {
        return Err("The ELF program-header and section-header tables overlap.".into());
    }
    Ok(())
}

/*
Elf constructors collect checked load maps and validate executable section ranges from buffered or paged sources.
Both paths pass the same parts to from_parts before metadata becomes visible.
*/
impl Elf {
    fn read(data: &[u8]) -> Result<Self, String> {
        /*
        The header section resolves counts and validates both complete table ranges.
        Later loops can index declared entries without partial slices.
        */
        let mut header = ElfHeader::parse(data, data.len() as u64)?;
        let section_zero = elf_section_zero(data, &header)?;
        header.resolve_counts(section_zero)?;
        let program_end = checked_elf_table(
            header.program_offset,
            header.program_count,
            header.program_size,
            data.len() as u64,
            "program-header table",
        )?;
        let section_end = checked_elf_table(
            header.section_offset,
            header.section_count,
            header.section_size,
            data.len() as u64,
            "section-header table",
        )?;
        validate_elf_table_layout(&header, program_end, section_end)?;

        /*
        The program section keeps only PT_LOAD entries in the core map.
        Each entry keeps its exact declared file and virtual ranges.
        */
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(header.program_count.min(ELF_MAX_LOAD_SEGMENTS))
            .map_err(|_| "Cannot allocate the ELF program headers.")?;
        for index in 0..header.program_count {
            let start =
                usize::try_from(header.program_offset + index as u64 * header.program_size as u64)
                    .map_err(|_| "The ELF program-header offset exceeds the address range.")?;
            let entry = &data[start..start + header.program_size];
            let segment = ElfSegment::parse(entry, &header, index)?;
            if segment.segment_type == 1 {
                segment.validate(header.bits, data.len() as u64)?;
                if segments.len() >= ELF_MAX_LOAD_SEGMENTS {
                    return Err(format!(
                        "The ELF PT_LOAD count exceeds the limit of {ELF_MAX_LOAD_SEGMENTS}."
                    ));
                }
                segments.push(segment);
            }
        }

        /*
        The section loop validates current file-backed executable sections.
        The final constructor checks machine pairs and mapping aliases.
        */
        for index in 1..header.section_count {
            let start =
                usize::try_from(header.section_offset + index as u64 * header.section_size as u64)
                    .map_err(|_| "The ELF section-header offset exceeds the address range.")?;
            let _ = elf_executable_section(
                &data[start..start + header.section_size],
                &header,
                data.len() as u64,
            )?;
        }
        Self::from_parts(header, segments, data.len() as u64)
    }

    fn read_from(file: &PagedFile, prefix: &[u8]) -> Result<Self, String> {
        /*
        The paged header section reads section header zero only for extended counts.
        The declared entry size remains below one 64 KiB logical read.
        */
        let mut header = ElfHeader::parse(prefix, file.len())?;
        let needs_section_zero = header.needs_section_zero();
        let expected_section = if header.bits == 32 {
            ELF32_SECTION_SIZE
        } else {
            ELF64_SECTION_SIZE
        };
        if needs_section_zero
            && (header.section_size < expected_section || header.section_offset == 0)
        {
            return Err("The ELF extended counts require a valid section header 0.".into());
        }
        if needs_section_zero
            && header.section_offset
                < if header.bits == 32 {
                    ELF32_HEADER_SIZE as u64
                } else {
                    ELF64_HEADER_SIZE as u64
                }
        {
            return Err("ELF section header 0 overlaps the ELF header.".into());
        }
        let mut section_zero = Vec::new();
        section_zero
            .try_reserve_exact(header.section_size.max(expected_section))
            .map_err(|_| "Cannot allocate ELF section header 0.")?;
        section_zero.resize(header.section_size.max(expected_section), 0);
        let section_zero = if needs_section_zero {
            read_paged_exact(
                file,
                header.section_offset,
                &mut section_zero,
                "ELF section header 0",
            )?;
            Some(section_zero.as_slice())
        } else {
            None
        };
        header.resolve_counts(section_zero)?;
        let program_end = checked_elf_table(
            header.program_offset,
            header.program_count,
            header.program_size,
            file.len(),
            "program-header table",
        )?;
        let section_end = checked_elf_table(
            header.section_offset,
            header.section_count,
            header.section_size,
            file.len(),
            "section-header table",
        )?;
        validate_elf_table_layout(&header, program_end, section_end)?;

        /*
        The paged program loop groups complete entries into reads of at most 64 KiB.
        Only validated PT_LOAD entries enter the shared map.
        */
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(header.program_count.min(ELF_MAX_LOAD_SEGMENTS))
            .map_err(|_| "Cannot allocate the ELF program headers.")?;
        let entries_per_read = (crate::paged::MAX_READ_BYTES / header.program_size.max(1)).max(1);
        let mut first = 0usize;
        while first < header.program_count {
            let count = entries_per_read.min(header.program_count - first);
            let byte_count = count * header.program_size;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(byte_count)
                .map_err(|_| "Cannot allocate the ELF program-header window.")?;
            bytes.resize(byte_count, 0);
            let offset = header
                .program_offset
                .checked_add(first as u64 * header.program_size as u64)
                .ok_or("The ELF program-header offset exceeds the address range.")?;
            read_paged_exact(file, offset, &mut bytes, "ELF program-header table")?;
            for local in 0..count {
                let start = local * header.program_size;
                let segment = ElfSegment::parse(
                    &bytes[start..start + header.program_size],
                    &header,
                    first + local,
                )?;
                if segment.segment_type == 1 {
                    segment.validate(header.bits, file.len())?;
                    if segments.len() >= ELF_MAX_LOAD_SEGMENTS {
                        return Err(format!(
                            "The ELF PT_LOAD count exceeds the limit of {ELF_MAX_LOAD_SEGMENTS}."
                        ));
                    }
                    segments.push(segment);
                }
            }
            first += count;
        }

        /*
        The paged section loop applies the same 64 KiB read rule to executable-section checks.
        The shared constructor receives exact high offsets without a full-file allocation.
        */
        let entries_per_read = (crate::paged::MAX_READ_BYTES / header.section_size.max(1)).max(1);
        let mut first = 1usize;
        while first < header.section_count {
            let count = entries_per_read.min(header.section_count - first);
            let byte_count = count * header.section_size;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(byte_count)
                .map_err(|_| "Cannot allocate the ELF section-header window.")?;
            bytes.resize(byte_count, 0);
            let offset = header
                .section_offset
                .checked_add(first as u64 * header.section_size as u64)
                .ok_or("The ELF section-header offset exceeds the address range.")?;
            read_paged_exact(file, offset, &mut bytes, "ELF section-header table")?;
            for local in 0..count {
                let start = local * header.section_size;
                let _ = elf_executable_section(
                    &bytes[start..start + header.section_size],
                    &header,
                    file.len(),
                )?;
            }
            first += count;
        }
        Self::from_parts(header, segments, file.len())
    }

    fn from_parts(
        header: ElfHeader,
        segments: Vec<ElfSegment>,
        file_len: u64,
    ) -> Result<Self, String> {
        /*
        This section rejects known machine and class mismatches before Code selection.
        Unknown machines keep inspectable metadata and fail only at the Code capability boundary.
        */
        match (header.machine, header.bits) {
            (3, 64) | (EM_ARM, 64) | (62 | 183, 32) => {
                return Err("The ELF machine does not match the ELF class.".into());
            }
            _ => {}
        }
        if segments.len() > ELF_MAX_LOAD_SEGMENTS {
            return Err(format!(
                "The ELF PT_LOAD count exceeds the limit of {ELF_MAX_LOAD_SEGMENTS}."
            ));
        }
        let elf = Self {
            header,
            segments,
            file_len,
        };
        elf.validate_load_aliases()?;
        Ok(elf)
    }

    fn architecture(&self) -> Result<Architecture, String> {
        /*
        This selector matches each supported machine with its required ELF class.
        ARM also uses the checked entry-state bits to select ARM or Thumb decoding.
        */
        match (self.header.machine, self.header.bits) {
            (3, 32) => Ok(Architecture::X86(32)),
            (62, 64) => Ok(Architecture::X86(64)),
            (183, 64) => Ok(Architecture::Arm64),
            (EM_ARM, 32) if self.header.file_type == 1 || self.header.entry == 0 => Err(
                "ELF ARM files without an entry point require an explicit ARM or Thumb raw model."
                    .into(),
            ),
            (EM_ARM, 32) if self.header.entry & 1 != 0 => Ok(Architecture::Thumb),
            (EM_ARM, 32) if self.header.entry & 3 == 0 => Ok(Architecture::Arm),
            (EM_ARM, 32) => Err("The ELF ARM entry point has a reserved state value.".into()),
            _ => Err("The ELF processor is unsupported for code decoding.".into()),
        }
    }

    fn validate_load_aliases(&self) -> Result<(), String> {
        /*
        The bounded pair check compares file-to-VA and VA-to-file meanings for all PT_LOAD ranges.
        Identical aliases remain valid, while file-backed and zero-fill conflicts fail.
        */
        // ponytail: The 256-load limit bounds this pair check. Use a sweep if that limit increases.
        for (index, left) in self.segments.iter().enumerate() {
            for right in &self.segments[index + 1..] {
                /*
                The file-overlap section requires equal virtual addresses for every shared file byte.
                Checked deltas prevent high virtual addresses from overflowing before comparison.
                */
                let file_start = left.offset.max(right.offset);
                let file_end = (left.offset + left.file_size).min(right.offset + right.file_size);
                if file_start < file_end {
                    let left_delta = file_start - left.offset;
                    let right_delta = file_start - right.offset;
                    let left_address = left
                        .address
                        .checked_add(left_delta)
                        .ok_or("An ELF segment virtual range exceeds the address range.")?;
                    let right_address = right
                        .address
                        .checked_add(right_delta)
                        .ok_or("An ELF segment virtual range exceeds the address range.")?;
                    if left_address != right_address {
                        return Err("Two ELF PT_LOAD file ranges have ambiguous mappings.".into());
                    }
                }

                /*
                The virtual-overlap section divides the shared range at each file-backed boundary.
                Each interval must map to the same file offset or to the same zero-fill state.
                */
                let virtual_start = left.address.max(right.address);
                let virtual_end =
                    (left.address + left.memory_size).min(right.address + right.memory_size);
                if virtual_start >= virtual_end {
                    continue;
                }
                let mut boundaries = [
                    virtual_start,
                    virtual_end,
                    (left.address + left.file_size).clamp(virtual_start, virtual_end),
                    (right.address + right.file_size).clamp(virtual_start, virtual_end),
                ];
                boundaries.sort_unstable();
                for window in boundaries.windows(2).filter(|window| window[0] < window[1]) {
                    let address = window[0];
                    let left_delta = address - left.address;
                    let left_file = if left_delta < left.file_size {
                        Some(
                            left.offset
                                .checked_add(left_delta)
                                .ok_or("An ELF segment file range exceeds the address range.")?,
                        )
                    } else {
                        None
                    };
                    let right_delta = address - right.address;
                    let right_file = if right_delta < right.file_size {
                        Some(
                            right
                                .offset
                                .checked_add(right_delta)
                                .ok_or("An ELF segment file range exceeds the address range.")?,
                        )
                    } else {
                        None
                    };
                    if left_file != right_file {
                        return Err(
                            "Two ELF PT_LOAD virtual ranges have ambiguous mappings.".into()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn file_to_virtual(&self, offset: u64) -> Result<Option<u64>, String> {
        /*
        This forward conversion gives relocatable files no virtual mapping.
        Mapped files compare all file-backed PT_LOAD results and reject different aliases.
        */
        if self.header.file_type == 1 {
            return Ok(None);
        }
        let mut result = None;
        for segment in &self.segments {
            let Some(delta) = offset.checked_sub(segment.offset) else {
                continue;
            };
            if delta >= segment.file_size {
                continue;
            }
            let address = segment
                .address
                .checked_add(delta)
                .ok_or("An ELF segment virtual range exceeds the address range.")?;
            if result.is_some_and(|previous| previous != address) {
                return Err("The ELF file offset has ambiguous virtual mappings.".into());
            }
            result = Some(address);
        }
        Ok(result)
    }

    fn virtual_to_file(&self, address: u64) -> Result<Option<u64>, String> {
        /*
        This strict reverse conversion rejects relocatable files and addresses outside all load ranges.
        A valid memory-only address returns no file byte through the inner optional result.
        */
        if self.header.file_type == 1 {
            return Err("ELF relocatable files have no virtual address mapping.".into());
        }
        self.virtual_mapping(address)?
            .ok_or_else(|| "The virtual address is outside the ELF load image.".into())
    }

    fn virtual_mapping(&self, address: u64) -> Result<Option<Option<u64>>, String> {
        /*
        This mapping helper compares all PT_LOAD ranges that contain one virtual address.
        File-backed ranges calculate offsets, while zero-fill ranges avoid unused offset arithmetic.
        */
        let mut result: Option<Option<u64>> = None;
        for segment in &self.segments {
            let Some(delta) = address.checked_sub(segment.address) else {
                continue;
            };
            if delta >= segment.memory_size {
                continue;
            }
            let file = if delta < segment.file_size {
                Some(
                    segment
                        .offset
                        .checked_add(delta)
                        .ok_or("An ELF segment file range exceeds the address range.")?,
                )
            } else {
                None
            };
            if result.is_some_and(|previous| previous != file) {
                return Err("The ELF virtual address has ambiguous PT_LOAD mappings.".into());
            }
            result = Some(file);
        }
        Ok(result)
    }

    fn entry_offset(&self) -> Result<Option<u64>, String> {
        /*
        The availability section removes entries from relocatable files and files with a zero entry.
        Other files continue to architecture-specific entry normalization.
        */
        if self.header.file_type == 1 || self.header.entry == 0 {
            return Ok(None);
        }
        /*
        The ARM section clears the Thumb state bit and rejects the reserved low-bit state.
        The final mapping accepts the entry only when its VA identifies one file byte.
        */
        let entry = if self.header.machine == EM_ARM && self.header.bits == 32 {
            if self.header.entry & 1 != 0 {
                self.header.entry & !1
            } else if self.header.entry & 3 == 0 {
                self.header.entry
            } else {
                return Err("The ELF ARM entry point has a reserved state value.".into());
            }
        } else {
            self.header.entry
        };
        Ok(self.virtual_mapping(entry)?.flatten())
    }

    fn convert_address(
        &self,
        kind: AddressKind,
        value: u64,
        file_len: Option<u64>,
    ) -> Result<PeAddress, String> {
        /*
        This domain conversion rejects RVA because ELF defines no PE-style image-relative address.
        File input can return a partial unmapped result, while VA input can return zero-fill without a file byte.
        */
        match kind {
            AddressKind::Rva => Err("ELF files have no RVA.".into()),
            AddressKind::File => {
                if file_len.is_some_and(|len| value >= len) {
                    return Err("The file offset has no file byte.".into());
                }
                let file_offset = usize::try_from(value)
                    .map_err(|_| "The file offset exceeds the address range.")?;
                Ok(PeAddress {
                    file_offset: Some(file_offset),
                    rva: None,
                    va: self.file_to_virtual(value)?,
                })
            }
            AddressKind::Va => {
                let file = self.virtual_to_file(value)?;
                let file_offset = file
                    .map(|offset| {
                        usize::try_from(offset)
                            .map_err(|_| "The file offset exceeds the address range.")
                    })
                    .transpose()?;
                Ok(PeAddress {
                    file_offset,
                    rva: None,
                    va: Some(value),
                })
            }
        }
    }
}

/*
These constants name PE directories and bound browser table and string reads.
The table and string limits are separate from the caller's final row cap.
*/
const DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "Relocation",
    "Debug",
    "Architecture",
    "Global pointer",
    "TLS",
    "Load configuration",
    "Bound import",
    "Import address table",
    "Delay import",
    "CLR runtime header",
    "Reserved",
];
const MAX_BROWSER_ENTRIES: usize = 100_000;
const MAX_NAME_BYTES: usize = 4_096;

/*
AddressKind identifies the user input domain for general address conversion.
PeAddress returns every domain that the selected source location can represent.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    File,
    Rva,
    Va,
}

/*
PeAddress contains each available file, RVA, and virtual-address result.
An absent field identifies a valid partial mapping.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeAddress {
    pub file_offset: Option<usize>,
    pub rva: Option<u32>,
    pub va: Option<u64>,
}

/*
These browser records retain validated PE directory and section data for structure rows.
The browser keeps display limits separate from file mapping validation.
*/
#[derive(Clone, Copy)]
struct BrowserDirectory {
    rva: u32,
    size: u32,
}

struct BrowserSection {
    name: String,
    header: usize,
    virtual_size: u32,
    rva: u32,
    raw_size: u32,
    raw: u32,
    characteristics: u32,
}

struct BrowserPe {
    bits: u32,
    image_base: u64,
    header_size: u32,
    sections: Vec<BrowserSection>,
    directories: [Option<BrowserDirectory>; 16],
}

/*
BrowserElfSection retains validated section data and its raw name range in the source.
BrowserElf keeps complete program and section rows beside the smaller shared ELF map.
Name ranges permit complete validation without escaped text allocation for discarded rows.
*/
struct BrowserElfSection {
    name: std::ops::Range<usize>,
    name_offset: u32,
    header: usize,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    align: u64,
    entry_size: u64,
}

struct BrowserElf {
    header: ElfHeader,
    segments: Vec<ElfSegment>,
    sections: Vec<BrowserElfSection>,
    mapping: Elf,
}

/*
These fixed-width helpers validate PE browser ranges before they read little-endian values.
Later import and export readers use the same checked arithmetic.
*/
fn browser_range(data: &[u8], at: usize, size: usize, what: &str) -> Result<(), String> {
    at.checked_add(size)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| format!("The {what} range is outside the file."))?;
    Ok(())
}

fn browser_word(data: &[u8], at: usize, what: &str) -> Result<u16, String> {
    browser_range(data, at, 2, what)?;
    Ok(u16::from_le_bytes(data[at..at + 2].try_into().unwrap()))
}

fn browser_dword(data: &[u8], at: usize, what: &str) -> Result<u32, String> {
    browser_range(data, at, 4, what)?;
    Ok(u32::from_le_bytes(data[at..at + 4].try_into().unwrap()))
}

fn browser_qword(data: &[u8], at: usize, what: &str) -> Result<u64, String> {
    browser_range(data, at, 8, what)?;
    Ok(u64::from_le_bytes(data[at..at + 8].try_into().unwrap()))
}

/*
This helper escapes control and non-ASCII bytes for browser row text.
The output does not change the source name or its file offset.
*/
fn escaped(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &byte in bytes {
        for value in std::ascii::escape_default(byte) {
            text.push(char::from(value));
        }
    }
    text
}

/*
This helper checks one table count against the browser entry cap and byte-size arithmetic.
The returned byte count does not limit the final display row count.
*/
fn checked_count(count: u32, unit: usize, what: &str) -> Result<usize, String> {
    let count = usize::try_from(count).map_err(|_| format!("The {what} count is too large."))?;
    if count > MAX_BROWSER_ENTRIES {
        return Err(format!(
            "The {what} count exceeds the browser limit of {MAX_BROWSER_ENTRIES}."
        ));
    }
    count
        .checked_mul(unit)
        .ok_or_else(|| format!("The {what} range exceeds the address range."))
}

/*
This helper converts one ELF file range into a buffered slice range.
The browser uses the result for section data and the section-name string table.
*/
fn elf_range(
    data: &[u8],
    at: u64,
    size: u64,
    what: &str,
) -> Result<std::ops::Range<usize>, String> {
    let end = at
        .checked_add(size)
        .filter(|&end| end <= data.len() as u64)
        .ok_or_else(|| format!("The ELF {what} range is outside the file."))?;
    Ok(
        usize::try_from(at).map_err(|_| format!("The ELF {what} offset is too large."))?
            ..usize::try_from(end).map_err(|_| format!("The ELF {what} range is too large."))?,
    )
}

/*
This predicate compares two half-open ELF ranges.
Empty ranges never overlap and adjacent ranges remain valid.
*/
fn elf_ranges_overlap(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

/*
The browser validates all declared program segments, including entries that do not affect address mapping.
PT_LOAD entries receive the stronger file-size and congruent-alignment checks.
*/
impl ElfSegment {
    fn validate_browser(self, bits: u32, file_len: u64) -> Result<(), String> {
        if self.segment_type == 0 {
            return Ok(());
        }
        let file_end = self
            .offset
            .checked_add(self.file_size)
            .filter(|&end| end <= file_len)
            .ok_or("An ELF program segment file range is outside the file.")?;
        let memory_end = self
            .address
            .checked_add(self.memory_size)
            .ok_or("An ELF program segment virtual range exceeds the address range.")?;
        if bits == 32
            && (file_end > u64::from(u32::MAX) + 1 || memory_end > u64::from(u32::MAX) + 1)
        {
            return Err("An ELF32 program segment range exceeds the 32-bit address range.".into());
        }
        if self.align > 1
            && (!self.align.is_power_of_two()
                || (self.segment_type == 1
                    && self.offset % self.align != self.address % self.align))
        {
            return Err("An ELF program segment has invalid alignment.".into());
        }
        if self.segment_type == 1 && self.file_size > self.memory_size {
            return Err("An ELF PT_LOAD file size exceeds its memory size.".into());
        }
        Ok(())
    }
}

/*
BrowserElfSection parses one class-specific section entry and validates its declared data rules.
Names remain unresolved until the complete section-name table passes validation.
*/
impl BrowserElfSection {
    fn parse(data: &[u8], header: &ElfHeader, index: usize) -> Result<Self, String> {
        /*
        The location section calculates one declared section-header file offset.
        NOBITS and empty rows later use this offset as their selectable source location.
        */
        let table_delta = (index as u64)
            .checked_mul(header.section_size as u64)
            .ok_or("The ELF section-header offset exceeds the address range.")?;
        let header_offset = header
            .section_offset
            .checked_add(table_delta)
            .ok_or("The ELF section-header offset exceeds the address range.")?;
        /*
        The field section converts either class layout into one common browser record.
        Name bytes remain unresolved until the complete string table passes validation.
        */
        let (name_offset, section_type, flags, address, offset, size, align, entry_size) =
            if header.bits == 32 {
                (
                    dword(data, 0)?,
                    dword(data, 4)?,
                    u64::from(dword(data, 8)?),
                    u64::from(dword(data, 12)?),
                    u64::from(dword(data, 16)?),
                    u64::from(dword(data, 20)?),
                    u64::from(dword(data, 32)?),
                    u64::from(dword(data, 36)?),
                )
            } else {
                (
                    dword(data, 0)?,
                    dword(data, 4)?,
                    qword(data, 8)?,
                    qword(data, 16)?,
                    qword(data, 24)?,
                    qword(data, 32)?,
                    qword(data, 48)?,
                    qword(data, 56)?,
                )
            };
        Ok(Self {
            name: 0..0,
            name_offset,
            header: usize::try_from(header_offset)
                .map_err(|_| "The ELF section-header offset is too large.")?,
            section_type,
            flags,
            address,
            offset,
            size,
            align,
            entry_size,
        })
    }

    fn validate(&self, data: &[u8], bits: u32, index: usize) -> Result<(), String> {
        /*
        The identity section keeps section header zero canonical and checks the complete virtual end.
        ELF32 permits a virtual end equal to 2^32.
        */
        if index == 0 && self.section_type != 0 {
            return Err("ELF section header 0 has a nonzero type.".into());
        }
        let memory_end = self
            .address
            .checked_add(self.size)
            .ok_or("An ELF section address range exceeds the address range.")?;
        if bits == 32 && memory_end > u64::from(u32::MAX) + 1 {
            return Err("An ELF32 section range exceeds the 32-bit address range.".into());
        }
        /*
        The geometry section checks power-of-two alignment and declared record division.
        File-backed nonzero sections must also own their complete current source range.
        */
        if self.align > 1 && !self.align.is_power_of_two() {
            return Err("An ELF section has invalid alignment.".into());
        }
        if self.entry_size != 0 && !self.size.is_multiple_of(self.entry_size) {
            return Err("An ELF section size is not a multiple of its entry size.".into());
        }
        if index != 0 && self.section_type != 8 && self.size != 0 {
            elf_range(data, self.offset, self.size, "section data")?;
        }
        Ok(())
    }
}

/*
BrowserElf validates complete buffered program, section, and section-name tables before it exposes rows.
The parser reuses the shared mapping constructor after browser-specific checks pass.
*/
impl BrowserElf {
    fn parse(data: &[u8]) -> Result<Self, String> {
        /*
        The header section resolves extended counts and checks both table ranges.
        The program and section tables cannot overlap the fixed header or each other.
        */
        let mut header = ElfHeader::parse(data, data.len() as u64)?;
        let expected_section = if header.bits == 32 {
            ELF32_SECTION_SIZE
        } else {
            ELF64_SECTION_SIZE
        };
        let section_zero = if header.needs_section_zero() {
            if header.section_offset == 0 || header.section_size < expected_section {
                return Err("The ELF extended counts require a valid section header 0.".into());
            }
            let range = elf_range(
                data,
                header.section_offset,
                header.section_size as u64,
                "section header 0",
            )?;
            Some(&data[range])
        } else {
            None
        };
        header.resolve_counts(section_zero)?;
        let program_end = checked_elf_table(
            header.program_offset,
            header.program_count,
            header.program_size,
            data.len() as u64,
            "program-header table",
        )?;
        let section_end = checked_elf_table(
            header.section_offset,
            header.section_count,
            header.section_size,
            data.len() as u64,
            "section-header table",
        )?;
        validate_elf_table_layout(&header, program_end, section_end)?;

        /*
        The program section keeps every row and a separate bounded PT_LOAD list.
        The shared map receives only the load entries after complete validation.
        */
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(header.program_count)
            .map_err(|_| "Cannot allocate the ELF program headers.")?;
        let mut loads = Vec::new();
        loads
            .try_reserve_exact(header.program_count.min(ELF_MAX_LOAD_SEGMENTS))
            .map_err(|_| "Cannot allocate the ELF load segments.")?;
        for index in 0..header.program_count {
            let start =
                usize::try_from(header.program_offset + index as u64 * header.program_size as u64)
                    .map_err(|_| "The ELF program-header offset is too large.")?;
            let segment =
                ElfSegment::parse(&data[start..start + header.program_size], &header, index)?;
            segment.validate_browser(header.bits, data.len() as u64)?;
            if segment.segment_type == 1 {
                if loads.len() >= ELF_MAX_LOAD_SEGMENTS {
                    return Err(format!(
                        "The ELF PT_LOAD count exceeds the limit of {ELF_MAX_LOAD_SEGMENTS}."
                    ));
                }
                loads.push(segment);
            }
            segments.push(segment);
        }

        /*
        The section section validates all entries and rejects overlapping file-backed data.
        NOBITS sections keep virtual size but do not create raw navigation.
        */
        let mut sections = Vec::new();
        sections
            .try_reserve_exact(header.section_count)
            .map_err(|_| "Cannot allocate the ELF section headers.")?;
        for index in 0..header.section_count {
            let start =
                usize::try_from(header.section_offset + index as u64 * header.section_size as u64)
                    .map_err(|_| "The ELF section-header offset is too large.")?;
            let section = BrowserElfSection::parse(
                &data[start..start + header.section_size],
                &header,
                index,
            )?;
            section.validate(data, header.bits, index)?;
            sections.push(section);
        }
        let mut section_ranges = Vec::new();
        section_ranges
            .try_reserve_exact(sections.len().saturating_sub(1))
            .map_err(|_| "Cannot allocate the ELF section ranges.")?;
        section_ranges.extend(
            sections
                .iter()
                .skip(1)
                .filter(|section| section.section_type != 8 && section.size != 0)
                .map(|section| (section.offset, section.offset + section.size)),
        );
        section_ranges.sort_unstable();
        if section_ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
            return Err("Two ELF section file ranges overlap.".into());
        }

        /*
        The name section validates every bounded null-terminated name and retains its source range.
        Shared names do not allocate shared escaped text for every section.
        Row creation later escapes only retained names within the aggregate text limit.
        The final map then rechecks PT_LOAD aliases before the browser exposes rows.
        */
        if header.section_names == 0 {
            if sections.iter().any(|section| section.name_offset != 0) {
                return Err("An ELF section name exists without a section-name table.".into());
            }
        } else {
            let names = &sections[header.section_names];
            if names.section_type != 3 || names.size == 0 {
                return Err("The ELF section-name table is invalid.".into());
            }
            let range = elf_range(data, names.offset, names.size, "section-name table")?;
            let table_start = range.start;
            let table = &data[range];
            if table.first() != Some(&0) || table.last() != Some(&0) {
                return Err(
                    "The ELF section-name table must start and end with a null byte.".into(),
                );
            }
            for section in &mut sections {
                let offset = section.name_offset as usize;
                if offset >= table.len() {
                    return Err("An ELF section-name offset is outside the string table.".into());
                }
                let available = table.len() - offset;
                let scan = available.min(MAX_NAME_BYTES + 1);
                let Some(length) = table[offset..offset + scan]
                    .iter()
                    .position(|&byte| byte == 0)
                else {
                    if available > MAX_NAME_BYTES {
                        return Err(format!(
                            "An ELF section name exceeds the limit of {MAX_NAME_BYTES} bytes."
                        ));
                    }
                    return Err("An ELF section name is not null-terminated.".into());
                };
                section.name = table_start + offset..table_start + offset + length;
            }
        }
        let mapping = Elf::from_parts(header, loads, data.len() as u64)?;
        Ok(Self {
            header,
            segments,
            sections,
            mapping,
        })
    }
}

/*
BrowserPe validates its own PE browser map from current source bytes.
Its methods resolve source-backed ranges before they create user-visible structure rows.
*/
impl BrowserPe {
    /*
    This parser validates browser-specific PE fields and section records.
    The resulting map supports later directory, import, and export rows.
    */
    fn parse(data: &[u8]) -> Result<Self, String> {
        /*
        The first section validates the DOS, COFF, and optional headers.
        It obtains the address width and table bounds for later records.
        */
        if data.len() > u32::MAX as usize {
            return Err("PE files above 4 GB are unsupported.".into());
        }
        if !data.starts_with(b"MZ") && !data.starts_with(b"ZM") {
            return Err("The file is not a PE file.".into());
        }
        let header = browser_dword(data, 60, "DOS header")? as usize;
        browser_range(data, header, 24, "PE header")?;
        if &data[header..header + 4] != b"PE\0\0" {
            return Err("The file is not a PE file.".into());
        }
        let section_count = usize::from(browser_word(data, header + 6, "COFF header")?);
        if section_count > 96 {
            return Err("The PE section count exceeds the Windows limit of 96.".into());
        }
        let optional_size = usize::from(browser_word(data, header + 20, "COFF header")?);
        let optional = header
            .checked_add(24)
            .ok_or("The optional-header offset exceeds the address range.")?;
        browser_range(data, optional, optional_size, "optional header")?;
        let magic = browser_word(data, optional, "optional header")?;
        let (bits, image_base, directory_start, directory_count_at) = match magic {
            0x10b => (
                32,
                u64::from(browser_dword(data, optional + 28, "PE32 image base")?),
                96usize,
                92usize,
            ),
            0x20b => (
                64,
                browser_qword(data, optional + 24, "PE32+ image base")?,
                112usize,
                108usize,
            ),
            _ => return Err("The PE optional-header type is unsupported.".into()),
        };
        if optional_size < directory_start {
            return Err("The PE optional header is incomplete.".into());
        }
        let header_size = browser_dword(data, optional + 60, "header size")?;
        if header_size == 0 || header_size as usize > data.len() {
            return Err("The PE header range is outside the file.".into());
        }
        let directory_count =
            browser_dword(data, optional + directory_count_at, "data-directory count")? as usize;
        let directory_bytes = directory_count
            .checked_mul(8)
            .ok_or("The data-directory range exceeds the address range.")?;
        if directory_start
            .checked_add(directory_bytes)
            .is_none_or(|end| end > optional_size)
        {
            return Err("The data-directory table exceeds the optional header.".into());
        }
        let table = optional
            .checked_add(optional_size)
            .ok_or("The section-table offset exceeds the address range.")?;
        let table_size = section_count
            .checked_mul(40)
            .ok_or("The section-table range exceeds the address range.")?;
        browser_range(data, table, table_size, "section table")?;
        if table + table_size > header_size as usize {
            return Err("The section table exceeds the declared PE headers.".into());
        }

        /*
        The directory section records complete nonzero directory ranges.
        A half-empty directory entry cannot continue to section parsing.
        */
        let mut directories = [None; 16];
        for (index, slot) in directories
            .iter_mut()
            .enumerate()
            .take(directory_count.min(16))
        {
            let at = optional + directory_start + index * 8;
            let rva = browser_dword(data, at, "data-directory entry")?;
            let size = browser_dword(data, at + 4, "data-directory entry")?;
            if rva == 0 && size == 0 {
                continue;
            }
            if rva == 0 || size == 0 {
                return Err(format!(
                    "The {} directory has an incomplete range.",
                    DIRECTORY_NAMES[index]
                ));
            }
            *slot = Some(BrowserDirectory { rva, size });
        }

        /*
        The section-table section validates names, raw bytes, and virtual spans.
        The next overlap check receives only complete section records.
        */
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let at = table + index * 40;
            let raw_name = &data[at..at + 8];
            let name_end = raw_name
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(raw_name.len());
            let name = escaped(&raw_name[..name_end]);
            let virtual_size = browser_dword(data, at + 8, "section header")?;
            let rva = browser_dword(data, at + 12, "section header")?;
            let raw_size = browser_dword(data, at + 16, "section header")?;
            let raw = browser_dword(data, at + 20, "section header")?;
            let characteristics = browser_dword(data, at + 36, "section header")?;
            let virtual_span = u64::from(virtual_size.max(raw_size));
            let virtual_end = u64::from(rva)
                .checked_add(virtual_span)
                .ok_or("A section virtual range exceeds the address range.")?;
            if virtual_end > u64::from(u32::MAX) + 1 {
                return Err("A section virtual range exceeds the PE address range.".into());
            }
            if virtual_span != 0 && rva < header_size {
                return Err("A section virtual range overlaps the PE headers.".into());
            }
            if raw_size != 0 {
                if raw == 0 {
                    return Err("A section with raw bytes has a zero file offset.".into());
                }
                if raw < header_size {
                    return Err("A section raw range overlaps the PE headers.".into());
                }
                browser_range(data, raw as usize, raw_size as usize, "section raw data")?;
            }
            sections.push(BrowserSection {
                name,
                header: at,
                virtual_size,
                rva,
                raw_size,
                raw,
                characteristics,
            });
        }

        /*
        The overlap section rejects ambiguous raw or virtual mappings.
        The final directory check then uses one unambiguous BrowserPe map.
        */
        for (index, left) in sections.iter().enumerate() {
            for right in &sections[index + 1..] {
                if ranges_overlap(left.raw, left.raw_size, right.raw, right.raw_size) {
                    return Err("Two section raw ranges overlap.".into());
                }
                if ranges_overlap(
                    left.rva,
                    left.virtual_size.max(left.raw_size),
                    right.rva,
                    right.virtual_size.max(right.raw_size),
                ) {
                    return Err("Two section virtual ranges overlap.".into());
                }
            }
        }

        /*
        The final section validates every directory against the completed map.
        Security uses a file offset, while other directories use RVAs.
        */
        let pe = Self {
            bits,
            image_base,
            header_size,
            sections,
            directories,
        };
        for (index, directory) in pe.directories.iter().enumerate() {
            let Some(directory) = directory else {
                continue;
            };
            if index == 4 {
                browser_range(
                    data,
                    directory.rva as usize,
                    directory.size as usize,
                    "Security directory",
                )?;
            } else {
                pe.map_range(data, directory.rva, directory.size, DIRECTORY_NAMES[index])?;
            }
        }
        Ok(pe)
    }

    /*
    This helper adds one RVA to the current image base with PE width checks.
    The supplied name identifies the failed structure when overflow occurs.
    */
    fn va(&self, rva: u32, what: &str) -> Result<u64, String> {
        let va = self
            .image_base
            .checked_add(u64::from(rva))
            .ok_or_else(|| format!("The {what} virtual address exceeds the address range."))?;
        if self.bits == 32 && va > u64::from(u32::MAX) {
            return Err(format!(
                "The {what} virtual address exceeds the PE32 address range."
            ));
        }
        Ok(va)
    }

    /*
    This helper resolves a complete RVA range to file bytes.
    Partial, virtual-only, and out-of-file ranges return an error.
    */
    fn map_range(&self, data: &[u8], rva: u32, size: u32, what: &str) -> Result<usize, String> {
        if size == 0 {
            return Err(format!("The {what} range is empty."));
        }
        let end = u64::from(rva)
            .checked_add(u64::from(size))
            .ok_or_else(|| format!("The {what} RVA range exceeds the address range."))?;
        let mut mapped = None;
        if rva < self.header_size && end <= u64::from(self.header_size) {
            mapped = Some(rva as usize);
        }
        for section in &self.sections {
            if rva < section.rva {
                continue;
            }
            let delta = u64::from(rva - section.rva);
            if delta < u64::from(section.virtual_size.max(section.raw_size))
                && delta + u64::from(size) <= u64::from(section.raw_size)
            {
                let file = u64::from(section.raw)
                    .checked_add(delta)
                    .ok_or_else(|| format!("The {what} file range exceeds the address range."))?;
                let file = usize::try_from(file)
                    .map_err(|_| format!("The {what} file range exceeds the address range."))?;
                if mapped.replace(file).is_some() {
                    return Err(format!("The {what} RVA range has ambiguous file mappings."));
                }
            }
        }
        let file = mapped.ok_or_else(|| format!("The {what} RVA range has no raw bytes."))?;
        browser_range(data, file, size as usize, what)?;
        Ok(file)
    }

    /*
    This helper returns a file byte when an RVA has current source data.
    A valid virtual-only address returns no file byte.
    */
    fn virtual_file(&self, data: &[u8], rva: u32, what: &str) -> Result<Option<usize>, String> {
        let mut result = None;
        if rva < self.header_size {
            browser_range(data, rva as usize, 1, what)?;
            result = Some(Some(rva as usize));
        }
        for section in &self.sections {
            if rva < section.rva {
                continue;
            }
            let delta = u64::from(rva - section.rva);
            if delta >= u64::from(section.virtual_size.max(section.raw_size)) {
                continue;
            }
            let file =
                if delta < u64::from(section.raw_size) {
                    let file = u64::from(section.raw) + delta;
                    Some(usize::try_from(file).map_err(|_| {
                        format!("The {what} file offset exceeds the address range.")
                    })?)
                } else {
                    None
                };
            if result.replace(file).is_some() {
                return Err(format!("The {what} RVA has ambiguous section mappings."));
            }
        }
        result.ok_or_else(|| format!("The {what} RVA is outside the PE image."))
    }

    /*
    This helper returns an RVA when a current file byte belongs to the PE image.
    Overlays and valid gaps return no RVA.
    */
    fn file_rva(&self, data: &[u8], file: usize, what: &str) -> Result<Option<u32>, String> {
        browser_range(data, file, 1, what)?;
        let mut result = (file < self.header_size as usize).then_some(file as u32);
        for section in &self.sections {
            let Some(delta) = file.checked_sub(section.raw as usize) else {
                continue;
            };
            if delta >= section.raw_size as usize {
                continue;
            }
            let rva = u64::from(section.rva)
                .checked_add(delta as u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| format!("The {what} RVA exceeds the PE address range."))?;
            if result.replace(rva).is_some() {
                return Err(format!(
                    "The {what} file offset has ambiguous RVA mappings."
                ));
            }
        }
        Ok(result)
    }

    /*
    This helper reads one bounded NUL-terminated string through an RVA mapping.
    Escaping produces safe structure-row text without changing source bytes.
    */
    fn string_at_rva(
        &self,
        data: &[u8],
        rva: u32,
        rva_limit: Option<u64>,
        what: &str,
    ) -> Result<(usize, String), String> {
        let file = self.map_range(data, rva, 1, what)?;
        let mut available = if rva < self.header_size {
            usize::try_from(self.header_size - rva).unwrap()
        } else {
            let section = self
                .sections
                .iter()
                .find(|section| {
                    rva >= section.rva && u64::from(rva - section.rva) < u64::from(section.raw_size)
                })
                .ok_or_else(|| format!("The {what} has no raw bytes."))?;
            usize::try_from(u64::from(section.raw_size) - u64::from(rva - section.rva)).unwrap()
        };
        if let Some(limit) = rva_limit {
            if u64::from(rva) >= limit {
                return Err(format!("The {what} starts outside its directory."));
            }
            available =
                available.min(usize::try_from(limit - u64::from(rva)).unwrap_or(usize::MAX));
        }
        available = available.min(data.len() - file);
        let scan = available.min(MAX_NAME_BYTES + 1);
        let Some(length) = data[file..file + scan].iter().position(|&byte| byte == 0) else {
            if available > MAX_NAME_BYTES {
                return Err(format!(
                    "The {what} exceeds the browser name limit of {MAX_NAME_BYTES} bytes."
                ));
            }
            return Err(format!("The {what} is not null-terminated."));
        };
        Ok((file, escaped(&data[file..file + length])))
    }
}

/*
This helper reports whether two nonempty 32-bit source ranges overlap.
PE parsing uses the result to reject ambiguous section mappings.
*/
fn ranges_overlap(left: u32, left_size: u32, right: u32, right_size: u32) -> bool {
    if left_size == 0 || right_size == 0 {
        return false;
    }
    let left = u64::from(left)..u64::from(left) + u64::from(left_size);
    let right = u64::from(right)..u64::from(right) + u64::from(right_size);
    left.start < right.end && right.start < left.end
}

/*
This helper alone applies the caller-supplied display row cap.
It preserves each accepted source offset and text pair.
*/
fn add_row(rows: &mut Vec<(usize, String)>, limit: usize, offset: usize, text: String) {
    if rows.len() < limit {
        rows.push((offset, text));
    }
}

/*
This helper calculates one indexed table RVA with checked multiplication and addition.
It also rejects values outside the PE 32-bit RVA range.
*/
fn indexed_rva(base: u32, index: usize, width: usize, what: &str) -> Result<u32, String> {
    let delta = index
        .checked_mul(width)
        .ok_or_else(|| format!("The {what} index exceeds the address range."))?;
    let value = u64::from(base)
        .checked_add(delta as u64)
        .ok_or_else(|| format!("The {what} RVA exceeds the address range."))?;
    u32::try_from(value).map_err(|_| format!("The {what} RVA exceeds the PE address range."))
}

/*
This reader walks validated import descriptors and their name or ordinal entries.
Each result carries the file offset that the structure browser can select.
*/
fn import_rows(
    pe: &BrowserPe,
    data: &[u8],
    rows: &mut Vec<(usize, String)>,
    limit: usize,
) -> Result<(), String> {
    /*
    The first section validates the import directory and selects the thunk width.
    Empty directories return without changing the row list.
    */
    let Some(directory) = pe.directories[1] else {
        return Ok(());
    };
    if directory.size as usize / 20 > MAX_BROWSER_ENTRIES + 1 {
        return Err(format!(
            "The import descriptor count exceeds the browser limit of {MAX_BROWSER_ENTRIES}."
        ));
    }
    let directory_file = pe.map_range(data, directory.rva, directory.size, "Import directory")?;
    let directory_end = directory_file + directory.size as usize;
    let thunk_width = if pe.bits == 64 { 8 } else { 4 };
    let ordinal_flag = if pe.bits == 64 {
        1u64 << 63
    } else {
        1u64 << 31
    };
    let mut descriptor_file = directory_file;
    let mut descriptor_index = 0usize;
    let mut thunk_count = 0usize;
    let mut terminated = false;
    /*
    The descriptor loop validates each DLL name and lookup-table source.
    It adds the descriptor row before its individual thunk rows.
    */
    while descriptor_file < directory_end {
        if descriptor_file + 20 > directory_end {
            return Err("The import descriptor table ends with a partial descriptor.".into());
        }
        let fields = [
            browser_dword(data, descriptor_file, "import descriptor")?,
            browser_dword(data, descriptor_file + 4, "import descriptor")?,
            browser_dword(data, descriptor_file + 8, "import descriptor")?,
            browser_dword(data, descriptor_file + 12, "import descriptor")?,
            browser_dword(data, descriptor_file + 16, "import descriptor")?,
        ];
        if fields.iter().all(|&value| value == 0) {
            terminated = true;
            break;
        }
        let lookup_rva = fields[0];
        let name_rva = fields[3];
        let iat_rva = fields[4];
        if name_rva == 0 || iat_rva == 0 {
            return Err("An import descriptor lacks its DLL name or import address table.".into());
        }
        let (_, dll) = pe.string_at_rva(data, name_rva, None, "import DLL name")?;
        let descriptor_rva = indexed_rva(directory.rva, descriptor_index, 20, "import descriptor")?;
        let descriptor_va = pe.va(descriptor_rva, "import descriptor")?;
        add_row(
            rows,
            limit,
            descriptor_file,
            format!(
                "Import {dll} | File={descriptor_file:08X} RVA={descriptor_rva:08X} VA={descriptor_va:016X} Size=00000014 | descriptor"
            ),
        );

        let fallback = lookup_rva == 0;
        let lookup_rva = if fallback { iat_rva } else { lookup_rva };
        let mut thunk_terminated = false;
        /*
        The thunk loop resolves each ordinal or name through checked file ranges.
        A zero entry terminates the current DLL table.
        */
        for index in 0..=MAX_BROWSER_ENTRIES {
            let lookup_entry_rva =
                indexed_rva(lookup_rva, index, thunk_width, "import lookup entry")?;
            let lookup_file = pe
                .map_range(
                    data,
                    lookup_entry_rva,
                    thunk_width as u32,
                    "import lookup entry",
                )
                .map_err(|_| {
                    "The import lookup table is not terminated within raw bytes.".to_string()
                })?;
            let value = if pe.bits == 64 {
                browser_qword(data, lookup_file, "import lookup entry")?
            } else {
                u64::from(browser_dword(data, lookup_file, "import lookup entry")?)
            };
            if value == 0 {
                thunk_terminated = true;
                break;
            }
            thunk_count += 1;
            if thunk_count > MAX_BROWSER_ENTRIES {
                return Err(format!(
                    "The import thunk count exceeds the browser limit of {MAX_BROWSER_ENTRIES}."
                ));
            }
            let iat_entry_rva = indexed_rva(iat_rva, index, thunk_width, "import address entry")?;
            let iat_file = pe.map_range(
                data,
                iat_entry_rva,
                thunk_width as u32,
                "import address entry",
            )?;
            let iat_va = pe.va(iat_entry_rva, "import address entry")?;
            let source = if fallback { " Source=IAT-fallback" } else { "" };
            let symbol = if value & ordinal_flag != 0 {
                if value & !(ordinal_flag | 0xffff) != 0 {
                    return Err("An ordinal import has nonzero reserved bits.".into());
                }
                format!("#{}", value & 0xffff)
            } else {
                let name_record_rva = match u32::try_from(value) {
                    Ok(value) => value,
                    Err(_) if fallback => {
                        return Err(
                            "The import address table contains a bound value without an import lookup table."
                                .into(),
                        );
                    }
                    Err(_) => return Err("An import name RVA exceeds the PE address range.".into()),
                };
                let name_rva = name_record_rva
                    .checked_add(2)
                    .ok_or("An import name RVA exceeds the PE address range.")?;
                let name_record_file = match pe.map_range(data, name_record_rva, 2, "import hint") {
                    Ok(file) => file,
                    Err(_) if fallback => {
                        return Err(
                            "The import address table contains a bound value without an import lookup table."
                                .into(),
                        );
                    }
                    Err(error) => return Err(error),
                };
                let hint = browser_word(data, name_record_file, "import hint")?;
                let (_, name) = match pe.string_at_rva(data, name_rva, None, "import name") {
                    Ok(name) => name,
                    Err(_) if fallback => {
                        return Err(
                            "The import address table contains a bound value without an import lookup table."
                                .into(),
                        );
                    }
                    Err(error) => return Err(error),
                };
                format!("{name} Hint={hint:04X}")
            };
            add_row(
                rows,
                limit,
                iat_file,
                format!(
                    "Import {dll}!{symbol} | File={iat_file:08X} RVA={iat_entry_rva:08X} VA={iat_va:016X} Size={thunk_width:08X} LookupFile={lookup_file:08X}{source}"
                ),
            );
        }
        if !thunk_terminated {
            return Err("The import thunk table exceeds the browser entry limit.".into());
        }
        descriptor_index += 1;
        descriptor_file += 20;
    }
    if !terminated {
        return Err(
            "The import descriptor table is not null-terminated within its directory.".into(),
        );
    }
    Ok(())
}

/*
This reader joins export functions, names, ordinals, and forwarders.
Malformed indexes or strings stop the complete structure request with an error.
*/
fn export_rows(
    pe: &BrowserPe,
    data: &[u8],
    rows: &mut Vec<(usize, String)>,
    limit: usize,
) -> Result<(), String> {
    /*
    The first section validates the export header and its three index tables.
    It also reads the module name for all output rows.
    */
    let Some(directory) = pe.directories[0] else {
        return Ok(());
    };
    if directory.size < 40 {
        return Err("The export directory is smaller than its header.".into());
    }
    let directory_file = pe.map_range(data, directory.rva, directory.size, "Export directory")?;
    let module_rva = browser_dword(data, directory_file + 12, "export directory")?;
    let ordinal_base = browser_dword(data, directory_file + 16, "export directory")?;
    let address_count = browser_dword(data, directory_file + 20, "export directory")?;
    let name_count = browser_dword(data, directory_file + 24, "export directory")?;
    let address_table_rva = browser_dword(data, directory_file + 28, "export directory")?;
    let name_table_rva = browser_dword(data, directory_file + 32, "export directory")?;
    let ordinal_table_rva = browser_dword(data, directory_file + 36, "export directory")?;
    let address_bytes = checked_count(address_count, 4, "export address")?;
    let name_bytes = checked_count(name_count, 4, "export name")?;
    let ordinal_bytes = checked_count(name_count, 2, "export ordinal")?;
    let address_count = address_count as usize;
    let name_count = name_count as usize;
    if name_count > address_count {
        return Err("The export name count exceeds the export address count.".into());
    }
    let (_, module) = pe.string_at_rva(data, module_rva, None, "export module name")?;
    let address_file = if address_bytes == 0 {
        None
    } else {
        Some(pe.map_range(
            data,
            address_table_rva,
            address_bytes as u32,
            "export address table",
        )?)
    };
    let name_file = if name_bytes == 0 {
        None
    } else {
        Some(pe.map_range(data, name_table_rva, name_bytes as u32, "export name table")?)
    };
    let ordinal_file = if ordinal_bytes == 0 {
        None
    } else {
        Some(pe.map_range(
            data,
            ordinal_table_rva,
            ordinal_bytes as u32,
            "export ordinal table",
        )?)
    };
    /*
    The name section joins each name pointer to its validated ordinal index.
    Unnamed address entries keep an empty name list.
    */
    let mut names = vec![Vec::<u32>::new(); address_count];
    for index in 0..name_count {
        let name_rva = browser_dword(data, name_file.unwrap() + index * 4, "export name pointer")?;
        let ordinal_index = usize::from(browser_word(
            data,
            ordinal_file.unwrap() + index * 2,
            "export ordinal",
        )?);
        if ordinal_index >= address_count {
            return Err("An export ordinal index exceeds the export address table.".into());
        }
        pe.string_at_rva(data, name_rva, None, "export name")?;
        names[ordinal_index].push(name_rva);
    }

    /*
    The row section resolves each nonzero target and detects forwarder strings.
    It creates one row for each name or one ordinal-only row.
    */
    let directory_end = u64::from(directory.rva) + u64::from(directory.size);
    for (index, entry_names) in names.iter().enumerate() {
        let entry_file = address_file.unwrap() + index * 4;
        let target_rva = browser_dword(data, entry_file, "export address")?;
        if target_rva == 0 {
            if !entry_names.is_empty() {
                return Err("A named export has a zero export address.".into());
            }
            continue;
        }
        let ordinal = ordinal_base
            .checked_add(index as u32)
            .ok_or("An export ordinal exceeds the address range.")?;
        let target_va = pe.va(target_rva, "export target")?;
        let (target_file, detail) = if u64::from(target_rva) >= u64::from(directory.rva)
            && u64::from(target_rva) < directory_end
        {
            let (file, forwarder) =
                pe.string_at_rva(data, target_rva, Some(directory_end), "export forwarder")?;
            (Some(file), format!(" Forwarder={forwarder}"))
        } else {
            (
                pe.virtual_file(data, target_rva, "export target")?,
                String::new(),
            )
        };
        let target_file = target_file.map_or_else(|| "-".into(), |file| format!("{file:08X}"));
        if entry_names.is_empty() {
            add_row(
                rows,
                limit,
                entry_file,
                format!(
                    "Export {module}!#{ordinal} | EntryFile={entry_file:08X} File={target_file} RVA={target_rva:08X} VA={target_va:016X}{detail}"
                ),
            );
        } else {
            for &name_rva in entry_names {
                if rows.len() >= limit {
                    break;
                }
                let (_, name) = pe.string_at_rva(data, name_rva, None, "export name")?;
                add_row(
                    rows,
                    limit,
                    entry_file,
                    format!(
                        "Export {module}!{name} | Ordinal={ordinal} EntryFile={entry_file:08X} File={target_file} RVA={target_rva:08X} VA={target_va:016X}{detail}"
                    ),
                );
            }
        }
    }
    Ok(())
}

/*
These helpers give known ELF program and section values stable structure-row names.
Unknown values keep their numeric type, and program permissions use the standard RWX order.
*/
fn elf_segment_name(segment_type: u32) -> String {
    match segment_type {
        0 => "PT_NULL".into(),
        1 => "PT_LOAD".into(),
        2 => "PT_DYNAMIC".into(),
        3 => "PT_INTERP".into(),
        4 => "PT_NOTE".into(),
        5 => "PT_SHLIB".into(),
        6 => "PT_PHDR".into(),
        7 => "PT_TLS".into(),
        value => format!("type {value:#X}"),
    }
}

fn elf_section_name(section_type: u32) -> String {
    match section_type {
        0 => "SHT_NULL".into(),
        1 => "SHT_PROGBITS".into(),
        2 => "SHT_SYMTAB".into(),
        3 => "SHT_STRTAB".into(),
        4 => "SHT_RELA".into(),
        5 => "SHT_HASH".into(),
        6 => "SHT_DYNAMIC".into(),
        7 => "SHT_NOTE".into(),
        8 => "SHT_NOBITS".into(),
        9 => "SHT_REL".into(),
        11 => "SHT_DYNSYM".into(),
        value => format!("type {value:#X}"),
    }
}

fn elf_flags(flags: u32) -> String {
    [(4, 'R'), (2, 'W'), (1, 'X')]
        .into_iter()
        .map(|(mask, name)| if flags & mask != 0 { name } else { '-' })
        .collect()
}

/*
This helper combines fixed row fields with one raw ELF name after the caller checks row capacity.
The exact escaped size includes every retained row field in the aggregate text limit.
An excessive row returns an error before the helper allocates or escapes the name.
*/
fn add_elf_row(
    rows: &mut Vec<(usize, String)>,
    text_bytes: &mut usize,
    offset: usize,
    prefix: &str,
    name: &[u8],
    suffix: &str,
) -> Result<(), String> {
    /*
    The size section counts each escaped byte without creating text.
    Checked addition rejects size overflow and aggregate text above 16 MiB.
    */
    let name_bytes: usize = name
        .iter()
        .map(|&byte| std::ascii::escape_default(byte).len())
        .sum();
    let row_bytes = prefix
        .len()
        .checked_add(name_bytes)
        .and_then(|value| value.checked_add(suffix.len()))
        .ok_or("The ELF structure text exceeds the limit of 16 MiB.")?;
    let total_bytes = text_bytes
        .checked_add(row_bytes)
        .filter(|&value| value <= ELF_MAX_STRUCTURE_TEXT_BYTES)
        .ok_or("The ELF structure text exceeds the limit of 16 MiB.")?;

    /*
    The output section reserves the accepted row and text with fallible allocation.
    Escaping uses the existing browser byte rules without a separate name string.
    The completed row updates the aggregate count for the next row.
    */
    rows.try_reserve(1)
        .map_err(|_| "Cannot allocate the ELF structure rows.")?;
    let mut text = String::new();
    text.try_reserve_exact(row_bytes)
        .map_err(|_| "Cannot allocate the ELF structure text.")?;
    text.push_str(prefix);
    for &byte in name {
        for value in std::ascii::escape_default(byte) {
            text.push(char::from(value));
        }
    }
    text.push_str(suffix);
    rows.push((offset, text));
    *text_bytes = total_bytes;
    Ok(())
}

/*
This browser converts one fully validated ELF model into selectable header, entry, program, and section rows.
Rows without source data use their table entry as the navigation location.
The caller row limit stops formatting, and the aggregate text limit bounds all retained row strings.
*/
fn elf_structures(data: &[u8], limit: usize) -> Result<Vec<(usize, String)>, String> {
    let elf = BrowserElf::parse(data)?;
    let mut rows = Vec::new();
    let mut text_bytes = 0;

    /*
    The first section adds the fixed header and an optional file-backed entry row.
    A Thumb entry row displays the original state bit from the ELF header.
    Entry mapping remains checked when the caller retains no rows.
    */
    if rows.len() < limit {
        add_elf_row(
            &mut rows,
            &mut text_bytes,
            0,
            &format!(
                "ELF{} header | Type={} Machine={:#06X} Entry={:016X}",
                elf.header.bits, elf.header.file_type, elf.header.machine, elf.header.entry
            ),
            b"",
            "",
        )?;
    }
    if let Some(entry_file) = elf.mapping.entry_offset()?
        && rows.len() < limit
    {
        add_elf_row(
            &mut rows,
            &mut text_bytes,
            usize::try_from(entry_file).map_err(|_| "The ELF entry file offset is too large.")?,
            &format!(
                "Entry | File={entry_file:016X} VA={:016X}",
                elf.header.entry
            ),
            b"",
            "",
        )?;
    }

    /*
    The program section adds all declared entries, including unknown types and PT_NULL records.
    File-backed records navigate to their source bytes, while empty records navigate to their headers.
    The parser has already validated entries beyond the caller row limit.
    */
    for (index, segment) in elf.segments.iter().enumerate() {
        if rows.len() >= limit {
            break;
        }
        let file = if segment.segment_type == 0 || segment.file_size == 0 {
            "-".into()
        } else {
            format!("{:016X}", segment.offset)
        };
        let navigation = if segment.segment_type == 0 || segment.file_size == 0 {
            segment.header
        } else {
            segment.offset
        };
        let address = if elf.header.file_type == 1 {
            format!("Address={:016X}", segment.address)
        } else {
            format!("VA={:016X}", segment.address)
        };
        add_elf_row(
            &mut rows,
            &mut text_bytes,
            usize::try_from(navigation)
                .map_err(|_| "The ELF program-header navigation offset is too large.")?,
            &format!(
                "Program[{index}] {} | File={file} {address} FileSize={:016X} MemorySize={:016X} Flags={} Align={:X} HeaderFile={:016X}",
                elf_segment_name(segment.segment_type),
                segment.file_size,
                segment.memory_size,
                elf_flags(segment.flags),
                segment.align,
                segment.header
            ),
            b"",
            "",
        )?;
    }

    /*
    The section section omits section zero and gives NOBITS or empty sections header navigation.
    Retained rows read validated raw name ranges and check escaped size before text allocation.
    The parser has already validated names beyond the caller row limit.
    */
    for (index, section) in elf.sections.iter().enumerate().skip(1) {
        if rows.len() >= limit {
            break;
        }
        let name = &data[section.name.clone()];
        let name = if name.is_empty() {
            b"<unnamed>".as_slice()
        } else {
            name
        };
        let has_bytes = section.section_type != 8 && section.size != 0;
        let file = if has_bytes {
            format!("{:016X}", section.offset)
        } else {
            "-".into()
        };
        let navigation = if has_bytes {
            section.offset
        } else {
            section.header as u64
        };
        let address = if elf.header.file_type == 1 {
            "-".into()
        } else {
            format!("{:016X}", section.address)
        };
        add_elf_row(
            &mut rows,
            &mut text_bytes,
            usize::try_from(navigation)
                .map_err(|_| "The ELF section navigation offset is too large.")?,
            &format!("Section[{index}] "),
            name,
            &format!(
                " {} | File={file} VA={address} Size={:016X} Flags={:X} Align={:X} HeaderFile={:016X}",
                elf_section_name(section.section_type),
                section.size,
                section.flags,
                section.align,
                section.header
            ),
        )?;
    }
    debug_assert!(rows.len() <= limit);
    debug_assert!(text_bytes <= ELF_MAX_STRUCTURE_TEXT_BYTES);
    debug_assert!(rows.iter().all(|(offset, _)| *offset < data.len()));
    Ok(rows)
}

/*
This title helper identifies the active buffered structure parser before the workbench opens its row list.
Malformed ELF input keeps the ELF title while the parser reports its exact error.
*/
pub(crate) fn structure_title(data: &[u8]) -> &'static str {
    if data.starts_with(ELF_MAGIC) {
        "ELF structures"
    } else {
        "PE structures"
    }
}

/*
This entry point creates ELF or PE structure rows from current source bytes.
The selected parser validates all format records before it applies the caller's row cap.
*/
pub fn structures(data: &[u8], limit: usize) -> Result<Vec<(usize, String)>, String> {
    if data.starts_with(ELF_MAGIC) {
        return elf_structures(data, limit);
    }
    let pe = BrowserPe::parse(data)?;
    let mut rows = Vec::with_capacity(limit.min(1_024));
    /*
    The first section creates one row for each mapped or virtual-only section.
    Each row carries a selectable source offset when source bytes exist.
    */
    for section in &pe.sections {
        let name = if section.name.is_empty() {
            "<unnamed>"
        } else {
            &section.name
        };
        let va = pe.va(section.rva, "section")?;
        if section.raw_size == 0 {
            add_row(
                &mut rows,
                limit,
                section.header,
                format!(
                    "Section {name} | File=- RVA={:08X} VA={va:016X} RawSize=00000000 VirtualSize={:08X} HeaderFile={:08X} Characteristics={:08X} | no raw bytes",
                    section.rva, section.virtual_size, section.header, section.characteristics
                ),
            );
        } else {
            add_row(
                &mut rows,
                limit,
                section.raw as usize,
                format!(
                    "Section {name} | File={:08X} RVA={:08X} VA={va:016X} RawSize={:08X} VirtualSize={:08X} Characteristics={:08X}",
                    section.raw,
                    section.rva,
                    section.raw_size,
                    section.virtual_size,
                    section.characteristics
                ),
            );
        }
    }
    /*
    The directory section keeps Security in its file-offset domain.
    All other directories use the PE virtual map.
    */
    for (index, directory) in pe.directories.iter().enumerate() {
        let Some(directory) = directory else {
            continue;
        };
        if index == 4 {
            add_row(
                &mut rows,
                limit,
                directory.rva as usize,
                format!(
                    "Directory Security | File={:08X} RVA=- VA=- Size={:08X} | certificate file offset",
                    directory.rva, directory.size
                ),
            );
        } else {
            let file = pe.map_range(data, directory.rva, directory.size, DIRECTORY_NAMES[index])?;
            let va = pe.va(directory.rva, DIRECTORY_NAMES[index])?;
            add_row(
                &mut rows,
                limit,
                file,
                format!(
                    "Directory {} | File={file:08X} RVA={:08X} VA={va:016X} Size={:08X}",
                    DIRECTORY_NAMES[index], directory.rva, directory.size
                ),
            );
        }
    }
    /*
    The table section appends imports and exports within the same row limit.
    A table error stops the complete browser request.
    */
    import_rows(&pe, data, &mut rows, limit)?;
    export_rows(&pe, data, &mut rows, limit)?;

    /*
    The final section finds bytes after all source-backed image ranges.
    One overlay row identifies the remaining file data.
    */
    let disk_end = pe
        .sections
        .iter()
        .try_fold(pe.header_size as usize, |end, section| {
            let section_end = (section.raw as usize)
                .checked_add(section.raw_size as usize)
                .ok_or("A section raw range exceeds the address range.")?;
            Ok::<_, String>(end.max(section_end))
        })?;
    if disk_end < data.len() {
        add_row(
            &mut rows,
            limit,
            disk_end,
            format!(
                "Overlay | File={disk_end:08X} RVA=- VA=- Size={:08X} | can contain certificate or debug data",
                data.len() - disk_end
            ),
        );
    }
    debug_assert!(rows.len() <= limit);
    debug_assert!(rows.iter().all(|(offset, _)| *offset < data.len()));
    Ok(rows)
}

/*
This entry point converts a checked ELF or PE address through current source bytes.
Each format returns only declared domains and file-backed locations.
*/
pub fn convert_address(data: &[u8], kind: AddressKind, value: u64) -> Result<PeAddress, String> {
    if data.starts_with(ELF_MAGIC) {
        return Elf::read(data)?.convert_address(kind, value, Some(data.len() as u64));
    }
    let pe = BrowserPe::parse(data)?;
    match kind {
        AddressKind::File => {
            let file =
                usize::try_from(value).map_err(|_| "The file offset exceeds the address range.")?;
            let rva = pe.file_rva(data, file, "file offset")?;
            let va = rva.map(|rva| pe.va(rva, "converted")).transpose()?;
            Ok(PeAddress {
                file_offset: Some(file),
                rva,
                va,
            })
        }
        AddressKind::Rva => {
            let rva = u32::try_from(value).map_err(|_| "The RVA exceeds the PE address range.")?;
            let file_offset = pe.virtual_file(data, rva, "converted address")?;
            let va = pe.va(rva, "converted")?;
            Ok(PeAddress {
                file_offset,
                rva: Some(rva),
                va: Some(va),
            })
        }
        AddressKind::Va => {
            if pe.bits == 32 && value > u64::from(u32::MAX) {
                return Err("The VA exceeds the PE32 address range.".into());
            }
            let rva = value
                .checked_sub(pe.image_base)
                .ok_or("The VA is below the PE image base.")?;
            let rva = u32::try_from(rva).map_err(|_| "The VA exceeds the PE address range.")?;
            let file_offset = pe.virtual_file(data, rva, "converted address")?;
            let va = pe.va(rva, "converted")?;
            Ok(PeAddress {
                file_offset,
                rva: Some(rva),
                va: Some(va),
            })
        }
    }
}

/*
This helper finds a PE signature through a checked DOS header offset.
Plain data returns no PE header, while malformed executable headers return an error.
*/
fn pe_header(data: &[u8]) -> Result<Option<usize>, String> {
    if data.starts_with(b"\x7fELF") || data.starts_with(b"NetWare Loadable Module\x1a") {
        return Err("This executable format is unsupported.".into());
    }
    if [b"NE", b"LE", b"LX"]
        .iter()
        .any(|magic| data.starts_with(*magic))
    {
        return Err("NE, LE, and LX executable formats are unsupported.".into());
    }
    if !data.starts_with(b"MZ") && !data.starts_with(b"ZM") {
        return Ok(None);
    }
    let header = dword(data, 60)? as usize;
    let signature = data.get(header..header + 4).unwrap_or(&[]);
    if signature == b"PE\0\0" {
        return Ok(Some(header));
    }
    if [b"NE", b"LE", b"LX"]
        .iter()
        .any(|magic| signature.starts_with(*magic))
    {
        return Err("NE, LE, and LX executable formats are unsupported.".into());
    }
    Ok(None)
}

/*
This standalone entry query maps an ELF or PE entry to a file byte.
Plain sources retain zero, and DOS files retain their legacy entry calculation.
*/
pub fn entry_point(data: &[u8]) -> Result<u64, String> {
    if data.starts_with(ELF_MAGIC) {
        return Elf::read(data)?
            .entry_offset()?
            .ok_or_else(|| OUTSIDE.into());
    }
    if let Some(header) = pe_header(data)? {
        let pe = Pe::read(data, header)?;
        return pe.rva_to_file(pe.entry).ok_or_else(|| OUTSIDE.into());
    }
    if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
        return dos_entry(data);
    }
    Ok(0)
}

/*
This standalone navigation wrapper maps one ELF VA or one compatible PE virtual value to a file byte.
Plain-source behavior and existing mapping errors remain unchanged.
*/
pub fn virtual_to_file(data: &[u8], address: u64) -> Result<u64, String> {
    if data.starts_with(ELF_MAGIC) {
        return Elf::read(data)?
            .virtual_to_file(address)?
            .ok_or_else(|| OUTSIDE.into());
    }
    match pe_header(data)? {
        Some(header) => Pe::read(data, header)?.legacy_virtual_to_file(address),
        None => Ok(address),
    }
}

/*
This standalone tuple wrapper returns one current code address and compatibility width.
Callers that need the address domain use code_location instead.
*/
pub fn code_address(data: &[u8], file_offset: u64) -> Result<(u64, u32), String> {
    Metadata::parse(data)?.code_address(file_offset)
}

/*
This standalone helper parses the source and returns its complete CodeLocation.
Callers that retain the domain can distinguish file offsets from virtual addresses.
*/
#[cfg(test)]
pub fn code_location(data: &[u8], file_offset: u64) -> Result<CodeLocation, String> {
    Metadata::parse(data)?.code_location(file_offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;

    /*
    This helper returns one unique temporary pathname for native paged metadata checks.
    Each test removes its file after the owned PagedFile closes.
    */
    fn temp_path(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hview-l08-pe-{label}-{}-{unique}.bin",
            std::process::id()
        ))
    }

    /*
    These fixture writers place little-endian values into preallocated PE buffers.
    Each test controls the destination range through fixed fixture offsets.
    */
    fn put_word(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_qword(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /*
    This fixture creates one independent ELF32 or ELF64 image with optional section records.
    The normal PT_LOAD maps file 0x100 through 0x1FF to VA 0x400000 through 0x4000FF.
    */
    fn elf_fixture(bits: u32, machine: u16, file_type: u16, with_sections: bool) -> Vec<u8> {
        let mut data = vec![0; 0x500];
        data[..4].copy_from_slice(ELF_MAGIC);
        data[4] = if bits == 32 { 1 } else { 2 };
        data[5] = 1;
        data[6] = 1;
        put_word(&mut data, 16, file_type);
        put_word(&mut data, 18, machine);
        put(&mut data, 20, 1);
        let header_size = if bits == 32 {
            ELF32_HEADER_SIZE
        } else {
            ELF64_HEADER_SIZE
        };
        let program_size = if bits == 32 {
            ELF32_PROGRAM_SIZE
        } else {
            ELF64_PROGRAM_SIZE
        };
        let section_size = if bits == 32 {
            ELF32_SECTION_SIZE
        } else {
            ELF64_SECTION_SIZE
        };
        let has_program = file_type != 1;

        /*
        This section writes class-specific header offsets and table counts.
        ET_REL omits the program table and keeps a file-relative entry value.
        */
        if bits == 32 {
            put(&mut data, 24, if has_program { 0x400010 } else { 7 });
            put(
                &mut data,
                28,
                if has_program { header_size as u32 } else { 0 },
            );
            put(&mut data, 32, if with_sections { 0x300 } else { 0 });
            put_word(&mut data, 40, header_size as u16);
            put_word(
                &mut data,
                42,
                if has_program { program_size as u16 } else { 0 },
            );
            put_word(&mut data, 44, u16::from(has_program));
            put_word(
                &mut data,
                46,
                if with_sections {
                    section_size as u16
                } else {
                    0
                },
            );
            put_word(&mut data, 48, if with_sections { 4 } else { 0 });
            put_word(&mut data, 50, if with_sections { 3 } else { 0 });
        } else {
            put_qword(&mut data, 24, if has_program { 0x400010 } else { 7 });
            put_qword(
                &mut data,
                32,
                if has_program { header_size as u64 } else { 0 },
            );
            put_qword(&mut data, 40, if with_sections { 0x300 } else { 0 });
            put_word(&mut data, 52, header_size as u16);
            put_word(
                &mut data,
                54,
                if has_program { program_size as u16 } else { 0 },
            );
            put_word(&mut data, 56, u16::from(has_program));
            put_word(
                &mut data,
                58,
                if with_sections {
                    section_size as u16
                } else {
                    0
                },
            );
            put_word(&mut data, 60, if with_sections { 4 } else { 0 });
            put_word(&mut data, 62, if with_sections { 3 } else { 0 });
        }

        /*
        This section writes one executable PT_LOAD with a 0x80-byte zero-fill tail.
        The final section table adds .text, .bss, and the section-name table when requested.
        */
        if has_program {
            let at = header_size;
            put(&mut data, at, 1);
            if bits == 32 {
                put(&mut data, at + 4, 0x100);
                put(&mut data, at + 8, 0x400000);
                put(&mut data, at + 16, 0x100);
                put(&mut data, at + 20, 0x180);
                put(&mut data, at + 24, 5);
                put(&mut data, at + 28, 0x100);
            } else {
                put(&mut data, at + 4, 5);
                put_qword(&mut data, at + 8, 0x100);
                put_qword(&mut data, at + 16, 0x400000);
                put_qword(&mut data, at + 32, 0x100);
                put_qword(&mut data, at + 40, 0x180);
                put_qword(&mut data, at + 48, 0x100);
            }
        }
        if with_sections {
            let names = b"\0.text\0.bss\0.shstrtab\0";
            data[0x280..0x280 + names.len()].copy_from_slice(names);
            let mut section = |index: usize,
                               name: u32,
                               section_type: u32,
                               address: u64,
                               offset: u64,
                               size: u64| {
                let at = 0x300 + index * section_size;
                put(&mut data, at, name);
                put(&mut data, at + 4, section_type);
                if bits == 32 {
                    put(&mut data, at + 8, u32::from(index != 3) * 2);
                    put(&mut data, at + 12, address as u32);
                    put(&mut data, at + 16, offset as u32);
                    put(&mut data, at + 20, size as u32);
                    put(&mut data, at + 32, 1);
                } else {
                    put_qword(&mut data, at + 8, u64::from(index != 3) * 2);
                    put_qword(&mut data, at + 16, address);
                    put_qword(&mut data, at + 24, offset);
                    put_qword(&mut data, at + 32, size);
                    put_qword(&mut data, at + 48, 1);
                }
            };
            section(
                1,
                1,
                1,
                if file_type == 1 { 0 } else { 0x400000 },
                0x100,
                0x100,
            );
            section(
                2,
                7,
                8,
                if file_type == 1 { 0 } else { 0x400100 },
                0x200,
                0x80,
            );
            section(3, 12, 3, 0, 0x280, names.len() as u64);
        }
        data[0x110..0x115].copy_from_slice(&[0xe8, 0x0b, 0, 0, 0]);
        data[0x120] = 0xc3;
        data
    }

    /*
    This fixture creates an ELF32 or ELF64 ET_REL file with one name shared by every nonzero section.
    Section one owns the string table, and later NOBITS sections require no file data.
    Large counts use the canonical extended count in section header zero.
    */
    fn elf_shared_name_fixture(bits: u32, count: usize, name: &[u8]) -> Vec<u8> {
        assert!((2..=ELF_MAX_ENTRIES).contains(&count));
        let header = elf_fixture(bits, if bits == 32 { 3 } else { 62 }, 1, false);
        let (header_size, section_size) = if bits == 32 {
            (ELF32_HEADER_SIZE, ELF32_SECTION_SIZE)
        } else {
            (ELF64_HEADER_SIZE, ELF64_SECTION_SIZE)
        };
        let names_file = header_size + count * section_size;
        let names_size = name.len() + 2;
        let mut data = vec![0; names_file + names_size];
        data[..header_size].copy_from_slice(&header[..header_size]);
        data[names_file + 1..names_file + 1 + name.len()].copy_from_slice(name);

        /*
        The header section replaces the ordinary fixture geometry with the complete synthetic section table.
        The name-table index remains one for both normal and extended section counts.
        */
        let short_count = if count >= ELF_RESERVED_INDEX_START {
            0
        } else {
            count as u16
        };
        if bits == 32 {
            put(&mut data, 32, header_size as u32);
            put_word(&mut data, 46, section_size as u16);
            put_word(&mut data, 48, short_count);
            put_word(&mut data, 50, 1);
            if short_count == 0 {
                put(&mut data, header_size + 20, count as u32);
            }
        } else {
            put_qword(&mut data, 40, header_size as u64);
            put_word(&mut data, 58, section_size as u16);
            put_word(&mut data, 60, short_count);
            put_word(&mut data, 62, 1);
            if short_count == 0 {
                put_qword(&mut data, header_size + 32, count as u64);
            }
        }

        /*
        The record section assigns the same raw name offset to every nonzero section.
        Only the string-table section owns file bytes, so repeated names create no overlapping section ranges.
        */
        for index in 1..count {
            let at = header_size + index * section_size;
            put(&mut data, at, 1);
            put(&mut data, at + 4, if index == 1 { 3 } else { 8 });
            let offset = if index == 1 { names_file } else { 0 };
            let size = if index == 1 { names_size } else { 1 };
            if bits == 32 {
                put(&mut data, at + 16, offset as u32);
                put(&mut data, at + 20, size as u32);
                put(&mut data, at + 32, 1);
            } else {
                put_qword(&mut data, at + 24, offset as u64);
                put_qword(&mut data, at + 32, size as u64);
                put_qword(&mut data, at + 48, 1);
            }
        }
        data
    }

    /*
    This fixture creates a minimal mapped PE32 or PE32+ source.
    Tests adjust selected header fields to exercise mapping errors.
    */
    fn fixture(plus: bool) -> Vec<u8> {
        let mut data = vec![0; 1024];
        data[..2].copy_from_slice(b"MZ");
        put(&mut data, 60, 128);
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&(if plus { 34404u16 } else { 332u16 }).to_le_bytes());
        data[134] = 1;
        data[148] = if plus { 240 } else { 224 };
        let optional = 152;
        data[optional..optional + 2]
            .copy_from_slice(&(if plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
        put(&mut data, optional + 16, 4096);
        if plus {
            put(&mut data, optional + 24, 0x40000000);
            put(&mut data, optional + 28, 1);
        } else {
            put(&mut data, optional + 28, 0x400000);
        }
        put(&mut data, optional + 32, 4096);
        put(&mut data, optional + 36, 512);
        put(&mut data, optional + 56, 8192);
        put(&mut data, optional + 60, 512);
        let section = optional + if plus { 240 } else { 224 };
        put(&mut data, section + 8, 256);
        put(&mut data, section + 12, 4096);
        put(&mut data, section + 16, 512);
        put(&mut data, section + 20, 512);
        data
    }

    /*
    This fixture adds browser directories, imports, exports, names, and an overlay.
    The source keeps stable offsets for exact structure-row assertions.
    */
    fn browser_fixture(plus: bool) -> Vec<u8> {
        let mut data = fixture(plus);
        data.resize(0x810, 0);
        let optional = 152;
        let section = optional + if plus { 240 } else { 224 };
        data[section..section + 8].copy_from_slice(b".rdata\0\0");
        put(&mut data, section + 8, 0x600);
        put(&mut data, section + 16, 0x600);
        put(&mut data, section + 36, 0x4000_0040);
        put(&mut data, optional + if plus { 108 } else { 92 }, 16);
        let directories = optional + if plus { 112 } else { 96 };
        put(&mut data, directories, 0x1100);
        put(&mut data, directories + 4, 0xa0);
        put(&mut data, directories + 8, 0x1000);
        put(&mut data, directories + 12, 0x28);
        put(&mut data, directories + 32, 0x808);
        put(&mut data, directories + 36, 8);

        put(&mut data, 0x200, 0x1040);
        put(&mut data, 0x20c, 0x1080);
        put(&mut data, 0x210, 0x1060);
        if plus {
            put_qword(&mut data, 0x240, 0x1090);
            put_qword(&mut data, 0x248, 1u64 << 63 | 7);
            put_qword(&mut data, 0x260, 0x1090);
            put_qword(&mut data, 0x268, 1u64 << 63 | 7);
        } else {
            put(&mut data, 0x240, 0x1090);
            put(&mut data, 0x244, 1u32 << 31 | 7);
            put(&mut data, 0x260, 0x1090);
            put(&mut data, 0x264, 1u32 << 31 | 7);
        }
        data[0x280..0x28d].copy_from_slice(b"KERNEL32.dll\0");
        put_word(&mut data, 0x290, 0x1234);
        data[0x292..0x29e].copy_from_slice(b"ExitProcess\0");

        put(&mut data, 0x30c, 0x1140);
        put(&mut data, 0x310, 1);
        put(&mut data, 0x314, 3);
        put(&mut data, 0x318, 2);
        put(&mut data, 0x31c, 0x1128);
        put(&mut data, 0x320, 0x1134);
        put(&mut data, 0x324, 0x113c);
        put(&mut data, 0x328, 0x1170);
        put(&mut data, 0x32c, 0x1010);
        put(&mut data, 0x330, 0x1020);
        put(&mut data, 0x334, 0x1150);
        put(&mut data, 0x338, 0x1160);
        put_word(&mut data, 0x33c, 0);
        put_word(&mut data, 0x33e, 1);
        data[0x340..0x34c].copy_from_slice(b"fixture.dll\0");
        data[0x350..0x35a].copy_from_slice(b"Forwarded\0");
        data[0x360..0x366].copy_from_slice(b"Named\0");
        data[0x370..0x37d].copy_from_slice(b"OTHER.Target\0");
        data[0x800..0x810].copy_from_slice(b"TAILCERTIFICATE!");
        data
    }

    /*
    This helper adds one virtual-only section to an existing browser fixture.
    The returned section-table offset lets tests modify its fields.
    */
    fn add_zero_raw_section(data: &mut [u8], plus: bool) -> usize {
        put_word(data, 134, 2);
        let second = 152 + if plus { 240 } else { 224 } + 40;
        data[second..second + 8].copy_from_slice(b".bss\0\0\0\0");
        put(data, second + 8, 0x200);
        put(data, second + 12, 0x2000);
        put(data, second + 36, 0xc000_0080);
        second
    }

    /*
    This test checks PE32 and PE32+ entry and mapping vectors.
    Stale metadata remains usable after machine bytes change.
    A mapping request from newly parsed metadata rejects the changed machine.
    Incomplete data remains an error.
    */
    #[test]
    fn pe_mapping_vectors() {
        for plus in [false, true] {
            let data = fixture(plus);
            let base = if plus { 0x140000000 } else { 0x400000 };
            let bits = if plus { 64 } else { 32 };
            let metadata = Metadata::parse(&data).unwrap();
            assert_eq!(entry_point(&data), Ok(512));
            assert_eq!(virtual_to_file(&data, 4096 + 16), Ok(528));
            assert_eq!(virtual_to_file(&data, base + 4096 + 16), Ok(528));
            assert_eq!(virtual_to_file(&data, base + 128), Ok(128));
            assert_eq!(metadata.code_address(528), Ok((base + 4096 + 16, bits)));
            assert_eq!(metadata.code_address(128), Ok((base + 128, bits)));
            assert_eq!(
                metadata.code_location(528),
                Ok(CodeLocation {
                    address: base + 4096 + 16,
                    bits,
                    architecture: Architecture::X86(bits),
                    domain: AddressDomain::Va,
                })
            );
            assert!(metadata.code_address(1024).is_err());
            assert_eq!(virtual_to_file(&data, 4607), Ok(1023));
            assert!(virtual_to_file(&data, 4608).is_err());
            assert!(virtual_to_file(&data, u64::MAX).is_err());
            assert!(entry_point(&data[..400]).is_err());
        }
        let mut changed = fixture(false);
        let stale = Metadata::parse(&changed).unwrap();
        changed[132..134].copy_from_slice(&0u16.to_le_bytes());
        assert!(stale.code_address(512).is_ok());
        assert!(
            Metadata::parse(&changed)
                .unwrap()
                .code_address(512)
                .is_err()
        );
        let mut data = fixture(false);
        data.resize(1025, 0);
        put(&mut data, 396, 513);
        assert_eq!(entry_point(&data), Ok(513));
        put(&mut data, 180, 1024);
        assert_eq!(virtual_to_file(&data, 4096), Ok(513));
        put(&mut data, 184, 512);
        assert_eq!(entry_point(&data), Ok(513));
        put(&mut data, 184, 4096);
        put(&mut data, 396, 0);
        assert!(entry_point(&data).is_err());
        data[134] = 0;
        assert!(entry_point(&data).is_err());
    }

    /*
    This test rejects PE section aliases, out-of-file ranges, and preferred-address overflow.
    Each failure occurs while shared metadata is built for buffered or paged consumers.
    */
    #[test]
    fn product_pe_mapping_rejects_invalid_ranges() {
        let mut raw_outside = fixture(false);
        put(&mut raw_outside, 376 + 16, 513);
        assert!(
            Metadata::parse(&raw_outside)
                .err()
                .unwrap()
                .contains("raw data range is outside")
        );

        let mut raw_overlap = fixture(false);
        raw_overlap[134] = 2;
        put(&mut raw_overlap, 416 + 8, 0x100);
        put(&mut raw_overlap, 416 + 12, 0x2000);
        put(&mut raw_overlap, 416 + 16, 0x100);
        put(&mut raw_overlap, 416 + 20, 0x300);
        assert!(
            Metadata::parse(&raw_overlap)
                .err()
                .unwrap()
                .contains("raw ranges overlap")
        );

        let mut virtual_overlap = fixture(false);
        virtual_overlap[134] = 2;
        put(&mut virtual_overlap, 416 + 8, 0x100);
        put(&mut virtual_overlap, 416 + 12, 0x1100);
        assert!(
            Metadata::parse(&virtual_overlap)
                .err()
                .unwrap()
                .contains("virtual ranges overlap")
        );

        let mut address_overflow = fixture(false);
        put(&mut address_overflow, 152 + 28, 0xffff_f000);
        assert!(
            Metadata::parse(&address_overflow)
                .err()
                .unwrap()
                .contains("PE32 address range")
        );
    }

    /*
    This test checks zero sections, table limits, truncation, header overlap, and exact EOF behavior.
    Plain and raw assembly addresses retain their separate EOF compatibility path.
    */
    #[test]
    fn product_pe_headers_and_eof_use_exact_limits() {
        let mut zero = fixture(false);
        put_word(&mut zero, 134, 0);
        put(&mut zero, 152 + 16, 0);
        let metadata = Metadata::parse(&zero).unwrap();
        assert_eq!(metadata.entry_offset(), Ok(0));
        assert_eq!(
            metadata.code_location(511).unwrap().domain,
            AddressDomain::Va
        );
        assert_eq!(
            metadata.code_location(512).unwrap().domain,
            AddressDomain::File
        );
        assert!(metadata.code_location(zero.len() as u64).is_err());
        assert!(metadata.code_address(zero.len() as u64).is_err());
        assert_eq!(
            Metadata::parse(b"raw").unwrap().code_address(3),
            Ok((3, 16))
        );

        let mut maximum = fixture(false);
        maximum.resize(0x2000, 0);
        put_word(&mut maximum, 134, 96);
        put(&mut maximum, 152 + 60, 0x2000);
        put(&mut maximum, 152 + 16, 0);
        maximum[376..376 + 96 * 40].fill(0);
        assert!(Metadata::parse(&maximum).is_ok());
        put_word(&mut maximum, 134, 97);
        assert_eq!(
            Metadata::parse(&maximum).err().unwrap(),
            "The PE section count exceeds the Windows limit of 96."
        );

        let mut short_optional = fixture(false);
        put_word(&mut short_optional, 148, 63);
        assert!(
            Metadata::parse(&short_optional)
                .err()
                .unwrap()
                .contains("optional header is incomplete")
        );
        assert!(Metadata::parse(&fixture(false)[..400]).is_err());

        let mut header_overlap = fixture(false);
        put(&mut header_overlap, 376 + 20, 0x100);
        assert!(
            Metadata::parse(&header_overlap)
                .err()
                .unwrap()
                .contains("raw range overlaps")
        );
    }

    /*
    This test selects supported PE architectures and rejects unsupported machine and class pairs.
    Metadata remains parseable until a Code operation requests the unsupported architecture.
    */
    #[test]
    fn pe_machine_and_class_pairs_select_code_architectures() {
        for (plus, machine, architecture) in [
            (false, 0x014c, Architecture::X86(32)),
            (false, IMAGE_FILE_MACHINE_ARM, Architecture::Arm),
            (false, IMAGE_FILE_MACHINE_THUMB, Architecture::Thumb),
            (true, 0x8664, Architecture::X86(64)),
            (true, 0xaa64, Architecture::Arm64),
        ] {
            let mut data = fixture(plus);
            put_word(&mut data, 132, machine);
            let metadata = Metadata::parse(&data).unwrap();
            assert_eq!(
                metadata.code_location(0x210).unwrap().architecture,
                architecture
            );
            let decoder = if matches!(architecture, Architecture::X86(_)) {
                Architecture::X86(16)
            } else {
                architecture
            };
            assert_eq!(metadata.decoder_architecture(16), Ok(decoder));
        }

        for (plus, machine, message) in [
            (
                false,
                IMAGE_FILE_MACHINE_ARMNT,
                "PE ARMNT code decoding is unsupported.",
            ),
            (
                false,
                0x8664,
                "The PE processor is unsupported for code decoding.",
            ),
            (
                true,
                0x014c,
                "The PE processor is unsupported for code decoding.",
            ),
        ] {
            let mut data = fixture(plus);
            put_word(&mut data, 132, machine);
            let metadata = Metadata::parse(&data).unwrap();
            assert_eq!(metadata.decoder_architecture(32).unwrap_err(), message);
            assert_eq!(metadata.code_location(0x210).unwrap_err(), message);
        }
    }

    /*
    This test separates strict branch VAs from the legacy RVA-or-VA compatibility input.
    A low image base can make the compatibility input ambiguous.
    */
    #[test]
    fn strict_pe_targets_do_not_retry_ambiguous_rvas() {
        let mut data = fixture(false);
        data.resize(0x600, 0);
        put(&mut data, 152 + 28, 0x1000);
        put(&mut data, 376 + 8, 0x200);
        data[134] = 2;
        put(&mut data, 416 + 8, 0x200);
        put(&mut data, 416 + 12, 0x2000);
        put(&mut data, 416 + 16, 0x200);
        put(&mut data, 416 + 20, 0x400);

        let metadata = Metadata::parse(&data).unwrap();
        assert_eq!(metadata.target_offset(AddressDomain::Va, 0x2000), Ok(0x200));
        assert_eq!(
            metadata.legacy_virtual_offset(0x2000),
            Err("The value has ambiguous RVA and VA mappings.".into())
        );
    }

    /*
    This test proves that one declared PE range can cross the 4 GiB file boundary.
    Checked u64 mapping preserves the exact high file offset and virtual address.
    */
    #[test]
    fn product_pe_mapping_preserves_offsets_above_four_gib() {
        let mut data = fixture(false);
        put(&mut data, 376 + 20, 0xffff_ff00);
        let pe = Pe::from_parts(
            5 * 1024 * 1024 * 1024,
            128,
            224,
            &data[128..152],
            &data[152..216],
            &data[376..416],
        )
        .unwrap();
        assert_eq!(pe.rva_to_file(0x1100), Some(0x1_0000_0000));
        assert_eq!(pe.file_to_virtual(0x1_0000_0000), Some(0x40_1100));
    }

    /*
    This test parses one sparse PE source above 4 GiB without reading its overlay.
    The paged constructor preserves the exact high mapping from its bounded header parts.
    */
    #[test]
    fn paged_pe_preserves_high_mappings_and_file_domains() {
        let path = temp_path("high");
        let mut data = fixture(false);
        put(&mut data, 152 + 16, 0x1100);
        put(&mut data, 376 + 20, 0xffff_ff00);
        let file_len = 5 * 1024 * 1024 * 1024_u64 + 1;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all_at(&data, 0).unwrap();
        file.set_len(file_len).unwrap();
        drop(file);

        let source = PagedFile::open(&path).unwrap();
        let metadata = Metadata::read_from(&source).unwrap();
        assert_eq!(metadata.format_label(), Some("PE"));
        assert_eq!(metadata.entry_offset(), Ok(0x1_0000_0000));
        assert_eq!(
            metadata.code_location(0x1_0000_0000),
            Ok(CodeLocation {
                address: 0x40_1100,
                bits: 32,
                architecture: Architecture::X86(32),
                domain: AddressDomain::Va,
            })
        );
        assert_eq!(
            metadata.code_location(file_len - 1).unwrap().domain,
            AddressDomain::File
        );
        assert_eq!(
            metadata.target_offset(AddressDomain::File, file_len - 1),
            Ok(file_len - 1)
        );
        assert!(metadata.code_location(file_len).is_err());
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This test compares buffered and paged metadata for identical PE32 and PE32+ bytes.
    Both paths must agree on entries, domains, strict targets, and final file bounds.
    */
    #[test]
    fn buffered_and_paged_pe_metadata_agree() {
        for plus in [false, true] {
            let path = temp_path(if plus { "agree64" } else { "agree32" });
            let mut data = fixture(plus);
            data.resize(0x700, 0);
            let section = 152 + if plus { 240 } else { 224 };
            put(&mut data, section + 8, 0x200);
            put(&mut data, section + 16, 0x200);
            put(&mut data, section + 20, 0x300);
            let buffered = Metadata::parse(&data).unwrap();
            std::fs::write(&path, &data).unwrap();
            let source = PagedFile::open(&path).unwrap();
            let paged = Metadata::read_from(&source).unwrap();

            assert_eq!(buffered.entry_offset(), paged.entry_offset());
            assert_eq!(buffered.code_location(0x310), paged.code_location(0x310));
            assert_eq!(buffered.code_location(0x250), paged.code_location(0x250));
            let target = buffered.code_location(0x310).unwrap().address;
            assert_eq!(
                buffered.target_offset(AddressDomain::Va, target),
                paged.target_offset(AddressDomain::Va, target)
            );
            assert_eq!(
                buffered.code_location(data.len() as u64),
                paged.code_location(data.len() as u64)
            );
            assert_eq!(
                buffered.target_offset(AddressDomain::File, data.len() as u64),
                paged.target_offset(AddressDomain::File, data.len() as u64)
            );
            drop(source);
            std::fs::remove_file(path).unwrap();
        }
    }

    /*
    This test places a valid PE header far from the DOS prefix in one sparse source.
    Bounded paged reads reach the header and section without allocating the intervening hole.
    */
    #[test]
    fn paged_pe_reads_one_distant_header_with_bounded_windows() {
        let path = temp_path("distant");
        let distant = 32 * 1024 * 1024_u64;
        let mut prefix = [0_u8; 64];
        prefix[..2].copy_from_slice(b"MZ");
        prefix[60..64].copy_from_slice(&(distant as u32).to_le_bytes());
        let mut header = fixture(false)[128..416].to_vec();
        let header_size = u32::try_from(distant + 512).unwrap();
        put(&mut header, 24 + 60, header_size);
        put(&mut header, 24 + 16, header_size);
        put(&mut header, 24 + 224 + 12, header_size);
        put(&mut header, 24 + 224 + 20, header_size);
        let file_len = distant + 1024;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all_at(&prefix, 0).unwrap();
        file.write_all_at(&header, distant).unwrap();
        file.set_len(file_len).unwrap();
        drop(file);

        let source = PagedFile::open(&path).unwrap();
        let metadata = Metadata::read_from(&source).unwrap();
        assert_eq!(metadata.entry_offset(), Ok(u64::from(header_size)));
        assert_eq!(
            metadata
                .code_location(u64::from(header_size))
                .unwrap()
                .address,
            0x40_0000 + u64::from(header_size)
        );
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This test reparses current paged edit spans after edit, Undo, Redo, and logical truncation.
    A metadata error does not remove the PagedFile owner or its accepted edit history.
    */
    #[test]
    fn paged_pe_reparses_current_edit_spans_and_retains_owner() {
        let path = temp_path("edits");
        std::fs::write(&path, fixture(false)).unwrap();
        let mut source = PagedFile::open(&path).unwrap();
        source.begin_edit().unwrap();
        let cursor = crate::paged::PagedEditCursor {
            offset: 132,
            top: 0,
            low_nibble: false,
        };
        source
            .replace_bytes(
                132,
                &IMAGE_FILE_MACHINE_ARM.to_le_bytes(),
                cursor,
                cursor,
                false,
            )
            .unwrap();
        assert_eq!(
            Metadata::read_from(&source)
                .unwrap()
                .decoder_architecture(16),
            Ok(Architecture::Arm)
        );
        source.undo().unwrap();
        assert_eq!(
            Metadata::read_from(&source)
                .unwrap()
                .decoder_architecture(16),
            Ok(Architecture::X86(16))
        );
        source.redo().unwrap();
        assert_eq!(
            Metadata::read_from(&source)
                .unwrap()
                .decoder_architecture(16),
            Ok(Architecture::Arm)
        );

        let before = crate::paged::PagedEditCursor {
            offset: 400,
            top: 0,
            low_nibble: false,
        };
        let after = crate::paged::PagedEditCursor {
            offset: 400,
            top: 0,
            low_nibble: false,
        };
        source
            .splice_bytes(400, source.len() - 400, &[], before, after, false)
            .unwrap();
        assert!(Metadata::read_from(&source).is_err());
        assert_eq!(source.len(), 400);
        source.undo().unwrap();
        assert!(Metadata::read_from(&source).is_ok());
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This test preserves a PagedFile source-validation error during one bounded metadata read.
    The format helper must not replace the owner error with an incomplete-header message.
    */
    #[test]
    fn paged_pe_preserves_source_validation_errors() {
        let path = temp_path("source-error");
        let old = path.with_extension("old");
        std::fs::write(&path, fixture(false)).unwrap();
        let source = PagedFile::open(&path).unwrap();
        std::fs::rename(&path, &old).unwrap();
        std::fs::create_dir(&path).unwrap();
        let mut bytes = [0_u8; 2];
        assert_eq!(
            read_paged_exact(&source, 0, &mut bytes, "test header").unwrap_err(),
            "The source path is not a regular file. Reopen the source."
        );
        drop(source);
        std::fs::remove_dir(path).unwrap();
        std::fs::remove_file(old).unwrap();
    }

    /*
    This test compares buffered and paged rejection for recognized unsupported DOS signatures.
    The paged EntryPoint path must not construct a DOS fallback for these formats.
    */
    #[test]
    fn paged_pe_rejects_recognized_unsupported_dos_signatures() {
        for signature in [b"NE", b"LE", b"LX"] {
            let path = temp_path(std::str::from_utf8(signature).unwrap());
            let mut data = vec![0_u8; 132];
            data[..2].copy_from_slice(b"MZ");
            put(&mut data, 60, 128);
            data[128..130].copy_from_slice(signature);
            let buffered = Metadata::parse(&data).err().unwrap();
            std::fs::write(&path, &data).unwrap();
            let source = PagedFile::open(&path).unwrap();
            assert_eq!(Metadata::read_from(&source).err().unwrap(), buffered);
            drop(source);
            std::fs::remove_file(path).unwrap();
        }
    }

    /*
    This test keeps the established large-file notice for plain data.
    Paged malformed ELF and valid DOS sources retain their separate format results.
    */
    #[test]
    fn paged_metadata_preserves_plain_limits_and_dos_entry() {
        let path = temp_path("plain");
        std::fs::write(&path, b"plain").unwrap();
        let source = PagedFile::open(&path).unwrap();
        assert!(
            Metadata::read_from(&source)
                .err()
                .unwrap()
                .contains("Virtual and entry-point offsets are unavailable")
        );
        drop(source);
        std::fs::remove_file(path).unwrap();

        let path = temp_path("malformed-elf");
        let data = b"\x7fELF";
        let buffered = Metadata::parse(data).err().unwrap();
        std::fs::write(&path, data).unwrap();
        let source = PagedFile::open(&path).unwrap();
        assert_eq!(Metadata::read_from(&source).err().unwrap(), buffered);
        drop(source);
        std::fs::remove_file(path).unwrap();

        let path = temp_path("dos");
        let mut data = vec![0_u8; 128];
        data[..2].copy_from_slice(b"MZ");
        put_word(&mut data, 8, 4);
        put_word(&mut data, 20, 2);
        put_word(&mut data, 22, 1);
        std::fs::write(&path, &data).unwrap();
        let source = PagedFile::open(&path).unwrap();
        assert_eq!(Metadata::read_from(&source).unwrap().entry_offset(), Ok(82));
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This test checks plain-source locations, explicit raw selection, and legacy non-PE entries.
    Malformed executable headers remain errors until an explicit raw model takes ownership.
    */
    #[test]
    fn raw_and_invalid_vectors() {
        assert_eq!(entry_point(b"raw bytes"), Ok(0));
        assert_eq!(virtual_to_file(b"raw bytes", 16), Ok(16));
        assert_eq!(code_address(b"raw bytes", 16), Ok((16, 16)));
        assert!(code_location(b"raw bytes", 16).is_err());
        assert!(code_address(b"\x7fELF raw x86", 4).is_err());
        assert_eq!(Metadata::raw(0, 16).unwrap().code_address(4), Ok((4, 16)));
        assert!(entry_point(b"\x7fELF").is_err());
        assert!(entry_point(b"MZ").is_err());
        let mut dos = vec![0; 64];
        dos[..2].copy_from_slice(b"MZ");
        dos[8] = 4;
        dos[20] = 2;
        dos[22] = 1;
        assert_eq!(entry_point(&dos), Ok(82));
    }

    /*
    This test checks explicit raw virtual addresses for every supported x86 width.
    The raw model overrides PE metadata and has no RVA domain.
    */
    #[test]
    fn explicit_raw_metadata_overrides_pe_and_maps_all_x86_widths() {
        let data = fixture(false);
        let parsed = Metadata::parse(&data).unwrap();
        assert_eq!(parsed.code_address(0x210), Ok((0x40_1010, 32)));

        for (bits, base) in [
            (16, 0x1000),
            (32, u64::from(u32::MAX) - data.len() as u64 + 1),
            (64, u64::MAX - data.len() as u64 + 1),
        ] {
            let metadata = Metadata::raw(base, bits).unwrap();
            assert_eq!(metadata.code_address(0x210), Ok((base + 0x210, bits)));
            assert_eq!(
                metadata.code_location(0x210),
                Ok(CodeLocation {
                    address: base + 0x210,
                    bits,
                    architecture: Architecture::X86(bits),
                    domain: AddressDomain::Va,
                })
            );
            assert_eq!(metadata.navigation_address(&data, 0), Ok(base));
            assert_eq!(metadata.navigation_offset(&data, base), Ok(0));
            assert_eq!(
                metadata.convert_address(&data, AddressKind::File, 0x210),
                Ok(PeAddress {
                    file_offset: Some(0x210),
                    rva: None,
                    va: Some(base + 0x210),
                })
            );
            assert_eq!(
                metadata.convert_address(&data, AddressKind::Va, base + 0x210),
                Ok(PeAddress {
                    file_offset: Some(0x210),
                    rva: None,
                    va: Some(base + 0x210),
                })
            );
            assert!(
                metadata
                    .convert_address(&data, AddressKind::Rva, 0)
                    .is_err()
            );
        }
    }

    /*
    This test applies each ARM-family raw model over bytes that contain a valid PE header.
    The raw architecture, runtime base, and File/VA conversions must replace parsed PE behavior.
    */
    #[test]
    fn raw_arm_architectures_override_pe_and_keep_checked_domains() {
        /*
        The setup confirms that AUTO reads the fixture as the existing x86 PE model.
        A later explicit raw constructor must not retain that parsed architecture.
        */
        let data = fixture(false);
        assert_eq!(
            Metadata::parse(&data)
                .unwrap()
                .code_location(0x210)
                .unwrap()
                .architecture,
            Architecture::X86(32)
        );
        /*
        This table verifies each raw architecture, mapping domain, and checked reverse conversion.
        Each raw model rejects a below-base address and the unavailable RVA domain.
        */
        for (architecture, base) in [
            (Architecture::Arm, 0x1000),
            (Architecture::Thumb, 0x2000),
            (Architecture::Arm64, 0x1_4000_0000),
        ] {
            let metadata = Metadata::raw_architecture(base, architecture).unwrap();
            assert_eq!(metadata.decoder_architecture(16), Ok(architecture));
            assert_eq!(
                metadata.code_location(0x210),
                Ok(CodeLocation {
                    address: base + 0x210,
                    bits: architecture.bits(),
                    architecture,
                    domain: AddressDomain::Va,
                })
            );
            assert_eq!(metadata.navigation_address(&data, 0x210), Ok(base + 0x210));
            assert_eq!(metadata.navigation_offset(&data, base + 0x210), Ok(0x210));
            assert!(metadata.navigation_offset(&data, base - 1).is_err());
            assert_eq!(
                metadata.convert_address(&data, AddressKind::File, 0x210),
                Ok(PeAddress {
                    file_offset: Some(0x210),
                    rva: None,
                    va: Some(base + 0x210),
                })
            );
            assert_eq!(
                metadata.convert_address(&data, AddressKind::Va, base + 0x210),
                Ok(PeAddress {
                    file_offset: Some(0x210),
                    rva: None,
                    va: Some(base + 0x210),
                })
            );
            assert!(
                metadata
                    .convert_address(&data, AddressKind::Rva, 0)
                    .is_err()
            );
        }
    }

    /*
    This test checks shared architecture labels, widths, alignment, and instruction-size limits.
    The current native entry points use these facts for all supported architectures.
    */
    #[test]
    fn architecture_contract_validates_widths_alignment_and_lengths() {
        for bits in [16, 32, 64] {
            let architecture = Architecture::x86(bits).unwrap();
            assert_eq!(architecture.bits(), bits);
            assert_eq!(architecture.label(), format!("a{bits}"));
            assert_eq!(architecture.alignment(), 1);
            assert_eq!(architecture.max_instruction_bytes(), 15);
            assert!(architecture.valid_instruction_bytes(1));
            assert!(architecture.valid_instruction_bytes(15));
            assert!(!architecture.valid_instruction_bytes(0));
            assert!(!architecture.valid_instruction_bytes(16));
        }
        assert!(Architecture::x86(8).is_err());
        assert_eq!(
            (Architecture::Arm.bits(), Architecture::Arm.alignment()),
            (32, 4)
        );
        assert_eq!(Architecture::Arm.label(), "ARM");
        assert_eq!(
            (Architecture::Thumb.bits(), Architecture::Thumb.alignment()),
            (32, 2)
        );
        assert_eq!(Architecture::Thumb.label(), "THUMB");
        assert_eq!(
            (Architecture::Arm64.bits(), Architecture::Arm64.alignment()),
            (64, 4)
        );
        assert_eq!(Architecture::Arm64.label(), "ARM64");
        assert!(Architecture::Arm.valid_instruction_bytes(4));
        assert!(!Architecture::Arm.valid_instruction_bytes(2));
        assert!(Architecture::Thumb.valid_instruction_bytes(2));
        assert!(Architecture::Thumb.valid_instruction_bytes(4));
        assert!(!Architecture::Thumb.valid_instruction_bytes(3));
        assert!(Architecture::Arm64.valid_instruction_bytes(4));
    }

    /*
    This test checks raw architecture validation, address overflow, and current file bounds.
    Failed operations return before a caller can use an invalid model.
    */
    #[test]
    fn explicit_raw_metadata_checks_width_overflow_and_file_bounds() {
        /*
        The first checks reject invalid direct x86 values at both compatibility boundaries.
        */
        assert!(Metadata::raw(0, 8).is_err());
        assert!(Metadata::raw_architecture(0, Architecture::X86(8)).is_err());
        /*
        The 32-bit family accepts the exact final address and rejects the next byte or base.
        */
        for architecture in [
            Architecture::X86(16),
            Architecture::X86(32),
            Architecture::Arm,
            Architecture::Thumb,
        ] {
            let metadata = Metadata::raw_architecture(u64::from(u32::MAX), architecture).unwrap();
            assert_eq!(
                metadata.code_location(0).unwrap().address,
                u64::from(u32::MAX)
            );
            assert!(metadata.code_address(1).is_err());
            assert!(Metadata::raw_architecture(u64::from(u32::MAX) + 1, architecture).is_err());
        }
        /*
        The 64-bit family accepts the exact u64 end and rejects one added byte.
        */
        for architecture in [Architecture::X86(64), Architecture::Arm64] {
            let metadata = Metadata::raw_architecture(u64::MAX, architecture).unwrap();
            assert_eq!(metadata.code_location(0).unwrap().address, u64::MAX);
            assert!(metadata.code_address(1).is_err());
        }

        /*
        The final section checks live source bounds, a below-base target, growth, and an empty buffer.
        Address conversion must not publish a byte outside the current source.
        */
        let metadata = Metadata::raw(0x1000, 32).unwrap();
        let mut data = vec![0x90];
        assert_eq!(metadata.navigation_address(&data, 0), Ok(0x1000));
        assert_eq!(metadata.navigation_offset(&data, 0x1000), Ok(0));
        assert!(metadata.navigation_offset(&data, 0x0fff).is_err());
        assert!(metadata.navigation_address(&data, 1).is_err());
        assert!(metadata.navigation_offset(&data, 0x1001).is_err());
        assert!(
            metadata
                .convert_address(&data, AddressKind::File, 1)
                .is_err()
        );
        assert!(
            metadata
                .convert_address(&data, AddressKind::Va, 0x1001)
                .is_err()
        );

        data.push(0xc3);
        assert_eq!(metadata.navigation_address(&data, 1), Ok(0x1001));
        assert_eq!(metadata.navigation_offset(&data, 0x1001), Ok(1));
        data.clear();
        assert!(metadata.navigation_address(&data, 0).is_err());
        assert!(
            metadata
                .convert_address(&data, AddressKind::File, 0)
                .is_err()
        );
    }

    /*
    This test maps equivalent file, RVA, and virtual addresses for PE32 and PE32+.
    Boundary values outside the mapped section remain errors.
    */
    #[test]
    fn checked_address_conversion_maps_pe32_and_pe32_plus() {
        for plus in [false, true] {
            let data = fixture(plus);
            let base = if plus { 0x1_4000_0000 } else { 0x40_0000 };
            for (kind, value) in [
                (AddressKind::File, 0x210),
                (AddressKind::Rva, 0x1010),
                (AddressKind::Va, base + 0x1010),
            ] {
                assert_eq!(
                    convert_address(&data, kind, value),
                    Ok(PeAddress {
                        file_offset: Some(0x210),
                        rva: Some(0x1010),
                        va: Some(base + 0x1010),
                    })
                );
            }
            for (kind, value) in [
                (AddressKind::File, 0x80),
                (AddressKind::Rva, 0x80),
                (AddressKind::Va, base + 0x80),
            ] {
                assert_eq!(
                    convert_address(&data, kind, value),
                    Ok(PeAddress {
                        file_offset: Some(0x80),
                        rva: Some(0x80),
                        va: Some(base + 0x80),
                    })
                );
            }
            assert_eq!(
                convert_address(&data, AddressKind::File, 0x3ff),
                Ok(PeAddress {
                    file_offset: Some(0x3ff),
                    rva: Some(0x11ff),
                    va: Some(base + 0x11ff),
                })
            );
            assert_eq!(
                convert_address(&data, AddressKind::Rva, 0x11ff),
                Ok(PeAddress {
                    file_offset: Some(0x3ff),
                    rva: Some(0x11ff),
                    va: Some(base + 0x11ff),
                })
            );
            assert!(convert_address(&data, AddressKind::File, 0x400).is_err());
            assert!(convert_address(&data, AddressKind::Rva, 0x1200).is_err());
        }
    }

    /*
    This test checks navigation through mapped PE, explicit raw data, and supported ELF sources.
    It preserves source bounds and unsupported PE-machine errors.
    */
    #[test]
    fn code_navigation_uses_checked_pe_raw_and_elf_mappings() {
        for plus in [false, true] {
            let data = fixture(plus);
            let base = if plus { 0x1_4000_0000 } else { 0x40_0000 };
            let metadata = Metadata::parse(&data).unwrap();
            assert_eq!(metadata.navigation_address(&data, 0x210), Ok(base + 0x1010));
            assert_eq!(metadata.navigation_offset(&data, base + 0x1010), Ok(0x210));
            assert!(
                metadata
                    .navigation_address(&data, data.len() as u64)
                    .is_err()
            );
            assert!(metadata.navigation_offset(&data, base + 0x1200).is_err());
        }

        let data = b"raw code";
        let metadata = Metadata::parse(data).unwrap();
        assert_eq!(metadata.navigation_address(data, 4), Ok(4));
        assert_eq!(metadata.navigation_offset(data, 4), Ok(4));
        assert!(
            metadata
                .navigation_address(data, data.len() as u64)
                .is_err()
        );
        assert!(metadata.navigation_offset(data, data.len() as u64).is_err());

        let elf = elf_fixture(64, 62, 2, false);
        let metadata = Metadata::parse(&elf).unwrap();
        assert_eq!(metadata.navigation_address(&elf, 0x110), Ok(0x400010));
        assert_eq!(metadata.navigation_offset(&elf, 0x400020), Ok(0x120));
        assert!(metadata.navigation_address(&elf, 0x450).is_err());
        assert!(metadata.navigation_offset(&elf, 0x400110).is_err());

        let overlay = browser_fixture(false);
        let metadata = Metadata::parse(&overlay).unwrap();
        assert!(metadata.navigation_address(&overlay, 0x800).is_err());

        let mut gap = fixture(false);
        gap.resize(0x500, 0);
        put(&mut gap, 376 + 20, 0x300);
        let metadata = Metadata::parse(&gap).unwrap();
        assert!(metadata.navigation_address(&gap, 0x250).is_err());

        let mut zero_fill = browser_fixture(false);
        add_zero_raw_section(&mut zero_fill, false);
        let metadata = Metadata::parse(&zero_fill).unwrap();
        assert!(metadata.navigation_offset(&zero_fill, 0x40_2010).is_err());

        let mut malformed = vec![0; 64];
        malformed[..2].copy_from_slice(b"MZ");
        let metadata = Metadata::parse(&malformed).unwrap();
        assert!(metadata.navigation_address(&malformed, 0).is_err());
        assert!(metadata.navigation_offset(&malformed, 0).is_err());

        let mut unsupported = fixture(false);
        put(&mut unsupported, 132, 0x01c4);
        let metadata = Metadata::parse(&unsupported).unwrap();
        assert_eq!(
            metadata.navigation_address(&unsupported, 0x210),
            Err("PE ARMNT code decoding is unsupported.".into())
        );
    }

    /*
    This test reports file gaps, overlays, and virtual-only PE bytes as partial mappings.
    No unavailable address domain receives an invented value.
    */
    #[test]
    fn checked_address_conversion_reports_partial_mappings() {
        let mut gap = fixture(false);
        gap.resize(0x500, 0);
        put(&mut gap, 376 + 20, 0x300);
        assert_eq!(
            convert_address(&gap, AddressKind::File, 0x250),
            Ok(PeAddress {
                file_offset: Some(0x250),
                rva: None,
                va: None,
            })
        );

        let overlay = browser_fixture(false);
        for file_offset in [0x800, 0x808] {
            assert_eq!(
                convert_address(&overlay, AddressKind::File, file_offset as u64),
                Ok(PeAddress {
                    file_offset: Some(file_offset),
                    rva: None,
                    va: None,
                })
            );
        }

        let mut section_security = browser_fixture(false);
        put(&mut section_security, 152 + 96 + 32, 0x600);
        assert_eq!(
            convert_address(&section_security, AddressKind::File, 0x600),
            Ok(PeAddress {
                file_offset: Some(0x600),
                rva: Some(0x1400),
                va: Some(0x40_1400),
            })
        );

        let mut zero_fill = browser_fixture(false);
        add_zero_raw_section(&mut zero_fill, false);
        for (kind, value) in [(AddressKind::Rva, 0x2010), (AddressKind::Va, 0x40_2010)] {
            assert_eq!(
                convert_address(&zero_fill, kind, value),
                Ok(PeAddress {
                    file_offset: None,
                    rva: Some(0x2010),
                    va: Some(0x40_2010),
                })
            );
        }
        assert_eq!(
            convert_address(&zero_fill, AddressKind::Rva, 0x21ff),
            Ok(PeAddress {
                file_offset: None,
                rva: Some(0x21ff),
                va: Some(0x40_21ff),
            })
        );
        assert!(convert_address(&zero_fill, AddressKind::Rva, 0x2200).is_err());
    }

    /*
    This test rejects offsets, counts, and overlapping ranges that make PE mappings ambiguous.
    Each error identifies the invalid mapping class.
    */
    #[test]
    fn checked_address_conversion_rejects_invalid_ranges() {
        let data = fixture(false);
        for (kind, value) in [
            (AddressKind::File, data.len() as u64),
            (AddressKind::Rva, u64::from(u32::MAX) + 1),
            (AddressKind::Va, 0x3f_ffff),
            (AddressKind::Va, u64::from(u32::MAX) + 1),
        ] {
            assert!(convert_address(&data, kind, value).is_err());
        }
        assert!(convert_address(b"raw bytes", AddressKind::File, 0).is_err());
        assert!(convert_address(b"MZ", AddressKind::File, 0).is_err());

        let mut raw_header_overlap = fixture(false);
        put(&mut raw_header_overlap, 376 + 20, 0x100);
        assert!(
            convert_address(&raw_header_overlap, AddressKind::File, 0x180)
                .unwrap_err()
                .contains("raw range overlaps")
        );

        let mut rva_header_overlap = fixture(false);
        put(&mut rva_header_overlap, 376 + 12, 0x100);
        assert!(
            convert_address(&rva_header_overlap, AddressKind::Rva, 0x180)
                .unwrap_err()
                .contains("virtual range overlaps")
        );

        let mut raw_section_overlap = browser_fixture(false);
        let second = add_zero_raw_section(&mut raw_section_overlap, false);
        put(&mut raw_section_overlap, second + 16, 0x100);
        put(&mut raw_section_overlap, second + 20, 0x300);
        assert!(
            convert_address(&raw_section_overlap, AddressKind::File, 0x300)
                .unwrap_err()
                .contains("raw ranges overlap")
        );

        let mut rva_section_overlap = browser_fixture(false);
        let second = add_zero_raw_section(&mut rva_section_overlap, false);
        put(&mut rva_section_overlap, second + 12, 0x1100);
        assert!(
            convert_address(&rva_section_overlap, AddressKind::Rva, 0x1100)
                .unwrap_err()
                .contains("virtual ranges overlap")
        );

        let mut raw_outside = fixture(false);
        put(&mut raw_outside, 376 + 16, 0x201);
        assert!(
            convert_address(&raw_outside, AddressKind::File, 0x200)
                .unwrap_err()
                .contains("section raw data")
        );
    }

    /*
    This test reads the current image base and checks virtual-address addition.
    PE32 and PE32+ overflow returns an error.
    */
    #[test]
    fn checked_address_conversion_uses_current_image_base_and_checks_va_overflow() {
        let mut changed = fixture(false);
        put(&mut changed, 152 + 28, 0x50_0000);
        assert_eq!(
            convert_address(&changed, AddressKind::File, 0x210),
            Ok(PeAddress {
                file_offset: Some(0x210),
                rva: Some(0x1010),
                va: Some(0x50_1010),
            })
        );

        put(&mut changed, 152 + 28, 0xffff_f000);
        assert!(
            convert_address(&changed, AddressKind::Rva, 0x1000)
                .unwrap_err()
                .contains("PE32 address range")
        );

        let mut plus = fixture(true);
        put_qword(&mut plus, 152 + 24, u64::MAX);
        assert!(
            convert_address(&plus, AddressKind::Rva, 1)
                .unwrap_err()
                .contains("address range")
        );
    }

    /*
    This test lists bounded PE32 and PE32+ browser rows with stable source offsets.
    It checks sections, directories, imports, exports, forwarders, and overlays.
    */
    #[test]
    fn pe_browser_lists_checked_pe32_and_pe32_plus_structures() {
        assert_eq!(escaped(b"A\n\x1b"), r"A\n\x1b");
        for plus in [false, true] {
            let data = browser_fixture(plus);
            let rows = structures(&data, usize::MAX).unwrap();
            assert!(rows.iter().all(|(offset, _)| *offset < data.len()));
            for expected in [
                "Section .rdata | File=00000200",
                "Directory Export | File=00000300",
                "Directory Import | File=00000200",
                "Directory Security | File=00000808 RVA=- VA=-",
                "Import KERNEL32.dll!ExitProcess Hint=1234 | File=00000260",
                "Import KERNEL32.dll!#7 |",
                "Export fixture.dll!Forwarded |",
                "Forwarder=OTHER.Target",
                "Export fixture.dll!Named |",
                "Export fixture.dll!#3 |",
                "Overlay | File=00000800 RVA=- VA=- Size=00000010",
            ] {
                assert!(
                    rows.iter().any(|(_, text)| text.contains(expected)),
                    "missing {expected}"
                );
            }
            assert_eq!(structures(&data, 3).unwrap().len(), 3);
            assert!(structures(&data, 0).unwrap().is_empty());
        }
    }

    /*
    This test labels IAT fallback entries and sections without file bytes.
    The browser retains source offsets for selectable records.
    */
    #[test]
    fn pe_browser_labels_iat_fallback_and_virtual_only_bytes() {
        for plus in [false, true] {
            let mut data = browser_fixture(plus);
            put(&mut data, 0x200, 0);
            let second = add_zero_raw_section(&mut data, plus);
            put(&mut data, 0x330, 0x2010);
            let rows = structures(&data, usize::MAX).unwrap();
            assert!(rows.iter().any(|(offset, text)| {
                *offset == second
                    && text.starts_with("Section .bss | File=-")
                    && text.contains("no raw bytes")
            }));
            assert!(rows.iter().any(|(_, text)| {
                text.starts_with("Import KERNEL32.dll!ExitProcess")
                    && text.contains("Source=IAT-fallback")
            }));
            assert!(rows.iter().any(|(offset, text)| {
                *offset == 0x330
                    && text.starts_with("Export fixture.dll!#3")
                    && text.contains("EntryFile=00000330 File=- RVA=00002010")
            }));
        }
    }

    /*
    This test rejects malformed browser ranges, counts, ordinals, and strings.
    The complete structure request stops at the first invalid record.
    */
    #[test]
    fn pe_browser_rejects_malformed_ranges_counts_and_strings() {
        let mut cases = Vec::new();

        let mut raw_range = browser_fixture(false);
        put(&mut raw_range, 376 + 16, 0x700);
        cases.push((raw_range, "section raw data"));

        let mut security = browser_fixture(false);
        put(&mut security, 152 + 96 + 32, 0x900);
        cases.push((security, "Security directory"));

        let mut descriptor = browser_fixture(false);
        put(&mut descriptor, 152 + 96 + 12, 20);
        cases.push((descriptor, "not null-terminated"));

        let mut import_name = browser_fixture(false);
        put(&mut import_name, 0x20c, 0x15ff);
        import_name[0x7ff] = b'A';
        cases.push((import_name, "import DLL name"));

        let mut export_count = browser_fixture(false);
        put(&mut export_count, 0x314, MAX_BROWSER_ENTRIES as u32 + 1);
        cases.push((export_count, "browser limit"));

        let mut export_ordinal = browser_fixture(false);
        put_word(&mut export_ordinal, 0x33c, 3);
        cases.push((export_ordinal, "ordinal index"));

        let mut forwarder = browser_fixture(false);
        put(&mut forwarder, 0x328, 0x119f);
        forwarder[0x39f] = b'A';
        cases.push((forwarder, "export forwarder"));

        let mut overlap = browser_fixture(false);
        let second = add_zero_raw_section(&mut overlap, false);
        put(&mut overlap, second + 12, 0x1100);
        cases.push((overlap, "virtual ranges overlap"));

        for (data, expected) in cases {
            let error = structures(&data, usize::MAX).unwrap_err();
            assert!(error.contains(expected), "{error:?} lacks {expected:?}");
        }
        assert_eq!(
            structures(b"raw bytes", 10),
            Err("The file is not a PE file.".into())
        );
    }

    /*
    This test reads the tracked native DLL fixtures through the PE structure browser.
    The expected Capstone and Keystone exports prove that import and export rows remain available.
    */
    #[test]
    fn pe_browser_reads_tracked_native_dlls() {
        for (name, export) in [
            ("windows-capstone-5.0.9.dll", "cs_open"),
            ("windows-keystone-0.9.2.dll", "ks_open"),
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name);
            let data = std::fs::read(path).unwrap();
            let rows = structures(&data, 100_000).unwrap();
            assert!(rows.iter().all(|(offset, _)| *offset < data.len()));
            assert!(rows.iter().any(|(_, text)| text.starts_with("Section ")));
            assert!(rows.iter().any(|(_, text)| text.starts_with("Import ")));
            assert!(
                rows.iter()
                    .any(|(_, text)| { text.starts_with("Export ") && text.contains(export) })
            );
        }
    }

    /*
    This test compares ELF32, ELF64, and ARM64 mapping results across every public metadata route.
    It also checks ET_REL file domains and the absence of an RVA domain.
    */
    #[test]
    fn elf32_elf64_and_arm64_use_checked_load_mappings() {
        for (bits, machine, file_type, architecture) in [
            (32, 3, 2, Architecture::X86(32)),
            (64, 62, 3, Architecture::X86(64)),
            (64, 183, 2, Architecture::Arm64),
        ] {
            let data = elf_fixture(bits, machine, file_type, true);
            let metadata = Metadata::parse(&data).unwrap();
            assert_eq!(metadata.format_label(), Some("ELF"));
            assert!(!metadata.has_rva());
            assert!(metadata.has_va());
            assert_eq!(metadata.entry_offset(), Ok(0x110));
            assert_eq!(entry_point(&data), Ok(0x110));
            assert_eq!(virtual_to_file(&data, 0x400020), Ok(0x120));
            assert_eq!(
                metadata.code_location(0x110),
                Ok(CodeLocation {
                    address: 0x400010,
                    bits,
                    architecture,
                    domain: AddressDomain::Va,
                })
            );
            assert_eq!(
                metadata.target_offset(AddressDomain::Va, 0x400020),
                Ok(0x120)
            );
            assert_eq!(metadata.navigation_address(&data, 0x110), Ok(0x400010));
            assert_eq!(metadata.navigation_offset(&data, 0x400020), Ok(0x120));
            assert_eq!(
                metadata.convert_address(&data, AddressKind::File, 0x120),
                Ok(PeAddress {
                    file_offset: Some(0x120),
                    rva: None,
                    va: Some(0x400020),
                })
            );
            assert_eq!(
                metadata.convert_address(&data, AddressKind::Va, 0x400110),
                Ok(PeAddress {
                    file_offset: None,
                    rva: None,
                    va: Some(0x400110),
                })
            );
            assert_eq!(
                metadata.convert_address(&data, AddressKind::Rva, 0),
                Err("ELF files have no RVA.".into())
            );
            assert_eq!(
                metadata.code_location(0x450),
                Ok(CodeLocation {
                    address: 0x450,
                    bits,
                    architecture,
                    domain: AddressDomain::File,
                })
            );
        }

        let data = elf_fixture(32, 3, 1, true);
        let metadata = Metadata::parse(&data).unwrap();
        assert!(!metadata.has_va());
        assert!(metadata.entry_offset().is_err());
        assert_eq!(metadata.code_address(0x110), Ok((0x110, 32)));
        assert_eq!(metadata.navigation_address(&data, 0x110), Ok(0x110));
        assert_eq!(metadata.navigation_offset(&data, 0x120), Ok(0x120));
        assert_eq!(
            metadata.code_location(0x110).unwrap().domain,
            AddressDomain::File
        );
        assert!(metadata.convert_address(&data, AddressKind::Va, 0).is_err());
    }

    /*
    This test selects ARM or Thumb only from the supported ARM entry-state rules.
    Missing and reserved states keep metadata inspectable only when no invalid entry mapping is requested.
    */
    #[test]
    fn elf_arm_entry_state_selects_arm_or_thumb() {
        let arm = elf_fixture(32, EM_ARM, 2, true);
        let metadata = Metadata::parse(&arm).unwrap();
        assert_eq!(metadata.entry_offset(), Ok(0x110));
        assert_eq!(metadata.decoder_architecture(64), Ok(Architecture::Arm));

        let mut thumb = arm.clone();
        put(&mut thumb, 24, 0x400011);
        let metadata = Metadata::parse(&thumb).unwrap();
        assert_eq!(metadata.entry_offset(), Ok(0x110));
        assert_eq!(metadata.decoder_architecture(64), Ok(Architecture::Thumb));

        put(&mut thumb, 24, 0x400013);
        let metadata = Metadata::parse(&thumb).unwrap();
        assert_eq!(metadata.entry_offset(), Ok(0x112));
        assert_eq!(metadata.decoder_architecture(32), Ok(Architecture::Thumb));

        let mut reserved = arm;
        put(&mut reserved, 24, 0x400012);
        assert_eq!(
            Metadata::parse(&reserved).err().unwrap(),
            "The ELF ARM entry point has a reserved state value."
        );

        for mut missing in [
            elf_fixture(32, EM_ARM, 1, true),
            elf_fixture(32, EM_ARM, 2, true),
        ] {
            if word(&missing, 16).unwrap() != 1 {
                put(&mut missing, 24, 0);
            }
            let metadata = Metadata::parse(&missing).unwrap();
            assert!(metadata.decoder_architecture(32).is_err());
        }
    }

    /*
    This test validates ELF structure rows, optional sections, and canonical extended-count rules.
    The core parser accepts an invalid name offset until the separate structure browser checks it.
    */
    #[test]
    fn elf_structure_browser_validates_sections_and_extended_counts() {
        for bits in [32, 64] {
            let data = elf_fixture(bits, if bits == 32 { 3 } else { 62 }, 2, true);
            assert_eq!(structure_title(&data), "ELF structures");
            let rows = structures(&data, 100).unwrap();
            assert!(rows.iter().any(|(_, text)| text.contains("ELF")));
            assert!(rows.iter().any(|(_, text)| text.contains("PT_LOAD")));
            assert!(rows.iter().any(|(_, text)| text.contains(".text")));
            assert_eq!(structures(&data, 3).unwrap(), rows[..3]);
            assert!(structures(&data, 0).unwrap().is_empty());
            let bss = rows.iter().find(|(_, text)| text.contains(".bss")).unwrap();
            let section_size = if bits == 32 {
                ELF32_SECTION_SIZE
            } else {
                ELF64_SECTION_SIZE
            };
            assert_eq!(bss.0, 0x300 + 2 * section_size);
            assert!(bss.1.contains("File=-"));

            let mut bad_name = data.clone();
            put(&mut bad_name, 0x300 + section_size, 0xffff);
            assert!(Metadata::parse(&bad_name).is_ok());
            assert!(structures(&bad_name, 100).is_err());

            let stripped = elf_fixture(bits, if bits == 32 { 3 } else { 62 }, 2, false);
            let rows = structures(&stripped, 100).unwrap();
            assert!(rows.iter().any(|(_, text)| text.contains("PT_LOAD")));
            assert!(!rows.iter().any(|(_, text)| text.contains("Section[")));

            let mut no_load = stripped;
            let program = if bits == 32 {
                ELF32_HEADER_SIZE
            } else {
                ELF64_HEADER_SIZE
            };
            put(&mut no_load, program, 0);
            no_load[program + 4..program + if bits == 32 { 32 } else { 56 }].fill(0xff);
            let rows = structures(&no_load, 100).unwrap();
            let null = rows
                .iter()
                .find(|(_, text)| text.contains("PT_NULL"))
                .unwrap();
            assert_eq!(null.0, program);
            assert!(null.1.contains("File=-"));
        }

        let base = elf_fixture(64, 62, 2, true);
        let mut program_header = ElfHeader::parse(&base, base.len() as u64).unwrap();
        program_header.program_count = 0xffff;
        let mut program_zero = vec![0; ELF64_SECTION_SIZE];
        put(&mut program_zero, 44, 0xffff);
        program_header.resolve_counts(Some(&program_zero)).unwrap();
        assert_eq!(program_header.program_count, 0xffff);
        put(&mut program_zero, 44, 1);
        let mut low_program = ElfHeader::parse(&base, base.len() as u64).unwrap();
        low_program.program_count = 0xffff;
        assert!(low_program.resolve_counts(Some(&program_zero)).is_err());

        let mut section_header = ElfHeader::parse(&base, base.len() as u64).unwrap();
        section_header.section_count = 0;
        section_header.section_names = 0xffff;
        let mut section_zero = vec![0; ELF64_SECTION_SIZE];
        put_qword(&mut section_zero, 32, 0xff01);
        put(&mut section_zero, 40, 0xff00);
        section_header.resolve_counts(Some(&section_zero)).unwrap();
        assert_eq!(section_header.section_count, 0xff01);
        assert_eq!(section_header.section_names, 0xff00);
        put_qword(&mut section_zero, 32, 4);
        put(&mut section_zero, 40, 3);
        let mut low_sections = ElfHeader::parse(&base, base.len() as u64).unwrap();
        low_sections.section_count = 0;
        low_sections.section_names = 0xffff;
        assert!(low_sections.resolve_counts(Some(&section_zero)).is_err());
    }

    /*
    This test uses the maximum section count with a shared name that expands to four times its raw size.
    A three-row limit retains two complete names without text allocation for the remaining sections.
    The selected NOBITS row keeps section-header navigation.
    */
    #[test]
    fn elf_structure_browser_bounds_shared_names_at_maximum_sections() {
        let data = elf_shared_name_fixture(64, ELF_MAX_ENTRIES, &[0xff; MAX_NAME_BYTES]);
        let rows = structures(&data, 3).unwrap();
        assert_eq!(rows.len(), 3);
        let retained_bytes: usize = rows.iter().map(|(_, text)| text.capacity()).sum();
        assert!(retained_bytes <= 2 * MAX_NAME_BYTES * 4 + 512);
        assert!(rows[1].1.starts_with(&format!(
            "Section[1] {} SHT_STRTAB",
            "\\xff".repeat(MAX_NAME_BYTES)
        )));
        assert_eq!(
            rows[1].0,
            ELF64_HEADER_SIZE + ELF_MAX_ENTRIES * ELF64_SECTION_SIZE
        );
        assert_eq!(rows[2].0, ELF64_HEADER_SIZE + 2 * ELF64_SECTION_SIZE);
        assert!(rows[2].1.contains("SHT_NOBITS | File=-"));
    }

    /*
    This test places an invalid name offset beyond the retained row limit in both ELF classes.
    Even a zero-row request must reject the malformed final section name.
    */
    #[test]
    fn elf_structure_browser_checks_names_beyond_row_limit() {
        for bits in [32, 64] {
            let mut data = elf_shared_name_fixture(bits, 4, b"x");
            let (header_size, section_size) = if bits == 32 {
                (ELF32_HEADER_SIZE, ELF32_SECTION_SIZE)
            } else {
                (ELF64_HEADER_SIZE, ELF64_SECTION_SIZE)
            };
            put(&mut data, header_size + 3 * section_size, 3);
            for limit in [0, 1] {
                assert_eq!(
                    structures(&data, limit),
                    Err("An ELF section-name offset is outside the string table.".into())
                );
            }
        }
    }

    /*
    This test preserves exact 4,096-byte names, empty names, and browser byte escaping in both ELF classes.
    An excessive name remains invalid when the caller retains only the header row.
    */
    #[test]
    fn elf_structure_browser_keeps_name_limits_and_escaping() {
        for bits in [32, 64] {
            let data = elf_shared_name_fixture(bits, 3, &[0xff; MAX_NAME_BYTES]);
            let rows = structures(&data, usize::MAX).unwrap();
            assert_eq!(rows.len(), 3);
            assert!(rows[1].1.starts_with(&format!(
                "Section[1] {} SHT_STRTAB",
                "\\xff".repeat(MAX_NAME_BYTES)
            )));

            let empty = elf_shared_name_fixture(bits, 3, b"");
            let rows = structures(&empty, usize::MAX).unwrap();
            assert!(rows[1].1.starts_with("Section[1] <unnamed> SHT_STRTAB"));

            let escaped = elf_shared_name_fixture(bits, 3, b"plain\\\"'\n\t\xff");
            let rows = structures(&escaped, usize::MAX).unwrap();
            assert!(
                rows[1]
                    .1
                    .starts_with("Section[1] plain\\\\\\\"\\'\\n\\t\\xff SHT_STRTAB")
            );

            let excessive = elf_shared_name_fixture(bits, 3, &[0xff; MAX_NAME_BYTES + 1]);
            assert_eq!(
                structures(&excessive, 1),
                Err("An ELF section name exceeds the limit of 4096 bytes.".into())
            );
        }
    }

    /*
    This test rejects retained ELF row text above the aggregate limit with a clear error.
    A smaller caller row limit still returns complete accepted rows.
    The helper boundary check includes fixed row fields and escaped names before allocation.
    */
    #[test]
    fn elf_structure_browser_rejects_aggregate_text_over_budget() {
        let data = elf_shared_name_fixture(64, 1_024, &[0xff; MAX_NAME_BYTES]);
        let rows = structures(&data, 1_000).unwrap();
        assert_eq!(rows.len(), 1_000);
        let retained_bytes: usize = rows.iter().map(|(_, text)| text.capacity()).sum();
        assert!(retained_bytes <= ELF_MAX_STRUCTURE_TEXT_BYTES);
        drop(rows);
        let error = "The ELF structure text exceeds the limit of 16 MiB.";
        assert_eq!(structures(&data, 10_001), Err(error.into()));

        let mut rows = Vec::new();
        let mut text_bytes = ELF_MAX_STRUCTURE_TEXT_BYTES - 6;
        add_elf_row(&mut rows, &mut text_bytes, 0, "A", &[0xff], "B").unwrap();
        assert_eq!(rows[0].1, "A\\xffB");
        assert_eq!(text_bytes, ELF_MAX_STRUCTURE_TEXT_BYTES);
        assert_eq!(
            add_elf_row(&mut rows, &mut text_bytes, 0, "", b"x", ""),
            Err(error.into())
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(text_bytes, ELF_MAX_STRUCTURE_TEXT_BYTES);
    }

    /*
    This test rejects malformed ELF headers, load ranges, limits, and mapping aliases.
    An unknown machine remains inspectable and returns a Code capability error.
    */
    #[test]
    fn elf_rejects_invalid_headers_loads_and_ambiguous_aliases() {
        let valid = elf_fixture(64, 62, 2, false);
        let mut cases = Vec::new();
        let mut big_endian = valid.clone();
        big_endian[5] = 2;
        cases.push(big_endian);
        let mut bad_version = valid.clone();
        bad_version[6] = 0;
        cases.push(bad_version);
        let mut bad_type = valid.clone();
        put_word(&mut bad_type, 16, 4);
        cases.push(bad_type);
        let mut mismatch = valid.clone();
        put_word(&mut mismatch, 18, 3);
        cases.push(mismatch);
        let mut bad_class = valid.clone();
        bad_class[4] = 3;
        cases.push(bad_class);
        let mut bad_header_size = valid.clone();
        put_word(&mut bad_header_size, 52, 63);
        cases.push(bad_header_size);
        let mut bad_program_size = valid.clone();
        put_word(&mut bad_program_size, 54, 55);
        cases.push(bad_program_size);
        for data in cases {
            assert!(Metadata::parse(&data).is_err());
        }

        let program = ELF64_HEADER_SIZE;
        let mut too_large = valid.clone();
        put_qword(&mut too_large, program + 32, 0x181);
        assert!(Metadata::parse(&too_large).is_err());
        let mut bad_align = valid.clone();
        put_qword(&mut bad_align, program + 48, 3);
        assert!(Metadata::parse(&bad_align).is_err());
        let mut outside = valid.clone();
        put_qword(&mut outside, program + 8, 0x480);
        put_qword(&mut outside, program + 32, 0x100);
        assert!(Metadata::parse(&outside).is_err());
        let mut overflow = valid.clone();
        put_qword(&mut overflow, program + 16, u64::MAX - 0x7f);
        put_qword(&mut overflow, program + 48, 1);
        assert!(Metadata::parse(&overflow).is_err());
        let mut elf32_overflow = elf_fixture(32, 3, 2, false);
        put(&mut elf32_overflow, ELF32_HEADER_SIZE + 8, 0xffff_ff80);
        put(&mut elf32_overflow, ELF32_HEADER_SIZE + 28, 1);
        assert!(Metadata::parse(&elf32_overflow).is_err());

        let mut table_limit = valid.clone();
        put_word(&mut table_limit, 54, u16::MAX);
        put_word(&mut table_limit, 56, 200);
        assert!(
            Metadata::parse(&table_limit)
                .err()
                .unwrap()
                .contains("8 MiB")
        );

        let mut same = valid.clone();
        put_word(&mut same, 56, 2);
        let second = program + ELF64_PROGRAM_SIZE;
        put(&mut same, second, 1);
        put(&mut same, second + 4, 5);
        put_qword(&mut same, second + 8, 0x180);
        put_qword(&mut same, second + 16, 0x400080);
        put_qword(&mut same, second + 32, 0x80);
        put_qword(&mut same, second + 40, 0x80);
        put_qword(&mut same, second + 48, 0x100);
        assert!(Metadata::parse(&same).is_ok());

        let mut file_alias = same.clone();
        put_qword(&mut file_alias, second + 16, 0x500080);
        assert!(Metadata::parse(&file_alias).is_err());
        let mut virtual_alias = same;
        put_qword(&mut virtual_alias, second + 8, 0x280);
        assert!(Metadata::parse(&virtual_alias).is_err());

        let mut zero_fill_alias = valid.clone();
        put_word(&mut zero_fill_alias, 56, 2);
        put(&mut zero_fill_alias, second, 1);
        put(&mut zero_fill_alias, second + 4, 5);
        put_qword(&mut zero_fill_alias, second + 8, 0x280);
        put_qword(&mut zero_fill_alias, second + 16, 0x400100);
        put_qword(&mut zero_fill_alias, second + 32, 0x40);
        put_qword(&mut zero_fill_alias, second + 40, 0x40);
        put_qword(&mut zero_fill_alias, second + 48, 1);
        assert!(Metadata::parse(&zero_fill_alias).is_err());

        let mut unknown = valid;
        put_word(&mut unknown, 18, 0x7777);
        let metadata = Metadata::parse(&unknown).unwrap();
        assert_eq!(metadata.format_label(), Some("ELF"));
        assert_eq!(
            metadata.decoder_architecture(32),
            Err("The ELF processor is unsupported for code decoding.".into())
        );
    }

    /*
    This test proves that high virtual aliases and zero-fill deltas avoid eager overflow arithmetic.
    Equivalent mappings remain valid, and a large zero-fill address returns no file byte.
    */
    #[test]
    fn elf_high_aliases_and_zero_fill_use_checked_arithmetic() {
        let header = ElfHeader {
            bits: 64,
            file_type: 2,
            machine: 62,
            entry: 0,
            program_offset: 0,
            section_offset: 0,
            program_size: 0,
            program_count: 0,
            section_size: 0,
            section_count: 0,
            section_names: 0,
        };
        let left = ElfSegment {
            header: 0,
            segment_type: 1,
            flags: 5,
            offset: 0x100,
            address: u64::MAX - 0x1ff,
            file_size: 0x100,
            memory_size: 0x100,
            align: 1,
        };
        let right = ElfSegment {
            header: 0,
            segment_type: 1,
            flags: 5,
            offset: 0x180,
            address: u64::MAX - 0x17f,
            file_size: 0x80,
            memory_size: 0x80,
            align: 1,
        };
        let aliases = Elf::from_parts(header, vec![left, right], 0x300).unwrap();
        assert_eq!(aliases.file_to_virtual(0x180), Ok(Some(u64::MAX - 0x17f)));

        let zero = ElfSegment {
            header: 0,
            segment_type: 1,
            flags: 6,
            offset: u64::MAX,
            address: 0,
            file_size: 0,
            memory_size: u64::MAX,
            align: 1,
        };
        let zero_alias = ElfSegment {
            offset: u64::MAX - 1,
            ..zero
        };
        let zero_fill = Elf::from_parts(header, vec![zero, zero_alias], u64::MAX).unwrap();
        assert_eq!(zero_fill.virtual_mapping(u64::MAX - 1), Ok(Some(None)));
        assert_eq!(zero_fill.virtual_to_file(u64::MAX - 1), Ok(None));
    }

    /*
    This test compares buffered and paged ELF metadata and preserves sparse offsets above 4 GiB.
    The paged parser reads only the fixed header and declared table windows.
    */
    #[test]
    fn paged_elf_matches_buffered_and_maps_sparse_high_offsets() {
        let ordinary_path = temp_path("elf-ordinary");
        let ordinary = elf_fixture(64, 62, 3, true);
        std::fs::write(&ordinary_path, &ordinary).unwrap();
        let buffered = Metadata::parse(&ordinary).unwrap();
        let ordinary_file = PagedFile::open(&ordinary_path).unwrap();
        let paged = Metadata::read_from(&ordinary_file).unwrap();
        assert_eq!(buffered.entry_offset(), paged.entry_offset());
        assert_eq!(buffered.code_location(0x110), paged.code_location(0x110));
        assert_eq!(buffered.code_location(0x450), paged.code_location(0x450));
        assert_eq!(
            buffered.target_offset(AddressDomain::Va, 0x400020),
            paged.target_offset(AddressDomain::Va, 0x400020)
        );
        drop(ordinary_file);
        std::fs::remove_file(&ordinary_path).unwrap();

        let path = temp_path("elf-sparse-high");
        let mut data = elf_fixture(64, 62, 2, false);
        let high = 4 * 1024 * 1024 * 1024u64 + 0x100;
        put_qword(&mut data, 24, 0x1_4000_0010);
        put_qword(&mut data, ELF64_HEADER_SIZE + 8, high);
        put_qword(&mut data, ELF64_HEADER_SIZE + 16, 0x1_4000_0000);
        let source = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        source
            .write_all_at(&data[..ELF64_HEADER_SIZE + ELF64_PROGRAM_SIZE], 0)
            .unwrap();
        source.set_len(high + 0x100).unwrap();
        source
            .write_all_at(&[0xe8, 0x0b, 0, 0, 0], high + 0x10)
            .unwrap();
        source.sync_all().unwrap();
        drop(source);

        let file = PagedFile::open(&path).unwrap();
        let metadata = Metadata::read_from(&file).unwrap();
        assert_eq!(metadata.entry_offset(), Ok(high + 0x10));
        assert_eq!(
            metadata.legacy_virtual_offset(0x1_4000_0020),
            Ok(high + 0x20)
        );
        assert_eq!(
            metadata.code_location(high + 0x10).unwrap().address,
            0x1_4000_0010
        );
        assert_eq!(
            metadata.code_location(high + 0x100 - 1).unwrap().domain,
            AddressDomain::Va
        );
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    /*
    This test checks ELF entry availability, table limits, table overlap, and exact 32-bit ends.
    Executable sections must keep their declared file bytes inside the current source.
    */
    #[test]
    fn elf_entries_tables_counts_and_boundaries_are_checked() {
        /*
        The first section keeps missing or non-file-backed entries unavailable without losing metadata.
        A missing section header zero cannot supply an extended program count.
        */
        let valid = elf_fixture(64, 62, 2, false);
        for entry in [0, 0x400100, 0x900000] {
            let mut data = valid.clone();
            put_qword(&mut data, 24, entry);
            let metadata = Metadata::parse(&data).unwrap();
            assert!(metadata.entry_offset().is_err());
            assert!(metadata.code_location(0x110).is_ok());
        }
        let mut missing_section_zero = valid.clone();
        put_word(&mut missing_section_zero, 56, 0xffff);
        assert!(Metadata::parse(&missing_section_zero).is_err());

        /*
        The count section accepts each exact entry limit and rejects the next count before allocation.
        Direct header checks avoid construction of large synthetic tables.
        */
        let mut programs = ElfHeader::parse(&valid, valid.len() as u64).unwrap();
        programs.program_count = ELF_MAX_ENTRIES;
        programs.resolve_counts(None).unwrap();
        programs.program_count += 1;
        assert!(programs.resolve_counts(None).is_err());

        let mut sections = ElfHeader::parse(&valid, valid.len() as u64).unwrap();
        sections.section_offset = 0x100;
        sections.section_size = ELF64_SECTION_SIZE;
        sections.section_count = ELF_MAX_ENTRIES;
        sections.resolve_counts(None).unwrap();
        sections.section_count += 1;
        assert!(sections.resolve_counts(None).is_err());

        /*
        The table section rejects overlapping tables and incomplete declared bytes.
        The executable-section check rejects a current executable range outside the file.
        */
        let mut overlap = elf_fixture(64, 62, 2, true);
        put_qword(&mut overlap, 40, ELF64_HEADER_SIZE as u64);
        assert!(Metadata::parse(&overlap).is_err());
        assert!(Metadata::parse(&valid[..ELF64_HEADER_SIZE + 20]).is_err());

        let mut executable_outside = elf_fixture(64, 62, 2, true);
        let text = 0x300 + ELF64_SECTION_SIZE;
        put_qword(&mut executable_outside, text + 8, 6);
        put_qword(&mut executable_outside, text + 24, 0x4f0);
        put_qword(&mut executable_outside, text + 32, 0x20);
        assert!(Metadata::parse(&executable_outside).is_err());

        /*
        The final section permits an ELF32 file and virtual range that ends at 2^32.
        One additional virtual byte exceeds the supported class range.
        */
        let exact = ElfSegment {
            header: 0,
            segment_type: 1,
            flags: 5,
            offset: 0xffff_fff0,
            address: 0xffff_fff0,
            file_size: 0x10,
            memory_size: 0x10,
            align: 1,
        };
        exact.validate(32, 0x1_0000_0000).unwrap();
        assert!(
            ElfSegment {
                file_size: 0,
                memory_size: 0x11,
                ..exact
            }
            .validate(32, 0x1_0000_0000)
            .is_err()
        );
    }

    /*
    This test checks browser-only section geometry and section-name rules.
    Core metadata stays separate from the stricter buffered structure browser.
    */
    #[test]
    fn elf_structure_browser_rejects_malformed_section_details() {
        let valid = elf_fixture(64, 62, 2, true);
        let text = 0x300 + ELF64_SECTION_SIZE;
        let bss = text + ELF64_SECTION_SIZE;
        let names = bss + ELF64_SECTION_SIZE;

        /*
        The geometry section rejects invalid alignment, entry-size division, and raw overlap.
        NOBITS data does not create a raw overlap until its type changes.
        */
        let mut bad_align = valid.clone();
        put_qword(&mut bad_align, text + 48, 3);
        assert!(structures(&bad_align, 100).is_err());
        let mut bad_entry_size = valid.clone();
        put_qword(&mut bad_entry_size, text + 56, 3);
        assert!(structures(&bad_entry_size, 100).is_err());
        let mut overlap = valid.clone();
        put(&mut overlap, bss + 4, 1);
        put_qword(&mut overlap, bss + 24, 0x180);
        assert!(structures(&overlap, 100).is_err());

        /*
        The name section requires a string-table section with bounded null-terminated names.
        Each failure remains a browser error after core metadata succeeds.
        */
        let mut wrong_name_type = valid.clone();
        put(&mut wrong_name_type, names + 4, 1);
        assert!(Metadata::parse(&wrong_name_type).is_ok());
        assert!(structures(&wrong_name_type, 100).is_err());
        let mut bad_name_start = valid.clone();
        bad_name_start[0x280] = b'X';
        assert!(structures(&bad_name_start, 100).is_err());
        let mut bad_name_end = valid;
        bad_name_end[0x280 + 21] = b'X';
        assert!(structures(&bad_name_end, 100).is_err());
    }

    /*
    This test reparses current ELF paged edits and preserves the owner through metadata errors.
    Undo and Redo restore the matching machine, source length, and metadata result.
    */
    #[test]
    fn paged_elf_reparses_edits_and_preserves_source_errors() {
        let path = temp_path("elf-edits");
        std::fs::write(&path, elf_fixture(64, 62, 2, true)).unwrap();
        let mut source = PagedFile::open(&path).unwrap();
        source.begin_edit().unwrap();
        let cursor = crate::paged::PagedEditCursor {
            offset: 18,
            top: 0,
            low_nibble: false,
        };
        source
            .replace_bytes(18, &183_u16.to_le_bytes(), cursor, cursor, false)
            .unwrap();
        assert_eq!(
            Metadata::read_from(&source)
                .unwrap()
                .decoder_architecture(16),
            Ok(Architecture::Arm64)
        );
        source.undo().unwrap();
        assert_eq!(
            Metadata::read_from(&source)
                .unwrap()
                .decoder_architecture(64),
            Ok(Architecture::X86(64))
        );
        source.redo().unwrap();
        assert_eq!(
            Metadata::read_from(&source)
                .unwrap()
                .decoder_architecture(16),
            Ok(Architecture::Arm64)
        );

        /*
        The truncation section creates a short program and section table through logical spans.
        Metadata failure keeps the edit owner, and Undo restores a fresh successful parse.
        */
        let before = crate::paged::PagedEditCursor {
            offset: 100,
            top: 0,
            low_nibble: false,
        };
        source
            .splice_bytes(100, source.len() - 100, &[], before, before, false)
            .unwrap();
        assert!(Metadata::read_from(&source).is_err());
        assert_eq!(source.len(), 100);
        source.undo().unwrap();
        assert!(Metadata::read_from(&source).is_ok());
        drop(source);
        std::fs::remove_file(&path).unwrap();

        /*
        The replacement section proves that the ELF path preserves the PagedFile validation error.
        The bounded reader must not replace the source error with an ELF truncation message.
        */
        let old = path.with_extension("old");
        std::fs::write(&path, elf_fixture(64, 62, 2, false)).unwrap();
        let source = PagedFile::open(&path).unwrap();
        std::fs::rename(&path, &old).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            Metadata::read_from(&source).err().unwrap(),
            "The source path is not a regular file. Reopen the source."
        );
        drop(source);
        std::fs::remove_dir(path).unwrap();
        std::fs::remove_file(old).unwrap();
    }

    /*
    This test reads maximum-size ELF table strides from sparse offsets above 4 GiB.
    Each paged batch stays within 64 KiB, and exact high mappings survive both table scans.
    */
    #[test]
    fn paged_elf_reads_distant_tables_with_bounded_maximum_strides() {
        let path = temp_path("elf-distant-tables");
        let program_offset = 0x1_0000_1000_u64;
        let stride = u64::from(u16::MAX);
        let section_offset = program_offset + 2 * stride + 0x1000;
        let data_offset = section_offset + 2 * stride + 0x1000;
        let address = 0x2_4000_0000_u64;
        let mut header = elf_fixture(64, 62, 2, false);
        put_qword(&mut header, 24, address + 0x10);
        put_qword(&mut header, 32, program_offset);
        put_qword(&mut header, 40, section_offset);
        put_word(&mut header, 54, u16::MAX);
        put_word(&mut header, 56, 2);
        put_word(&mut header, 58, u16::MAX);
        put_word(&mut header, 60, 2);
        put_word(&mut header, 62, 0);

        /*
        The program section writes one load entry and leaves one sparse PT_NULL entry.
        The section table keeps section zero sparse and places one executable section in entry one.
        */
        let mut program = vec![0_u8; ELF64_PROGRAM_SIZE];
        put(&mut program, 0, 1);
        put(&mut program, 4, 5);
        put_qword(&mut program, 8, data_offset);
        put_qword(&mut program, 16, address);
        put_qword(&mut program, 32, 0x20);
        put_qword(&mut program, 40, 0x20);
        put_qword(&mut program, 48, 1);
        let mut section = vec![0_u8; ELF64_SECTION_SIZE];
        put(&mut section, 4, 1);
        put_qword(&mut section, 8, 4);
        put_qword(&mut section, 16, address);
        put_qword(&mut section, 24, data_offset);
        put_qword(&mut section, 32, 0x20);
        put_qword(&mut section, 48, 1);

        /*
        The final section creates the sparse source and checks exact high entry and address conversion.
        No read allocates the holes before either table or data range.
        */
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(data_offset + 0x20).unwrap();
        file.write_all_at(&header[..ELF64_HEADER_SIZE], 0).unwrap();
        file.write_all_at(&program, program_offset).unwrap();
        file.write_all_at(&section, section_offset + stride)
            .unwrap();
        file.write_all_at(&[0x90], data_offset + 0x10).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let source = PagedFile::open(&path).unwrap();
        let metadata = Metadata::read_from(&source).unwrap();
        assert_eq!(metadata.entry_offset(), Ok(data_offset + 0x10));
        assert_eq!(
            metadata.code_location(data_offset + 0x10).unwrap().address,
            address + 0x10
        );
        assert_eq!(
            metadata.target_offset(AddressDomain::Va, address + 0x1f),
            Ok(data_offset + 0x1f)
        );
        drop(source);
        std::fs::remove_file(path).unwrap();
    }
}
