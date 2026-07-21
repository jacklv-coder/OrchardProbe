//! Bounded, host-only parsing of Mach-O container metadata.
//!
//! This module intentionally reads only Mach-O headers, universal-binary
//! architecture records, and load-command metadata. It does not read or
//! transform encrypted payload bytes. In particular, the absence of an
//! encryption command (or an encryption command whose `cryptid` is zero) is
//! metadata only and is never treated as proof that plaintext was observed.

use std::io::{self, Read, Seek, SeekFrom};

use serde::Serialize;
use thiserror::Error;

const MACH_HEADER_32_SIZE: u64 = 28;
const MACH_HEADER_64_SIZE: u64 = 32;
const FAT_HEADER_SIZE: u64 = 8;
const FAT_ARCH_32_SIZE: u64 = 20;
const FAT_ARCH_64_SIZE: u64 = 32;
const LOAD_COMMAND_HEADER_SIZE: u64 = 8;

const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const ENCRYPTION_INFO_SIZE: u32 = 20;
const ENCRYPTION_INFO_64_SIZE: u32 = 24;

/// Maximum number of architecture slices accepted from a universal binary.
pub const MAX_FAT_SLICES: u32 = 64;

/// Maximum number of load commands accepted from one Mach-O slice.
pub const MAX_LOAD_COMMANDS: u32 = 4_096;

/// Maximum aggregate load-command region accepted from one Mach-O slice.
pub const MAX_LOAD_COMMAND_BYTES: u32 = 16 * 1024 * 1024;

/// Byte order used by a Mach-O header or universal-binary table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    fn read_u32(self, bytes: &[u8], offset: usize) -> u32 {
        let value = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        match self {
            Self::Little => u32::from_le_bytes(value),
            Self::Big => u32::from_be_bytes(value),
        }
    }

    fn read_i32(self, bytes: &[u8], offset: usize) -> i32 {
        self.read_u32(bytes, offset) as i32
    }

    fn read_u64(self, bytes: &[u8], offset: usize) -> u64 {
        let value = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ];
        match self {
            Self::Little => u64::from_le_bytes(value),
            Self::Big => u64::from_be_bytes(value),
        }
    }
}

/// Top-level Mach-O container representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachOContainer {
    Thin,
    Fat32,
    Fat64,
}

/// The encryption load-command variant found in a slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionCommand {
    EncryptionInfo,
    EncryptionInfo64,
}

/// Metadata from `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EncryptionInfo {
    pub command: EncryptionCommand,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

/// Encryption state declared by the Mach-O header metadata.
///
/// This is not a statement about bytes observed at runtime and is not proof of
/// decryption. `NotMarkedEncrypted` means only that the command's `cryptid`
/// field is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionState {
    NotDeclared,
    NotMarkedEncrypted,
    MarkedEncrypted,
}

/// What this metadata-only parser can conclude about plaintext.
///
/// Mach-O header metadata cannot prove that bytes are plaintext. This enum is
/// deliberately single-valued so that a successful parse cannot accidentally
/// be presented as stronger evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextStatus {
    NotProven,
}

/// Metadata for one thin Mach-O slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachOSlice {
    /// Byte offset of the slice from the beginning of the input stream.
    pub offset: u64,
    /// Declared slice size. For a thin file this is the complete file size.
    pub size: u64,
    pub is_64_bit: bool,
    pub endianness: Endianness,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    /// A stable, human-readable architecture label derived from CPU metadata.
    pub architecture: String,
    pub file_type: u32,
    /// A stable, human-readable Mach-O file-type label.
    pub file_type_name: String,
    pub load_command_count: u32,
    pub load_command_bytes: u32,
    /// Header-declared state only; see [`EncryptionState`].
    pub encryption_state: EncryptionState,
    pub encryption: Option<EncryptionInfo>,
    pub plaintext_status: PlaintextStatus,
}

/// Bounded metadata report for a thin or universal Mach-O input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachOReport {
    pub container: MachOContainer,
    /// Byte order of the outer header or universal-binary table.
    pub container_endianness: Endianness,
    pub file_size: u64,
    pub slices: Vec<MachOSlice>,
}

/// Failure while validating or reading Mach-O metadata.
#[derive(Debug, Error)]
pub enum MachOParseError {
    #[error("I/O error while reading Mach-O metadata: {0}")]
    Io(#[from] io::Error),

    #[error("input is too small for a Mach-O magic value: {file_size} bytes")]
    FileTooSmall { file_size: u64 },

    #[error("unsupported Mach-O magic 0x{magic:08x}")]
    UnsupportedMagic { magic: u32 },

    #[error("universal binary declares no architecture slices")]
    NoFatSlices,

    #[error("universal binary declares {count} slices; maximum is {maximum}")]
    TooManyFatSlices { count: u32, maximum: u32 },

    #[error("slice {slice_index} declares {count} load commands; maximum is {maximum}")]
    TooManyLoadCommands {
        slice_index: usize,
        count: u32,
        maximum: u32,
    },

    #[error("slice {slice_index} declares {size} load-command bytes; maximum is {maximum}")]
    LoadCommandsTooLarge {
        slice_index: usize,
        size: u32,
        maximum: u32,
    },

    #[error("integer overflow while calculating {context}")]
    ArithmeticOverflow { context: &'static str },

    #[error("{region} range at offset {offset} with size {size} exceeds containing size {limit}")]
    RangeOutOfBounds {
        region: &'static str,
        offset: u64,
        size: u64,
        limit: u64,
    },

    #[error("slice {slice_index} has zero size")]
    EmptySlice { slice_index: usize },

    #[error(
        "slice {slice_index} starts at {offset}, inside the universal header/table ending at {table_end}"
    )]
    SliceOverlapsFatTable {
        slice_index: usize,
        offset: u64,
        table_end: u64,
    },

    #[error(
        "slice {slice_index} offset {offset} does not satisfy alignment exponent {alignment_power}"
    )]
    InvalidFatAlignment {
        slice_index: usize,
        offset: u64,
        alignment_power: u32,
    },

    #[error("slice {first_slice} overlaps slice {second_slice}")]
    OverlappingSlices {
        first_slice: usize,
        second_slice: usize,
    },

    #[error("slice {slice_index} contains another universal-binary header")]
    NestedFatContainer { slice_index: usize },

    #[error(
        "slice {slice_index} CPU metadata differs between the universal table and Mach-O header"
    )]
    FatCpuMismatch { slice_index: usize },

    #[error(
        "slice {slice_index} load command {command_index} has size {size}; minimum is {minimum}"
    )]
    InvalidLoadCommandSize {
        slice_index: usize,
        command_index: u32,
        size: u32,
        minimum: u32,
    },

    #[error(
        "slice {slice_index} load command {command_index} has size {size}, which is not aligned to {required_alignment} bytes"
    )]
    MisalignedLoadCommandSize {
        slice_index: usize,
        command_index: u32,
        size: u32,
        required_alignment: u32,
    },

    #[error(
        "slice {slice_index} load command {command_index} at slice offset {offset} with size {size} exceeds the declared load-command table ending at slice offset {limit}"
    )]
    LoadCommandOutOfBounds {
        slice_index: usize,
        command_index: u32,
        offset: u64,
        size: u64,
        limit: u64,
    },

    #[error(
        "slice {slice_index} load commands consume {consumed} bytes, but sizeofcmds declares {declared}"
    )]
    LoadCommandTableSizeMismatch {
        slice_index: usize,
        consumed: u64,
        declared: u64,
    },

    #[error(
        "slice {slice_index} has duplicate encryption load commands at indexes {first_command} and {second_command}"
    )]
    DuplicateEncryptionCommand {
        slice_index: usize,
        first_command: u32,
        second_command: u32,
    },

    #[error(
        "slice {slice_index} load command {command_index} uses encryption command 0x{command:08x}, which does not match the slice bitness"
    )]
    EncryptionCommandBitnessMismatch {
        slice_index: usize,
        command_index: u32,
        command: u32,
    },

    #[error(
        "slice {slice_index} load command {command_index} has encryption-command size {size}; expected exactly {expected}"
    )]
    InvalidEncryptionCommandSize {
        slice_index: usize,
        command_index: u32,
        size: u32,
        expected: u32,
    },

    #[error(
        "slice {slice_index} load command {command_index} has nonzero 64-bit encryption padding"
    )]
    NonZeroEncryptionPadding {
        slice_index: usize,
        command_index: u32,
    },
}

#[derive(Debug, Clone, Copy)]
enum MagicKind {
    Thin {
        endianness: Endianness,
        is_64_bit: bool,
    },
    Fat {
        endianness: Endianness,
        is_64_bit: bool,
    },
}

#[derive(Debug, Clone, Copy)]
struct FatSliceDescriptor {
    index: usize,
    offset: u64,
    size: u64,
    cpu_type: i32,
    cpu_subtype: i32,
}

/// Parse bounded Mach-O metadata from the complete seekable input stream.
///
/// Parsing always begins at stream offset zero. Only fixed-size headers,
/// universal-binary architecture records, and the leading fields of load
/// commands are read. Payload bytes are never copied into memory.
pub fn parse_macho<R: Read + Seek>(reader: &mut R) -> Result<MachOReport, MachOParseError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    if file_size < 4 {
        return Err(MachOParseError::FileTooSmall { file_size });
    }

    let magic_bytes = read_magic(reader, 0, file_size)?;
    let magic = classify_magic(magic_bytes).ok_or(MachOParseError::UnsupportedMagic {
        magic: u32::from_be_bytes(magic_bytes),
    })?;

    match magic {
        MagicKind::Thin {
            endianness,
            is_64_bit,
        } => Ok(MachOReport {
            container: MachOContainer::Thin,
            container_endianness: endianness,
            file_size,
            slices: vec![parse_slice(
                reader,
                file_size,
                FatSliceDescriptor {
                    index: 0,
                    offset: 0,
                    size: file_size,
                    cpu_type: 0,
                    cpu_subtype: 0,
                },
                is_64_bit,
                endianness,
                None,
            )?],
        }),
        MagicKind::Fat {
            endianness,
            is_64_bit,
        } => parse_fat(reader, file_size, endianness, is_64_bit),
    }
}

fn parse_fat<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    endianness: Endianness,
    is_64_bit: bool,
) -> Result<MachOReport, MachOParseError> {
    let mut header = [0_u8; FAT_HEADER_SIZE as usize];
    read_exact_at(reader, 0, &mut header, file_size, "universal header")?;
    let slice_count = endianness.read_u32(&header, 4);
    if slice_count == 0 {
        return Err(MachOParseError::NoFatSlices);
    }
    if slice_count > MAX_FAT_SLICES {
        return Err(MachOParseError::TooManyFatSlices {
            count: slice_count,
            maximum: MAX_FAT_SLICES,
        });
    }

    let record_size = if is_64_bit {
        FAT_ARCH_64_SIZE
    } else {
        FAT_ARCH_32_SIZE
    };
    let table_size = record_size.checked_mul(u64::from(slice_count)).ok_or(
        MachOParseError::ArithmeticOverflow {
            context: "universal architecture table size",
        },
    )?;
    let table_end =
        FAT_HEADER_SIZE
            .checked_add(table_size)
            .ok_or(MachOParseError::ArithmeticOverflow {
                context: "universal architecture table end",
            })?;
    ensure_range(
        FAT_HEADER_SIZE,
        table_size,
        file_size,
        "universal architecture table",
    )?;

    let mut descriptors = Vec::with_capacity(slice_count as usize);
    for table_index in 0..slice_count {
        let relative_record_offset = record_size.checked_mul(u64::from(table_index)).ok_or(
            MachOParseError::ArithmeticOverflow {
                context: "universal architecture record offset",
            },
        )?;
        let record_offset = FAT_HEADER_SIZE.checked_add(relative_record_offset).ok_or(
            MachOParseError::ArithmeticOverflow {
                context: "universal architecture record offset",
            },
        )?;
        let mut record = [0_u8; FAT_ARCH_64_SIZE as usize];
        read_exact_at(
            reader,
            record_offset,
            &mut record[..record_size as usize],
            file_size,
            "universal architecture record",
        )?;

        let cpu_type = endianness.read_i32(&record, 0);
        let cpu_subtype = endianness.read_i32(&record, 4);
        let (offset, size, alignment_power) = if is_64_bit {
            // Bytes 28..32 are `fat_arch_64.reserved`. Apple's `fat.h`
            // imposes no must-be-zero rule on that field, and the parser does
            // not rely on it. Ignoring it preserves forward compatibility.
            (
                endianness.read_u64(&record, 8),
                endianness.read_u64(&record, 16),
                endianness.read_u32(&record, 24),
            )
        } else {
            (
                u64::from(endianness.read_u32(&record, 8)),
                u64::from(endianness.read_u32(&record, 12)),
                endianness.read_u32(&record, 16),
            )
        };
        let slice_index = table_index as usize;

        if size == 0 {
            return Err(MachOParseError::EmptySlice { slice_index });
        }
        if offset < table_end {
            return Err(MachOParseError::SliceOverlapsFatTable {
                slice_index,
                offset,
                table_end,
            });
        }
        let alignment =
            1_u64
                .checked_shl(alignment_power)
                .ok_or(MachOParseError::InvalidFatAlignment {
                    slice_index,
                    offset,
                    alignment_power,
                })?;
        if offset % alignment != 0 {
            return Err(MachOParseError::InvalidFatAlignment {
                slice_index,
                offset,
                alignment_power,
            });
        }

        ensure_range(offset, size, file_size, "universal Mach-O slice")?;
        descriptors.push(FatSliceDescriptor {
            index: slice_index,
            offset,
            size,
            cpu_type,
            cpu_subtype,
        });
    }

    reject_overlapping_slices(&descriptors)?;

    let mut slices = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let mut magic_bytes = [0_u8; 4];
        read_exact_in_slice(
            reader,
            descriptor,
            0,
            &mut magic_bytes,
            file_size,
            "Mach-O slice magic",
        )?;
        let magic = classify_magic(magic_bytes).ok_or(MachOParseError::UnsupportedMagic {
            magic: u32::from_be_bytes(magic_bytes),
        })?;
        let MagicKind::Thin {
            endianness: slice_endianness,
            is_64_bit: slice_is_64_bit,
        } = magic
        else {
            return Err(MachOParseError::NestedFatContainer {
                slice_index: descriptor.index,
            });
        };

        slices.push(parse_slice(
            reader,
            file_size,
            descriptor,
            slice_is_64_bit,
            slice_endianness,
            Some((descriptor.cpu_type, descriptor.cpu_subtype)),
        )?);
    }

    Ok(MachOReport {
        container: if is_64_bit {
            MachOContainer::Fat64
        } else {
            MachOContainer::Fat32
        },
        container_endianness: endianness,
        file_size,
        slices,
    })
}

fn parse_slice<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    descriptor: FatSliceDescriptor,
    is_64_bit: bool,
    endianness: Endianness,
    expected_cpu: Option<(i32, i32)>,
) -> Result<MachOSlice, MachOParseError> {
    let header_size = if is_64_bit {
        MACH_HEADER_64_SIZE
    } else {
        MACH_HEADER_32_SIZE
    };
    ensure_range(0, header_size, descriptor.size, "Mach-O header")?;

    let mut header = [0_u8; MACH_HEADER_64_SIZE as usize];
    read_exact_in_slice(
        reader,
        descriptor,
        0,
        &mut header[..header_size as usize],
        file_size,
        "Mach-O header",
    )?;

    let cpu_type = endianness.read_i32(&header, 4);
    let cpu_subtype = endianness.read_i32(&header, 8);
    if let Some((fat_cpu_type, fat_cpu_subtype)) = expected_cpu {
        if cpu_type != fat_cpu_type || cpu_subtype != fat_cpu_subtype {
            return Err(MachOParseError::FatCpuMismatch {
                slice_index: descriptor.index,
            });
        }
    }

    let file_type = endianness.read_u32(&header, 12);
    let command_count = endianness.read_u32(&header, 16);
    let command_bytes = endianness.read_u32(&header, 20);
    if command_count > MAX_LOAD_COMMANDS {
        return Err(MachOParseError::TooManyLoadCommands {
            slice_index: descriptor.index,
            count: command_count,
            maximum: MAX_LOAD_COMMANDS,
        });
    }
    if command_bytes > MAX_LOAD_COMMAND_BYTES {
        return Err(MachOParseError::LoadCommandsTooLarge {
            slice_index: descriptor.index,
            size: command_bytes,
            maximum: MAX_LOAD_COMMAND_BYTES,
        });
    }
    ensure_range(
        header_size,
        u64::from(command_bytes),
        descriptor.size,
        "Mach-O load-command table",
    )?;

    let mut command_offset = header_size;
    let command_table_end = header_size.checked_add(u64::from(command_bytes)).ok_or(
        MachOParseError::ArithmeticOverflow {
            context: "Mach-O load-command table end",
        },
    )?;
    let mut encryption = None;
    let mut encryption_command_index = None;

    for command_index in 0..command_count {
        let remaining = command_table_end.checked_sub(command_offset).ok_or(
            MachOParseError::ArithmeticOverflow {
                context: "remaining Mach-O load-command bytes",
            },
        )?;
        if remaining < LOAD_COMMAND_HEADER_SIZE {
            return Err(MachOParseError::LoadCommandOutOfBounds {
                slice_index: descriptor.index,
                command_index,
                offset: command_offset,
                size: LOAD_COMMAND_HEADER_SIZE,
                limit: command_table_end,
            });
        }

        let mut command_header = [0_u8; LOAD_COMMAND_HEADER_SIZE as usize];
        read_exact_in_slice(
            reader,
            descriptor,
            command_offset,
            &mut command_header,
            file_size,
            "Mach-O load-command header",
        )?;
        let command = endianness.read_u32(&command_header, 0);
        let command_size = endianness.read_u32(&command_header, 4);
        if command_size < LOAD_COMMAND_HEADER_SIZE as u32 {
            return Err(MachOParseError::InvalidLoadCommandSize {
                slice_index: descriptor.index,
                command_index,
                size: command_size,
                minimum: LOAD_COMMAND_HEADER_SIZE as u32,
            });
        }

        let encryption_command = command == LC_ENCRYPTION_INFO || command == LC_ENCRYPTION_INFO_64;
        if encryption_command
            && ((is_64_bit && command != LC_ENCRYPTION_INFO_64)
                || (!is_64_bit && command != LC_ENCRYPTION_INFO))
        {
            return Err(MachOParseError::EncryptionCommandBitnessMismatch {
                slice_index: descriptor.index,
                command_index,
                command,
            });
        }
        if encryption_command {
            let expected = if is_64_bit {
                ENCRYPTION_INFO_64_SIZE
            } else {
                ENCRYPTION_INFO_SIZE
            };
            if command_size != expected {
                return Err(MachOParseError::InvalidEncryptionCommandSize {
                    slice_index: descriptor.index,
                    command_index,
                    size: command_size,
                    expected,
                });
            }
        }

        let required_alignment = if is_64_bit { 8 } else { 4 };
        if command_size % required_alignment != 0 {
            return Err(MachOParseError::MisalignedLoadCommandSize {
                slice_index: descriptor.index,
                command_index,
                size: command_size,
                required_alignment,
            });
        }

        let command_end = command_offset.checked_add(u64::from(command_size)).ok_or(
            MachOParseError::ArithmeticOverflow {
                context: "Mach-O load-command end",
            },
        )?;
        if command_end > command_table_end {
            return Err(MachOParseError::LoadCommandOutOfBounds {
                slice_index: descriptor.index,
                command_index,
                offset: command_offset,
                size: u64::from(command_size),
                limit: command_table_end,
            });
        }

        if encryption_command {
            if let Some(first_command) = encryption_command_index {
                return Err(MachOParseError::DuplicateEncryptionCommand {
                    slice_index: descriptor.index,
                    first_command,
                    second_command: command_index,
                });
            }

            let payload_offset = command_offset.checked_add(LOAD_COMMAND_HEADER_SIZE).ok_or(
                MachOParseError::ArithmeticOverflow {
                    context: "Mach-O encryption-command payload offset",
                },
            )?;
            let mut payload = [0_u8; 16];
            let payload_size = if is_64_bit { 16 } else { 12 };
            read_exact_in_slice(
                reader,
                descriptor,
                payload_offset,
                &mut payload[..payload_size],
                file_size,
                "Mach-O encryption-command payload",
            )?;
            let cryptoff = endianness.read_u32(&payload, 0);
            let cryptsize = endianness.read_u32(&payload, 4);
            let cryptid = endianness.read_u32(&payload, 8);
            if is_64_bit && endianness.read_u32(&payload, 12) != 0 {
                return Err(MachOParseError::NonZeroEncryptionPadding {
                    slice_index: descriptor.index,
                    command_index,
                });
            }
            ensure_range(
                u64::from(cryptoff),
                u64::from(cryptsize),
                descriptor.size,
                "Mach-O encrypted byte range",
            )?;

            encryption = Some(EncryptionInfo {
                command: if command == LC_ENCRYPTION_INFO {
                    EncryptionCommand::EncryptionInfo
                } else {
                    EncryptionCommand::EncryptionInfo64
                },
                cryptoff,
                cryptsize,
                cryptid,
            });
            encryption_command_index = Some(command_index);
        }

        command_offset = command_end;
    }

    if command_offset != command_table_end {
        let consumed =
            command_offset
                .checked_sub(header_size)
                .ok_or(MachOParseError::ArithmeticOverflow {
                    context: "consumed Mach-O load-command bytes",
                })?;
        return Err(MachOParseError::LoadCommandTableSizeMismatch {
            slice_index: descriptor.index,
            consumed,
            declared: u64::from(command_bytes),
        });
    }

    let encryption_state = match encryption.as_ref() {
        None => EncryptionState::NotDeclared,
        Some(info) if info.cryptid == 0 => EncryptionState::NotMarkedEncrypted,
        Some(_) => EncryptionState::MarkedEncrypted,
    };

    Ok(MachOSlice {
        offset: descriptor.offset,
        size: descriptor.size,
        is_64_bit,
        endianness,
        cpu_type,
        cpu_subtype,
        architecture: architecture_name(cpu_type, cpu_subtype),
        file_type,
        file_type_name: file_type_name(file_type).to_owned(),
        load_command_count: command_count,
        load_command_bytes: command_bytes,
        encryption_state,
        encryption,
        plaintext_status: PlaintextStatus::NotProven,
    })
}

fn reject_overlapping_slices(descriptors: &[FatSliceDescriptor]) -> Result<(), MachOParseError> {
    let mut ranges = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let end = descriptor.offset.checked_add(descriptor.size).ok_or(
            MachOParseError::ArithmeticOverflow {
                context: "universal Mach-O slice end",
            },
        )?;
        ranges.push((descriptor.offset, end, descriptor.index));
    }
    ranges.sort_by_key(|range| range.0);

    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(MachOParseError::OverlappingSlices {
                first_slice: pair[0].2,
                second_slice: pair[1].2,
            });
        }
    }
    Ok(())
}

fn read_magic<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    file_size: u64,
) -> Result<[u8; 4], MachOParseError> {
    let mut magic = [0_u8; 4];
    read_exact_at(reader, offset, &mut magic, file_size, "Mach-O magic")?;
    Ok(magic)
}

fn read_exact_in_slice<R: Read + Seek>(
    reader: &mut R,
    descriptor: FatSliceDescriptor,
    relative_offset: u64,
    buffer: &mut [u8],
    file_size: u64,
    region: &'static str,
) -> Result<(), MachOParseError> {
    let size = buffer.len() as u64;
    ensure_range(relative_offset, size, descriptor.size, region)?;
    let absolute_offset = descriptor.offset.checked_add(relative_offset).ok_or(
        MachOParseError::ArithmeticOverflow {
            context: "absolute Mach-O slice read offset",
        },
    )?;
    read_exact_at(reader, absolute_offset, buffer, file_size, region)
}

fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
    file_size: u64,
    region: &'static str,
) -> Result<(), MachOParseError> {
    ensure_range(offset, buffer.len() as u64, file_size, region)?;
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buffer)?;
    Ok(())
}

fn ensure_range(
    offset: u64,
    size: u64,
    limit: u64,
    region: &'static str,
) -> Result<(), MachOParseError> {
    let end = offset
        .checked_add(size)
        .ok_or(MachOParseError::ArithmeticOverflow { context: region })?;
    if end > limit {
        return Err(MachOParseError::RangeOutOfBounds {
            region,
            offset,
            size,
            limit,
        });
    }
    Ok(())
}

fn classify_magic(bytes: [u8; 4]) -> Option<MagicKind> {
    match bytes {
        [0xce, 0xfa, 0xed, 0xfe] => Some(MagicKind::Thin {
            endianness: Endianness::Little,
            is_64_bit: false,
        }),
        [0xfe, 0xed, 0xfa, 0xce] => Some(MagicKind::Thin {
            endianness: Endianness::Big,
            is_64_bit: false,
        }),
        [0xcf, 0xfa, 0xed, 0xfe] => Some(MagicKind::Thin {
            endianness: Endianness::Little,
            is_64_bit: true,
        }),
        [0xfe, 0xed, 0xfa, 0xcf] => Some(MagicKind::Thin {
            endianness: Endianness::Big,
            is_64_bit: true,
        }),
        [0xca, 0xfe, 0xba, 0xbe] => Some(MagicKind::Fat {
            endianness: Endianness::Big,
            is_64_bit: false,
        }),
        [0xbe, 0xba, 0xfe, 0xca] => Some(MagicKind::Fat {
            endianness: Endianness::Little,
            is_64_bit: false,
        }),
        [0xca, 0xfe, 0xba, 0xbf] => Some(MagicKind::Fat {
            endianness: Endianness::Big,
            is_64_bit: true,
        }),
        [0xbf, 0xba, 0xfe, 0xca] => Some(MagicKind::Fat {
            endianness: Endianness::Little,
            is_64_bit: true,
        }),
        _ => None,
    }
}

fn architecture_name(cpu_type: i32, cpu_subtype: i32) -> String {
    let subtype = (cpu_subtype as u32) & 0x00ff_ffff;
    match (cpu_type as u32, subtype) {
        (7, 3) => "i386".to_owned(),
        (7, 4) => "i486".to_owned(),
        (7, _) => "x86".to_owned(),
        (0x0100_0007, 8) => "x86_64h".to_owned(),
        (0x0100_0007, _) => "x86_64".to_owned(),
        (12, 5) => "armv4t".to_owned(),
        (12, 6) => "armv6".to_owned(),
        (12, 7) => "armv5tej".to_owned(),
        (12, 8) => "xscale".to_owned(),
        (12, 9) => "armv7".to_owned(),
        (12, 10) => "armv7f".to_owned(),
        (12, 11) => "armv7s".to_owned(),
        (12, 12) => "armv7k".to_owned(),
        (12, 13) => "armv8".to_owned(),
        (12, 14) => "armv6m".to_owned(),
        (12, 15) => "armv7m".to_owned(),
        (12, 16) => "armv7em".to_owned(),
        (12, _) => "arm".to_owned(),
        (0x0100_000c, 2) => "arm64e".to_owned(),
        (0x0100_000c, _) => "arm64".to_owned(),
        (0x0200_000c, _) => "arm64_32".to_owned(),
        (18, _) => "powerpc".to_owned(),
        (0x0100_0012, _) => "powerpc64".to_owned(),
        (raw, _) => format!("unknown_cpu_0x{raw:08x}"),
    }
}

fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
        1 => "object",
        2 => "execute",
        3 => "fixed_vm_library",
        4 => "core",
        5 => "preload",
        6 => "dynamic_library",
        7 => "dynamic_linker",
        8 => "bundle",
        9 => "dynamic_library_stub",
        10 => "debug_symbols",
        11 => "kernel_extension_bundle",
        12 => "fileset",
        13 => "gpu_execute",
        14 => "gpu_dynamic_library",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::*;

    const CPU_TYPE_X86: u32 = 7;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;

    fn push_u32(bytes: &mut Vec<u8>, endianness: Endianness, value: u32) {
        let encoded = match endianness {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        bytes.extend_from_slice(&encoded);
    }

    fn push_u64(bytes: &mut Vec<u8>, endianness: Endianness, value: u64) {
        let encoded = match endianness {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        bytes.extend_from_slice(&encoded);
    }

    fn thin_magic(endianness: Endianness, is_64_bit: bool) -> [u8; 4] {
        match (endianness, is_64_bit) {
            (Endianness::Little, false) => [0xce, 0xfa, 0xed, 0xfe],
            (Endianness::Big, false) => [0xfe, 0xed, 0xfa, 0xce],
            (Endianness::Little, true) => [0xcf, 0xfa, 0xed, 0xfe],
            (Endianness::Big, true) => [0xfe, 0xed, 0xfa, 0xcf],
        }
    }

    fn fat_magic(endianness: Endianness, is_64_bit: bool) -> [u8; 4] {
        match (endianness, is_64_bit) {
            (Endianness::Big, false) => [0xca, 0xfe, 0xba, 0xbe],
            (Endianness::Little, false) => [0xbe, 0xba, 0xfe, 0xca],
            (Endianness::Big, true) => [0xca, 0xfe, 0xba, 0xbf],
            (Endianness::Little, true) => [0xbf, 0xba, 0xfe, 0xca],
        }
    }

    fn encryption_command(endianness: Endianness, is_64_bit: bool, cryptid: u32) -> Vec<u8> {
        let mut command = Vec::new();
        let command_size = if is_64_bit {
            ENCRYPTION_INFO_64_SIZE
        } else {
            ENCRYPTION_INFO_SIZE
        };
        push_u32(
            &mut command,
            endianness,
            if is_64_bit {
                LC_ENCRYPTION_INFO_64
            } else {
                LC_ENCRYPTION_INFO
            },
        );
        push_u32(&mut command, endianness, command_size);
        push_u32(&mut command, endianness, 32);
        push_u32(&mut command, endianness, 16);
        push_u32(&mut command, endianness, cryptid);
        if is_64_bit {
            push_u32(&mut command, endianness, 0);
        }
        command
    }

    fn raw_command(endianness: Endianness, command: u32, command_size: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_u32(&mut bytes, endianness, command);
        push_u32(&mut bytes, endianness, command_size);
        bytes.resize(command_size as usize, 0);
        bytes
    }

    fn thin(
        endianness: Endianness,
        is_64_bit: bool,
        cpu_type: u32,
        cpu_subtype: u32,
        commands: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&thin_magic(endianness, is_64_bit));
        push_u32(&mut bytes, endianness, cpu_type);
        push_u32(&mut bytes, endianness, cpu_subtype);
        push_u32(&mut bytes, endianness, 2);
        push_u32(&mut bytes, endianness, commands.len() as u32);
        let command_bytes = commands.iter().map(Vec::len).sum::<usize>();
        push_u32(&mut bytes, endianness, command_bytes as u32);
        push_u32(&mut bytes, endianness, 0);
        if is_64_bit {
            push_u32(&mut bytes, endianness, 0);
        }
        for command in commands {
            bytes.extend_from_slice(command);
        }
        bytes
    }

    fn fat(
        endianness: Endianness,
        is_64_bit: bool,
        slice: &[u8],
        cpu_type: u32,
        cpu_subtype: u32,
    ) -> Vec<u8> {
        let offset = 256_u64;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&fat_magic(endianness, is_64_bit));
        push_u32(&mut bytes, endianness, 1);
        push_u32(&mut bytes, endianness, cpu_type);
        push_u32(&mut bytes, endianness, cpu_subtype);
        if is_64_bit {
            push_u64(&mut bytes, endianness, offset);
            push_u64(&mut bytes, endianness, slice.len() as u64);
            push_u32(&mut bytes, endianness, 0);
            push_u32(&mut bytes, endianness, 0);
        } else {
            push_u32(&mut bytes, endianness, offset as u32);
            push_u32(&mut bytes, endianness, slice.len() as u32);
            push_u32(&mut bytes, endianness, 0);
        }
        bytes.resize(offset as usize, 0);
        bytes.extend_from_slice(slice);
        bytes
    }

    fn parse(bytes: Vec<u8>) -> Result<MachOReport, MachOParseError> {
        parse_macho(&mut Cursor::new(bytes))
    }

    #[test]
    fn parses_thin_32_and_64_bit_in_both_byte_orders() {
        for (endianness, is_64_bit, cpu_type, expected_architecture) in [
            (Endianness::Little, false, CPU_TYPE_X86, "i386"),
            (Endianness::Big, false, CPU_TYPE_X86, "i386"),
            (Endianness::Little, true, CPU_TYPE_ARM64, "arm64e"),
            (Endianness::Big, true, CPU_TYPE_X86_64, "x86_64h"),
        ] {
            let subtype = if cpu_type == CPU_TYPE_ARM64 {
                2
            } else if is_64_bit {
                8
            } else {
                3
            };
            let command = encryption_command(endianness, is_64_bit, 1);
            let report = parse(thin(endianness, is_64_bit, cpu_type, subtype, &[command]))
                .expect("valid thin Mach-O parses");

            assert_eq!(report.container, MachOContainer::Thin);
            assert_eq!(report.container_endianness, endianness);
            assert_eq!(report.slices.len(), 1);
            let slice = &report.slices[0];
            assert_eq!(slice.offset, 0);
            assert_eq!(slice.endianness, endianness);
            assert_eq!(slice.is_64_bit, is_64_bit);
            assert_eq!(slice.architecture, expected_architecture);
            assert_eq!(slice.file_type_name, "execute");
            assert_eq!(slice.encryption_state, EncryptionState::MarkedEncrypted);
            assert_eq!(slice.plaintext_status, PlaintextStatus::NotProven);
            assert_eq!(slice.encryption.as_ref().map(|info| info.cryptid), Some(1));
        }
    }

    #[test]
    fn parses_fat32_and_fat64_in_both_byte_orders() {
        let slice = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[]);
        for (endianness, is_64_bit, expected_container) in [
            (Endianness::Little, false, MachOContainer::Fat32),
            (Endianness::Big, false, MachOContainer::Fat32),
            (Endianness::Little, true, MachOContainer::Fat64),
            (Endianness::Big, true, MachOContainer::Fat64),
        ] {
            let report = parse(fat(endianness, is_64_bit, &slice, CPU_TYPE_ARM64, 0))
                .expect("valid universal Mach-O parses");

            assert_eq!(report.container, expected_container);
            assert_eq!(report.container_endianness, endianness);
            assert_eq!(report.slices[0].offset, 256);
            assert_eq!(report.slices[0].size, slice.len() as u64);
            assert_eq!(report.slices[0].architecture, "arm64");
        }
    }

    #[test]
    fn zero_cryptid_and_missing_command_do_not_prove_plaintext() {
        let zero_cryptid = parse(thin(
            Endianness::Little,
            true,
            CPU_TYPE_ARM64,
            0,
            &[encryption_command(Endianness::Little, true, 0)],
        ))
        .expect("valid zero-cryptid command parses");
        assert_eq!(
            zero_cryptid.slices[0]
                .encryption
                .as_ref()
                .map(|info| info.cryptid),
            Some(0)
        );
        assert_eq!(
            zero_cryptid.slices[0].plaintext_status,
            PlaintextStatus::NotProven
        );
        assert_eq!(
            zero_cryptid.slices[0].encryption_state,
            EncryptionState::NotMarkedEncrypted
        );

        let no_command = parse(thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[]))
            .expect("valid command-free Mach-O parses");
        assert!(no_command.slices[0].encryption.is_none());
        assert_eq!(
            serde_json::to_value(&no_command.slices[0]).expect("slice serializes"),
            json!({
                "offset": 0,
                "size": 32,
                "is_64_bit": true,
                "endianness": "little",
                "cpu_type": 16_777_228,
                "cpu_subtype": 0,
                "architecture": "arm64",
                "file_type": 2,
                "file_type_name": "execute",
                "load_command_count": 0,
                "load_command_bytes": 0,
                "encryption_state": "not_declared",
                "encryption": null,
                "plaintext_status": "not_proven"
            })
        );
    }

    #[test]
    fn rejects_truncated_headers() {
        assert!(matches!(
            parse(vec![0xcf, 0xfa, 0xed]),
            Err(MachOParseError::FileTooSmall { .. })
        ));

        assert!(matches!(
            parse(vec![0xcf, 0xfa, 0xed, 0xfe]),
            Err(MachOParseError::RangeOutOfBounds {
                region: "Mach-O header",
                ..
            })
        ));

        let mut truncated_fat = Vec::new();
        truncated_fat.extend_from_slice(&fat_magic(Endianness::Big, false));
        push_u32(&mut truncated_fat, Endianness::Big, 1);
        assert!(matches!(
            parse(truncated_fat),
            Err(MachOParseError::RangeOutOfBounds {
                region: "universal architecture table",
                ..
            })
        ));
    }

    #[test]
    fn rejects_fat64_slice_range_overflow() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&fat_magic(Endianness::Big, true));
        push_u32(&mut bytes, Endianness::Big, 1);
        push_u32(&mut bytes, Endianness::Big, CPU_TYPE_ARM64);
        push_u32(&mut bytes, Endianness::Big, 0);
        push_u64(&mut bytes, Endianness::Big, u64::MAX - 15);
        push_u64(&mut bytes, Endianness::Big, 32);
        push_u32(&mut bytes, Endianness::Big, 0);
        push_u32(&mut bytes, Endianness::Big, 0);

        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::ArithmeticOverflow {
                context: "universal Mach-O slice",
            })
        ));
    }

    #[test]
    fn rejects_too_many_slices_before_reading_the_table() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&fat_magic(Endianness::Big, false));
        push_u32(&mut bytes, Endianness::Big, MAX_FAT_SLICES + 1);

        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::TooManyFatSlices { .. })
        ));
    }

    #[test]
    fn rejects_too_many_load_commands_before_walking_them() {
        let mut bytes = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[]);
        bytes[16..20].copy_from_slice(&(MAX_LOAD_COMMANDS + 1).to_le_bytes());

        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::TooManyLoadCommands { .. })
        ));
    }

    #[test]
    fn rejects_oversized_load_command_region_before_reading_it() {
        let mut bytes = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[]);
        bytes[20..24].copy_from_slice(&(MAX_LOAD_COMMAND_BYTES + 1).to_le_bytes());

        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::LoadCommandsTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_misaligned_load_command_sizes_for_each_bitness() {
        for (is_64_bit, command_size, required_alignment, cpu_type) in
            [(false, 10, 4, CPU_TYPE_X86), (true, 12, 8, CPU_TYPE_ARM64)]
        {
            let command = raw_command(Endianness::Little, 1, command_size);
            let bytes = thin(Endianness::Little, is_64_bit, cpu_type, 0, &[command]);

            assert!(matches!(
                parse(bytes),
                Err(MachOParseError::MisalignedLoadCommandSize {
                    size,
                    required_alignment: alignment,
                    ..
                }) if size == command_size && alignment == required_alignment
            ));
        }
    }

    #[test]
    fn rejects_load_commands_that_cross_the_declared_table() {
        let mut bad_command = Vec::new();
        push_u32(&mut bad_command, Endianness::Little, 1);
        push_u32(&mut bad_command, Endianness::Little, 16);
        let bytes = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[bad_command]);

        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::LoadCommandOutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_unconsumed_declared_load_command_bytes() {
        let mut command = raw_command(Endianness::Little, 1, 8);
        command.extend_from_slice(&[0_u8; 8]);
        let bytes = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[command]);

        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::LoadCommandTableSizeMismatch {
                consumed: 8,
                declared: 16,
                ..
            })
        ));
    }

    #[test]
    fn rejects_wrong_encryption_command_size_and_bitness() {
        let mut oversized = encryption_command(Endianness::Little, true, 1);
        oversized[4..8].copy_from_slice(&32_u32.to_le_bytes());
        oversized.resize(32, 0);
        let wrong_size = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[oversized]);
        assert!(matches!(
            parse(wrong_size),
            Err(MachOParseError::InvalidEncryptionCommandSize {
                size: 32,
                expected: ENCRYPTION_INFO_64_SIZE,
                ..
            })
        ));

        let command_32 = encryption_command(Endianness::Little, false, 1);
        let wrong_bitness = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[command_32]);
        assert!(matches!(
            parse(wrong_bitness),
            Err(MachOParseError::EncryptionCommandBitnessMismatch {
                command: LC_ENCRYPTION_INFO,
                ..
            })
        ));
    }

    #[test]
    fn rejects_nonzero_encryption_padding_and_out_of_bounds_range() {
        let mut nonzero_padding = encryption_command(Endianness::Little, true, 1);
        nonzero_padding[20..24].copy_from_slice(&1_u32.to_le_bytes());
        let bytes = thin(
            Endianness::Little,
            true,
            CPU_TYPE_ARM64,
            0,
            &[nonzero_padding],
        );
        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::NonZeroEncryptionPadding { .. })
        ));

        let mut invalid_range = encryption_command(Endianness::Little, true, 1);
        invalid_range[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let bytes = thin(
            Endianness::Little,
            true,
            CPU_TYPE_ARM64,
            0,
            &[invalid_range],
        );
        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::RangeOutOfBounds {
                region: "Mach-O encrypted byte range",
                ..
            })
        ));
    }

    #[test]
    fn rejects_duplicate_encryption_commands() {
        let command = encryption_command(Endianness::Little, true, 1);
        let bytes = thin(
            Endianness::Little,
            true,
            CPU_TYPE_ARM64,
            0,
            &[command.clone(), command],
        );

        assert!(matches!(
            parse(bytes),
            Err(MachOParseError::DuplicateEncryptionCommand {
                first_command: 0,
                second_command: 1,
                ..
            })
        ));
    }

    #[test]
    fn rejects_fat_slice_table_overlap_slice_overlap_and_nested_fat() {
        let slice = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[]);

        let mut table_overlap = fat(Endianness::Big, false, &slice, CPU_TYPE_ARM64, 0);
        table_overlap[16..20].copy_from_slice(&8_u32.to_be_bytes());
        assert!(matches!(
            parse(table_overlap),
            Err(MachOParseError::SliceOverlapsFatTable { .. })
        ));

        let mut slice_overlap = Vec::new();
        slice_overlap.extend_from_slice(&fat_magic(Endianness::Big, false));
        push_u32(&mut slice_overlap, Endianness::Big, 2);
        for offset in [256_u32, 272_u32] {
            push_u32(&mut slice_overlap, Endianness::Big, CPU_TYPE_ARM64);
            push_u32(&mut slice_overlap, Endianness::Big, 0);
            push_u32(&mut slice_overlap, Endianness::Big, offset);
            push_u32(&mut slice_overlap, Endianness::Big, 32);
            push_u32(&mut slice_overlap, Endianness::Big, 0);
        }
        slice_overlap.resize(304, 0);
        assert!(matches!(
            parse(slice_overlap),
            Err(MachOParseError::OverlappingSlices {
                first_slice: 0,
                second_slice: 1,
            })
        ));

        let mut nested = Vec::new();
        nested.extend_from_slice(&fat_magic(Endianness::Big, false));
        push_u32(&mut nested, Endianness::Big, 0);
        let nested_fat = fat(Endianness::Big, false, &nested, CPU_TYPE_ARM64, 0);
        assert!(matches!(
            parse(nested_fat),
            Err(MachOParseError::NestedFatContainer { slice_index: 0 })
        ));
    }

    #[test]
    fn fat64_reserved_field_is_ignored_for_forward_compatibility() {
        let slice = thin(Endianness::Little, true, CPU_TYPE_ARM64, 0, &[]);
        let mut bytes = fat(Endianness::Big, true, &slice, CPU_TYPE_ARM64, 0);
        bytes[36..40].copy_from_slice(&0xdead_beef_u32.to_be_bytes());

        let report = parse(bytes).expect("reserved FAT64 data is not parser input");
        assert_eq!(report.container, MachOContainer::Fat64);
        assert_eq!(report.slices.len(), 1);
    }
}
