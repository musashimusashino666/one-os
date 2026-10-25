//! Bounded parser for ELF64 load-segment metadata used by the x86_64 boot path.
//!
//! This module does not map memory or dereference file offsets. The caller must
//! supply bytes it has already made safe to read and validate live mappings.

use crate::PAGE_SIZE;

pub const ELF64_HEADER_SIZE: usize = 64;
pub const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
pub const MAX_ELF64_PROGRAM_HEADERS: usize = 64;
/// Maximum aggregate PT_LOAD memory size accepted by this bootstrap inspector.
pub const MAX_ELF64_TOTAL_LOAD_BYTES: u64 = 256 * 1024 * 1024;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u32 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Metadata for one validated ELF64 PT_LOAD header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Elf64LoadSegment {
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
    pub alignment: u64,
}

impl Elf64LoadSegment {
    const EMPTY: Self = Self {
        offset: 0,
        virtual_address: 0,
        file_size: 0,
        memory_size: 0,
        flags: 0,
        alignment: 0,
    };

    pub const fn writable(self) -> bool {
        self.flags & PF_W != 0
    }

    pub const fn executable(self) -> bool {
        self.flags & PF_X != 0
    }

    pub const fn readable(self) -> bool {
        self.flags & PF_R != 0
    }
}

/// Bounded, allocation-free metadata for an ELF64 x86_64 image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Elf64LoadImage {
    entry_point: u64,
    segments: [Elf64LoadSegment; MAX_ELF64_PROGRAM_HEADERS],
    segment_count: usize,
}

impl Elf64LoadImage {
    pub const fn entry_point(&self) -> u64 {
        self.entry_point
    }

    pub fn load_segments(&self) -> &[Elf64LoadSegment] {
        &self.segments[..self.segment_count]
    }
}

/// A malformed or unsupported ELF header or PT_LOAD table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Elf64Error {
    TruncatedHeader,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedEndianness,
    UnsupportedVersion,
    UnsupportedType,
    UnsupportedMachine,
    InvalidHeaderSize,
    InvalidProgramHeaderSize,
    NoProgramHeaders,
    TooManyProgramHeaders,
    ProgramHeaderRangeOverflow,
    ProgramHeadersOverlapHeader,
    ProgramHeadersOutsideFile,
    TruncatedProgramHeaders,
    ProgramHeaderTableSizeMismatch,
    NoLoadSegments,
    LoadImageTooLarge,
    InvalidLoadSegment,
    FileRangeOverflow,
    FileRangeOutsideImage,
    VirtualRangeOverflow,
    InvalidAlignment,
    IncompatiblePageOffsets,
    OverlappingLoadSegments,
    EntryPointNotExecutable,
}

#[derive(Clone, Copy, Debug)]
struct ParsedHeader {
    entry_point: u64,
    program_header_offset: u64,
    program_header_count: usize,
    program_header_table_size: usize,
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?))
}

fn parse_header(header: &[u8], file_len: u64) -> Result<ParsedHeader, Elf64Error> {
    if header.len() < ELF64_HEADER_SIZE || file_len < ELF64_HEADER_SIZE as u64 {
        return Err(Elf64Error::TruncatedHeader);
    }
    if &header[0..4] != b"\x7fELF" {
        return Err(Elf64Error::InvalidMagic);
    }
    if header[4] != ELFCLASS64 {
        return Err(Elf64Error::UnsupportedClass);
    }
    if header[5] != ELFDATA2LSB {
        return Err(Elf64Error::UnsupportedEndianness);
    }
    if header[6] != EV_CURRENT as u8 || read_u32(header, 20) != Some(EV_CURRENT) {
        return Err(Elf64Error::UnsupportedVersion);
    }
    match read_u16(header, 16) {
        Some(ET_EXEC | ET_DYN) => {}
        _ => return Err(Elf64Error::UnsupportedType),
    }
    if read_u16(header, 18) != Some(EM_X86_64) {
        return Err(Elf64Error::UnsupportedMachine);
    }
    if read_u16(header, 52) != Some(ELF64_HEADER_SIZE as u16) {
        return Err(Elf64Error::InvalidHeaderSize);
    }
    if read_u16(header, 54) != Some(ELF64_PROGRAM_HEADER_SIZE as u16) {
        return Err(Elf64Error::InvalidProgramHeaderSize);
    }

    let program_header_count =
        usize::from(read_u16(header, 56).ok_or(Elf64Error::TruncatedHeader)?);
    if program_header_count == 0 {
        return Err(Elf64Error::NoProgramHeaders);
    }
    if program_header_count > MAX_ELF64_PROGRAM_HEADERS {
        return Err(Elf64Error::TooManyProgramHeaders);
    }

    let program_header_offset = read_u64(header, 32).ok_or(Elf64Error::TruncatedHeader)?;
    if program_header_offset < ELF64_HEADER_SIZE as u64 {
        return Err(Elf64Error::ProgramHeadersOverlapHeader);
    }
    let program_header_table_size = program_header_count
        .checked_mul(ELF64_PROGRAM_HEADER_SIZE)
        .ok_or(Elf64Error::ProgramHeaderRangeOverflow)?;
    let table_end = program_header_offset
        .checked_add(program_header_table_size as u64)
        .ok_or(Elf64Error::ProgramHeaderRangeOverflow)?;
    if table_end > file_len {
        return Err(Elf64Error::ProgramHeadersOutsideFile);
    }

    Ok(ParsedHeader {
        entry_point: read_u64(header, 24).ok_or(Elf64Error::TruncatedHeader)?,
        program_header_offset,
        program_header_count,
        program_header_table_size,
    })
}

/// Returns the offset and exact byte length of the ELF program-header table.
pub fn elf64_program_header_table_range(
    header: &[u8],
    file_len: u64,
) -> Result<(u64, usize), Elf64Error> {
    let parsed = parse_header(header, file_len)?;
    Ok((parsed.program_header_offset, parsed.program_header_table_size))
}

/// Parses every PT_LOAD header without allocating. The caller must separately
/// validate the runtime load bias and the observed page-table translations.
pub fn parse_elf64_load_segments(
    header: &[u8],
    program_headers: &[u8],
    file_len: u64,
) -> Result<Elf64LoadImage, Elf64Error> {
    let parsed = parse_header(header, file_len)?;
    if program_headers.len() < parsed.program_header_table_size {
        return Err(Elf64Error::TruncatedProgramHeaders);
    }
    if program_headers.len() != parsed.program_header_table_size {
        return Err(Elf64Error::ProgramHeaderTableSizeMismatch);
    }

    let mut image = Elf64LoadImage {
        entry_point: parsed.entry_point,
        segments: [Elf64LoadSegment::EMPTY; MAX_ELF64_PROGRAM_HEADERS],
        segment_count: 0,
    };
    let mut total_memory_size = 0u64;

    for index in 0..parsed.program_header_count {
        let offset = index * ELF64_PROGRAM_HEADER_SIZE;
        if read_u32(program_headers, offset) != Some(PT_LOAD) {
            continue;
        }

        let flags = read_u32(program_headers, offset + 4)
            .ok_or(Elf64Error::TruncatedProgramHeaders)?;
        let segment = Elf64LoadSegment {
            offset: read_u64(program_headers, offset + 8)
                .ok_or(Elf64Error::TruncatedProgramHeaders)?,
            virtual_address: read_u64(program_headers, offset + 16)
                .ok_or(Elf64Error::TruncatedProgramHeaders)?,
            file_size: read_u64(program_headers, offset + 32)
                .ok_or(Elf64Error::TruncatedProgramHeaders)?,
            memory_size: read_u64(program_headers, offset + 40)
                .ok_or(Elf64Error::TruncatedProgramHeaders)?,
            flags,
            alignment: read_u64(program_headers, offset + 48)
                .ok_or(Elf64Error::TruncatedProgramHeaders)?,
        };

        if segment.flags & !(PF_R | PF_W | PF_X) != 0
            || (segment.writable() && segment.executable())
            || segment.memory_size == 0
            || segment.file_size > segment.memory_size
        {
            return Err(Elf64Error::InvalidLoadSegment);
        }

        let file_end = segment
            .offset
            .checked_add(segment.file_size)
            .ok_or(Elf64Error::FileRangeOverflow)?;
        if file_end > file_len {
            return Err(Elf64Error::FileRangeOutsideImage);
        }
        let virtual_end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or(Elf64Error::VirtualRangeOverflow)?;
        if virtual_end <= segment.virtual_address {
            return Err(Elf64Error::VirtualRangeOverflow);
        }

        if segment.alignment > 1
            && (!segment.alignment.is_power_of_two()
                || segment.offset & (segment.alignment - 1)
                    != segment.virtual_address & (segment.alignment - 1))
        {
            return Err(Elf64Error::InvalidAlignment);
        }
        if segment.offset & (PAGE_SIZE - 1)
            != segment.virtual_address & (PAGE_SIZE - 1)
        {
            return Err(Elf64Error::IncompatiblePageOffsets);
        }

        total_memory_size = total_memory_size
            .checked_add(segment.memory_size)
            .ok_or(Elf64Error::LoadImageTooLarge)?;
        if total_memory_size > MAX_ELF64_TOTAL_LOAD_BYTES {
            return Err(Elf64Error::LoadImageTooLarge);
        }

        for previous in image.load_segments() {
            let previous_end = previous
                .virtual_address
                .checked_add(previous.memory_size)
                .ok_or(Elf64Error::VirtualRangeOverflow)?;
            if segment.virtual_address < previous_end
                && previous.virtual_address < virtual_end
            {
                return Err(Elf64Error::OverlappingLoadSegments);
            }
        }

        image.segments[image.segment_count] = segment;
        image.segment_count += 1;
    }

    if image.segment_count == 0 {
        return Err(Elf64Error::NoLoadSegments);
    }
    if !image.load_segments().iter().any(|segment| {
        segment.executable()
            && image.entry_point >= segment.virtual_address
            && image.entry_point
                < segment
                    .virtual_address
                    .saturating_add(segment.memory_size)
    }) {
        return Err(Elf64Error::EntryPointNotExecutable);
    }

    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::{
        elf64_program_header_table_range, parse_elf64_load_segments, Elf64Error,
        ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE,
    };

    const FILE_LEN: u64 = 0x4000;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn header(program_header_count: u16, entry: u64) -> [u8; ELF64_HEADER_SIZE] {
        let mut bytes = [0u8; ELF64_HEADER_SIZE];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        write_u16(&mut bytes, 16, 3);
        write_u16(&mut bytes, 18, 62);
        write_u32(&mut bytes, 20, 1);
        write_u64(&mut bytes, 24, entry);
        write_u64(&mut bytes, 32, ELF64_HEADER_SIZE as u64);
        write_u16(&mut bytes, 52, ELF64_HEADER_SIZE as u16);
        write_u16(&mut bytes, 54, ELF64_PROGRAM_HEADER_SIZE as u16);
        write_u16(&mut bytes, 56, program_header_count);
        bytes
    }

    fn program_header(
        bytes: &mut [u8],
        index: usize,
        flags: u32,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
    ) {
        let base = index * ELF64_PROGRAM_HEADER_SIZE;
        write_u32(bytes, base, 1);
        write_u32(bytes, base + 4, flags);
        write_u64(bytes, base + 8, offset);
        write_u64(bytes, base + 16, virtual_address);
        write_u64(bytes, base + 24, 0);
        write_u64(bytes, base + 32, file_size);
        write_u64(bytes, base + 40, memory_size);
        write_u64(bytes, base + 48, 0x1000);
    }

    fn valid_image() -> ([u8; ELF64_HEADER_SIZE], [u8; ELF64_PROGRAM_HEADER_SIZE * 2]) {
        let hdr = header(2, 0x1000);
        let mut phdrs = [0u8; ELF64_PROGRAM_HEADER_SIZE * 2];
        program_header(&mut phdrs, 0, 0x5, 0x1000, 0x1000, 0x800, 0x800);
        program_header(&mut phdrs, 1, 0x6, 0x2000, 0x2000, 0x400, 0x1800);
        (hdr, phdrs)
    }

    #[test]
    fn parses_separate_executable_and_writable_load_segments() {
        let (header, program_headers) = valid_image();
        assert_eq!(
            elf64_program_header_table_range(&header, FILE_LEN),
            Ok((ELF64_HEADER_SIZE as u64, ELF64_PROGRAM_HEADER_SIZE * 2))
        );
        let image = parse_elf64_load_segments(&header, &program_headers, FILE_LEN).unwrap();
        assert_eq!(image.entry_point(), 0x1000);
        assert_eq!(image.load_segments().len(), 2);
        assert!(image.load_segments()[0].executable());
        assert!(!image.load_segments()[0].writable());
        assert!(image.load_segments()[1].writable());
        assert!(!image.load_segments()[1].executable());
    }

    #[test]
    fn rejects_truncated_header_and_bad_magic() {
        assert_eq!(
            parse_elf64_load_segments(&[0; 10], &[], FILE_LEN),
            Err(Elf64Error::TruncatedHeader)
        );
        let (mut header, program_headers) = valid_image();
        header[0] = 0;
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::InvalidMagic)
        );
    }

    #[test]
    fn rejects_program_header_table_overlapping_elf_header() {
        let mut header = header(2, 0x1000);
        write_u64(&mut header, 32, 0);
        assert_eq!(
            elf64_program_header_table_range(&header, FILE_LEN),
            Err(Elf64Error::ProgramHeadersOverlapHeader)
        );
    }

    #[test]
    fn rejects_program_header_table_outside_the_elf_file() {
        let mut header = header(2, 0x1000);
        write_u64(&mut header, 32, FILE_LEN - 8);
        assert_eq!(
            elf64_program_header_table_range(&header, FILE_LEN),
            Err(Elf64Error::ProgramHeadersOutsideFile)
        );
    }

    #[test]
    fn rejects_truncated_or_extra_program_header_bytes() {
        let (header, program_headers) = valid_image();
        assert_eq!(
            parse_elf64_load_segments(
                &header,
                &program_headers[..program_headers.len() - 1],
                FILE_LEN
            ),
            Err(Elf64Error::TruncatedProgramHeaders)
        );
        let mut extra = program_headers.to_vec();
        extra.push(0);
        assert_eq!(
            parse_elf64_load_segments(&header, &extra, FILE_LEN),
            Err(Elf64Error::ProgramHeaderTableSizeMismatch)
        );
    }

    #[test]
    fn rejects_writable_executable_load_segment() {
        let (header, mut program_headers) = valid_image();
        program_header(&mut program_headers, 0, 0x7, 0x1000, 0x1000, 0x800, 0x800);
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::InvalidLoadSegment)
        );
    }

    #[test]
    fn rejects_file_size_larger_than_memory_size_and_file_overflow() {
        let (header, mut program_headers) = valid_image();
        program_header(&mut program_headers, 0, 0x5, 0x1000, 0x1000, 0x900, 0x800);
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::InvalidLoadSegment)
        );
        program_header(
            &mut program_headers,
            0,
            0x5,
            u64::MAX - 0x10,
            0x1000,
            0x40,
            0x40,
        );
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::FileRangeOverflow)
        );
    }

    #[test]
    fn rejects_incompatible_page_offsets_and_bad_alignment() {
        let (header, mut program_headers) = valid_image();
        program_header(&mut program_headers, 0, 0x5, 0x1001, 0x1000, 0x800, 0x800);
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::IncompatiblePageOffsets)
        );
        program_header(&mut program_headers, 0, 0x5, 0x1000, 0x1000, 0x800, 0x800);
        write_u64(&mut program_headers, 48, 0x1800);
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::InvalidAlignment)
        );
    }

    #[test]
    fn rejects_overlapping_segments_and_non_executable_entry() {
        let (header, mut program_headers) = valid_image();
        program_header(&mut program_headers, 1, 0x6, 0x17ff, 0x17ff, 0x400, 0x800);
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::OverlappingLoadSegments)
        );
        let (mut header, program_headers) = valid_image();
        write_u64(&mut header, 24, 0x2800);
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::EntryPointNotExecutable)
        );
    }

    #[test]
    fn rejects_pt_load_memory_size_over_bootstrap_limit() {
        let (header, mut program_headers) = valid_image();
        program_header(
            &mut program_headers,
            0,
            0x5,
            0x1000,
            0x1000,
            0x800,
            super::MAX_ELF64_TOTAL_LOAD_BYTES + 1,
        );
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::LoadImageTooLarge)
        );
    }

    #[test]
    fn rejects_large_program_header_counts() {
        let header = header(65, 0x1000);
        assert_eq!(
            elf64_program_header_table_range(&header, FILE_LEN),
            Err(Elf64Error::TooManyProgramHeaders)
        );
    }

    #[test]
    fn rejects_missing_load_segments() {
        let (header, mut program_headers) = valid_image();
        write_u32(&mut program_headers, 0, 4);
        write_u32(&mut program_headers, ELF64_PROGRAM_HEADER_SIZE, 4);
        assert_eq!(
            parse_elf64_load_segments(&header, &program_headers, FILE_LEN),
            Err(Elf64Error::NoLoadSegments)
        );
    }
}
