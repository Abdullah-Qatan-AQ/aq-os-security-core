use crate::{address_space, memory::BootInfoFrameAllocator};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, Size4KiB,
};
use x86_64::VirtAddr;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;
const PF_X: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedMachine,
    BadVersion,
    BadProgramHeader,
    OutOfBounds,
    InvalidSegment,
    InvalidEntry,
    AddressOverflow,
    MappingFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedImage {
    pub entry: u64,
    pub load_segments: usize,
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ElfError> {
    let bytes = data.get(offset..offset + 2).ok_or(ElfError::OutOfBounds)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ElfError> {
    let bytes = data.get(offset..offset + 4).ok_or(ElfError::OutOfBounds)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ElfError> {
    let bytes = data.get(offset..offset + 8).ok_or(ElfError::OutOfBounds)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn checked_end(start: u64, length: u64) -> Result<u64, ElfError> {
    start.checked_add(length).ok_or(ElfError::AddressOverflow)
}

pub unsafe fn load(
    image: &[u8],
    mapper: &mut OffsetPageTable<'static>,
    frame_allocator: &mut BootInfoFrameAllocator,
    physical_memory_offset: u64,
) -> Result<LoadedImage, ElfError> {
    if image.len() < ELF_HEADER_SIZE {
        return Err(ElfError::TooSmall);
    }
    if &image[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    if image[4] != 2 {
        return Err(ElfError::UnsupportedClass);
    }
    if image[5] != 1 {
        return Err(ElfError::UnsupportedEndian);
    }
    if read_u16(image, 16)? != 2 {
        return Err(ElfError::UnsupportedMachine);
    }
    if read_u32(image, 20)? != 1 {
        return Err(ElfError::BadVersion);
    }

    let entry = read_u64(image, 24)?;
    let phoff = usize::try_from(read_u64(image, 32)?).map_err(|_| ElfError::OutOfBounds)?;
    let phentsize = read_u16(image, 54)? as usize;
    let phnum = read_u16(image, 56)? as usize;
    if phentsize != PROGRAM_HEADER_SIZE || phnum == 0 || phnum > 64 {
        return Err(ElfError::BadProgramHeader);
    }
    let ph_end = phoff
        .checked_add(phentsize.checked_mul(phnum).ok_or(ElfError::OutOfBounds)?)
        .ok_or(ElfError::OutOfBounds)?;
    if ph_end > image.len() {
        return Err(ElfError::OutOfBounds);
    }

    let mut loaded = 0;
    let mut entry_is_executable = false;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        let kind = read_u32(image, offset)?;
        if kind != PT_LOAD {
            continue;
        }
        let flags = read_u32(image, offset + 4)?;
        let file_offset =
            usize::try_from(read_u64(image, offset + 8)?).map_err(|_| ElfError::OutOfBounds)?;
        let virtual_address = read_u64(image, offset + 16)?;
        let file_size = read_u64(image, offset + 32)?;
        let memory_size = read_u64(image, offset + 40)?;
        let alignment = read_u64(image, offset + 48)?;
        if memory_size == 0 || file_size > memory_size || alignment == 0 {
            return Err(ElfError::InvalidSegment);
        }
        if file_offset
            .checked_add(file_size as usize)
            .ok_or(ElfError::OutOfBounds)?
            > image.len()
        {
            return Err(ElfError::OutOfBounds);
        }
        if virtual_address % Size4KiB::SIZE != (file_offset as u64) % Size4KiB::SIZE {
            return Err(ElfError::InvalidSegment);
        }
        let segment_end = checked_end(virtual_address, memory_size)?;
        if !address_space::is_user_address(virtual_address)
            || segment_end == 0
            || segment_end - 1 > address_space::USER_ADDRESS_MAX
        {
            return Err(ElfError::InvalidSegment);
        }
        if entry >= virtual_address && entry < segment_end && flags & PF_X != 0 {
            entry_is_executable = true;
        }

        let first_page = virtual_address & !(Size4KiB::SIZE - 1);
        let last_page = (segment_end - 1) & !(Size4KiB::SIZE - 1);
        let mut page_address = first_page;
        let page_flags = if flags & PF_W != 0 {
            address_space::USER_PAGE_FLAGS
        } else {
            address_space::USER_PAGE_FLAGS & !x86_64::structures::paging::PageTableFlags::WRITABLE
        };
        loop {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(page_address));
            let frame = frame_allocator
                .allocate_frame()
                .ok_or(ElfError::MappingFailed)?;
            mapper
                .map_to(page, frame, page_flags, frame_allocator)
                .map_err(|_| ElfError::MappingFailed)?
                .flush();
            let page_ptr = (physical_memory_offset + frame.start_address().as_u64()) as *mut u8;
            core::ptr::write_bytes(page_ptr, 0, Size4KiB::SIZE as usize);

            let copy_start = core::cmp::max(virtual_address, page_address);
            let copy_end = core::cmp::min(segment_end, page_address + Size4KiB::SIZE);
            let file_end = virtual_address + file_size;
            let file_copy_end = core::cmp::min(copy_end, file_end);
            if copy_start < file_copy_end {
                let source_offset = file_offset + (copy_start - virtual_address) as usize;
                let copy_len = (file_copy_end - copy_start) as usize;
                let source = image.as_ptr().add(source_offset);
                core::ptr::copy_nonoverlapping(
                    source,
                    page_ptr.add((copy_start - page_address) as usize),
                    copy_len,
                );
            }
            if page_address == last_page {
                break;
            }
            page_address += Size4KiB::SIZE;
        }
        loaded += 1;
    }
    if loaded == 0 || !entry_is_executable {
        return Err(ElfError::InvalidEntry);
    }
    Ok(LoadedImage {
        entry,
        load_segments: loaded,
    })
}
