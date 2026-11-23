use crate::memory::BootInfoFrameAllocator;
use x86_64::{
    structures::paging::{
        mapper::MapToError, page_table::PageTableFlags, FrameAllocator, Mapper, OffsetPageTable,
        Page, PageSize, PageTable, PhysFrame, Size4KiB,
    },
    VirtAddr,
};

/// Lowest address used by user programs. The first pages remain unmapped to
/// turn null-pointer dereferences into page faults.
pub const USER_IMAGE_BASE: u64 = 0x0000_0000_0040_0000;
/// Highest canonical address accepted by the syscall ABI.
pub const USER_ADDRESS_MAX: u64 = 0x0000_7fff_ffff_ffff;

pub const USER_PAGE_FLAGS: PageTableFlags = PageTableFlags::PRESENT
    .union(PageTableFlags::WRITABLE)
    .union(PageTableFlags::USER_ACCESSIBLE);

#[allow(dead_code)]
#[derive(Debug)]
pub enum UserMapError {
    InvalidAddress,
    Mapping(MapToError<Size4KiB>),
}

pub fn is_user_address(address: u64) -> bool {
    (USER_IMAGE_BASE..=USER_ADDRESS_MAX).contains(&address)
}

/// Allocate and clear a fresh level-4 page table. It contains no kernel
/// mappings; kernel mappings will be copied deliberately in a later phase.
pub unsafe fn create_root(
    physical_memory_offset: u64,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Option<PhysFrame> {
    let frame = frame_allocator.allocate_frame()?;
    let virtual_address = VirtAddr::new(physical_memory_offset + frame.start_address().as_u64());
    core::ptr::write_bytes(
        virtual_address.as_mut_ptr::<u8>(),
        0,
        Size4KiB::SIZE as usize,
    );
    Some(frame)
}

/// Build an OffsetPageTable view over an independently allocated root table.
/// The returned mapper must not outlive the physical frame retained by the
/// owning address-space object.
pub unsafe fn mapper_for_root(
    root: PhysFrame,
    physical_memory_offset: u64,
) -> OffsetPageTable<'static> {
    let virtual_address = VirtAddr::new(physical_memory_offset + root.start_address().as_u64());
    OffsetPageTable::new(
        &mut *virtual_address.as_mut_ptr::<PageTable>(),
        VirtAddr::new(physical_memory_offset),
    )
}

/// Map one user page with user permission bits and no global/kernel flag.
pub unsafe fn map_user_page<A: FrameAllocator<Size4KiB>>(
    mapper: &mut OffsetPageTable<'static>,
    page: Page<Size4KiB>,
    frame: PhysFrame,
    frame_allocator: &mut A,
) -> Result<(), UserMapError> {
    if !is_user_address(page.start_address().as_u64()) {
        return Err(UserMapError::InvalidAddress);
    }
    mapper
        .map_to(page, frame, USER_PAGE_FLAGS, frame_allocator)
        .map(|flush| flush.flush())
        .map_err(UserMapError::Mapping)
}

pub fn same_virtual_page_is_isolated(
    first: &OffsetPageTable<'static>,
    second: &OffsetPageTable<'static>,
    page: Page<Size4KiB>,
) -> bool {
    match (first.translate_page(page), second.translate_page(page)) {
        (Ok(first_frame), Ok(second_frame)) => first_frame != second_frame,
        _ => false,
    }
}
