use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

pub struct BootInfoFrameAllocator {
    regions: &'static mut [bootloader_api::info::MemoryRegion],
    next_frame: u64,
}

impl BootInfoFrameAllocator {
    pub unsafe fn init(memory_regions: MemoryRegions) -> Self {
        Self {
            regions: memory_regions.into(),
            next_frame: 0,
        }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        self.regions
            .iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
            .flat_map(|r| (r.start..r.end).step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next_frame as usize);
        if frame.is_some() {
            self.next_frame += 1;
        }
        frame
    }
}

pub unsafe fn active_level_4_table(
    physical_memory_offset: u64,
) -> &'static mut x86_64::structures::paging::PageTable {
    use x86_64::registers::control::Cr3;
    let (level_4_frame, _) = Cr3::read();
    let phys = level_4_frame.start_address().as_u64();
    let virt = x86_64::VirtAddr::new(physical_memory_offset + phys);
    &mut *virt.as_mut_ptr()
}

pub unsafe fn init_mapper(
    physical_memory_offset: u64,
) -> x86_64::structures::paging::OffsetPageTable<'static> {
    let level_4_table = active_level_4_table(physical_memory_offset);
    x86_64::structures::paging::OffsetPageTable::new(
        level_4_table,
        x86_64::VirtAddr::new(physical_memory_offset),
    )
}
