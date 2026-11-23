use spin::Once;
use x86_64::{
    instructions::tables::load_tss,
    registers::segmentation::SegmentSelector,
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable},
        tss::TaskStateSegment,
    },
    PrivilegeLevel, VirtAddr,
};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

#[derive(Clone, Copy)]
pub struct Selectors {
    pub user_code: SegmentSelector,
    pub user_data: SegmentSelector,
    pub tss: SegmentSelector,
}

pub fn init() -> Selectors {
    let tss = TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();
        static mut DOUBLE_FAULT_STACK: [u8; 4096] = [0; 4096];
        static mut USER_KERNEL_STACK: [u8; 8192] = [0; 8192];
        let double_fault_start = VirtAddr::from_ptr(core::ptr::addr_of!(DOUBLE_FAULT_STACK));
        let user_kernel_start = VirtAddr::from_ptr(core::ptr::addr_of!(USER_KERNEL_STACK));
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = double_fault_start + 4096;
        tss.privilege_stack_table[0] = user_kernel_start + 8192;
        tss
    });
    GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let _kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(tss));
        (
            gdt,
            Selectors {
                user_code: SegmentSelector::new(user_code.index(), PrivilegeLevel::Ring3),
                user_data: SegmentSelector::new(user_data.index(), PrivilegeLevel::Ring3),
                tss: tss_selector,
            },
        )
    });
    let (gdt, selectors) = GDT.get().expect("GDT initialized");
    gdt.load();
    unsafe {
        load_tss(selectors.tss);
    }
    *selectors
}
