use spin::Once;
use x86_64::{
    instructions::{segmentation::Segment, tables::load_tss},
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

#[derive(Clone, Copy)]
struct Selectors {
    code_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

pub fn init() {
    let tss = TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();
        static mut STACK: [u8; 4096] = [0; 4096];
        let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(STACK));
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = stack_start + 4096;
        tss
    });
    let (gdt, selectors) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(tss));
        (
            gdt,
            Selectors {
                code_selector,
                tss_selector,
            },
        )
    });
    gdt.load();
    unsafe {
        x86_64::instructions::segmentation::CS::set_reg(selectors.code_selector);
        load_tss(selectors.tss_selector);
    }
}
