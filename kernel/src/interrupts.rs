use core::sync::atomic::{AtomicU64, Ordering};

use pic8259::ChainedPics;
use spin::{Mutex, Once};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

static IDT: Once<InterruptDescriptorTable> = Once::new();
static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });
static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt[InterruptIndex::Timer as u8].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard as u8].set_handler_fn(keyboard_interrupt_handler);
        idt
    });
    idt.load();
}

pub unsafe fn init_pics() {
    PICS.lock().initialize();
    PICS.lock().write_masks(0, 0);
}

pub fn enable() {
    x86_64::instructions::interrupts::enable();
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::serial_print(b"AQ OS: breakpoint exception\r\n");
    crate::serial_print_hex(stack_frame.instruction_pointer.as_u64());
}

extern "x86-interrupt" fn double_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    crate::serial_print(b"AQ OS: DOUBLE FAULT\r\n");
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn page_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: PageFaultErrorCode,
) {
    crate::serial_print(b"AQ OS: PAGE FAULT\r\n");
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    TICKS.fetch_add(1, Ordering::Relaxed);
    crate::scheduler::on_timer_tick();
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer as u8)
    };
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard as u8)
    };
}
