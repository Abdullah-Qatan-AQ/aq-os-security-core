use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use pic8259::ChainedPics;
use spin::{Mutex, Once};
use x86_64::{
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
    PrivilegeLevel,
};

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
static USER_BREAKPOINT_HIT: AtomicU8 = AtomicU8::new(0);
static TIMER_REPORTED: AtomicU8 = AtomicU8::new(0);

pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint
            .set_handler_fn(breakpoint_handler)
            .set_privilege_level(PrivilegeLevel::Ring3);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        idt.stack_segment_fault
            .set_handler_fn(stack_segment_fault_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
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
    if stack_frame.code_segment.rpl() == PrivilegeLevel::Ring3 {
        USER_BREAKPOINT_HIT.store(1, Ordering::Release);
        crate::serial_print(b"AQ OS kernel: ring3 breakpoint trap OK\r\n");
    } else {
        crate::serial_print(b"AQ OS: breakpoint exception\r\n");
        crate::serial_print_hex(stack_frame.instruction_pointer.as_u64());
    }
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

extern "x86-interrupt" fn general_protection_fault_handler(
    _stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    crate::serial_print(b"AQ OS: GENERAL PROTECTION\r\n");
    crate::serial_print_hex(error_code);
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_tss_handler(_stack_frame: InterruptStackFrame, error_code: u64) {
    crate::serial_print(b"AQ OS: INVALID TSS\r\n");
    crate::serial_print_hex(error_code);
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    _stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    crate::serial_print(b"AQ OS: STACK SEGMENT FAULT\r\n");
    crate::serial_print_hex(error_code);
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_opcode_handler(_stack_frame: InterruptStackFrame) {
    crate::serial_print(b"AQ OS: INVALID OPCODE\r\n");
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
    let tick = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if tick == 1 && TIMER_REPORTED.swap(1, Ordering::AcqRel) == 0 {
        crate::serial_print(b"AQ OS kernel: interrupts and timer OK\r\n");
    }
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
