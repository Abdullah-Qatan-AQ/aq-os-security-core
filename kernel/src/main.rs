#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod heap;
mod interrupts;
mod memory;
mod scheduler;

use alloc::boxed::Box;
use bootloader_api::{config::Mapping, entry_point, BootInfo, BootloaderConfig};
use core::{arch::asm, panic::PanicInfo};

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn serial_write(byte: u8) {
    unsafe {
        while (inb(0x3f8 + 5) & 0x20) == 0 {}
        outb(0x3f8, byte);
    }
}

unsafe fn outb(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    value
}

pub fn serial_print(message: &[u8]) {
    for &byte in message {
        serial_write(byte);
    }
}

pub fn serial_print_hex(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    serial_print(b"0x");
    let mut shift = 60;
    loop {
        serial_write(HEX[((value >> shift) & 0xf) as usize]);
        if shift == 0 {
            break;
        }
        shift -= 4;
    }
    serial_print(b"\r\n");
}

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    let physical_memory_offset = match boot_info.physical_memory_offset.into_option() {
        Some(offset) => offset,
        None => panic!("physical memory mapping missing"),
    };

    let mut mapper = unsafe { memory::init_mapper(physical_memory_offset) };
    let memory_regions = unsafe { core::ptr::read(&boot_info.memory_regions) };
    let mut frame_allocator = unsafe { memory::BootInfoFrameAllocator::init(memory_regions) };
    heap::init_heap(&mut mapper, &mut frame_allocator).expect("heap initialization failed");

    let allocation = Box::new(0xA005_u64);
    assert_eq!(*allocation, 0xA005_u64);
    serial_print(b"AQ OS kernel: memory manager OK\r\n");
    scheduler::register(0);
    scheduler::register(1);

    interrupts::init_idt();
    serial_print(b"AQ OS: IDT OK\r\n");
    unsafe { interrupts::init_pics() };
    serial_print(b"AQ OS: PIC OK\r\n");
    interrupts::enable();
    serial_print(b"AQ OS: interrupts enabled\r\n");
    while interrupts::ticks() < 10 {
        x86_64::instructions::hlt();
    }
    serial_print(b"AQ OS kernel: interrupts and timer OK\r\n");
    serial_print(b"AQ OS scheduler current task: ");
    serial_print_hex(scheduler::current() as u64);

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_print(b"AQ OS kernel: PANIC\r\n");
    loop {
        core::hint::spin_loop();
    }
}
