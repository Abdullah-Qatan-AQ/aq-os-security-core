#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo};
use core::{arch::asm, panic::PanicInfo};

entry_point!(kernel_main);

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

fn serial_print(message: &[u8]) {
    for &byte in message {
        serial_write(byte);
    }
}

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    serial_print(b"AQ OS kernel: Rust bare-metal boot OK\r\n");
    let message = b"AQ OS kernel: Rust bare-metal boot OK";
    let vga = 0xb8000 as *mut u8;
    let mut i = 0;
    while i < message.len() {
        unsafe {
            vga.add(i * 2).write_volatile(message[i]);
            vga.add(i * 2 + 1).write_volatile(0x0f);
        }
        i += 1;
    }
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
