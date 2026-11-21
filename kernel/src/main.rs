#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let message = b"AQ OS kernel: memory-safe Rust bootstrap\n";
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
