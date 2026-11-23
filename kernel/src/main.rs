#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod address_space;
mod gdt;
mod heap;
mod interrupts;
mod memory;
mod scheduler;

use alloc::boxed::Box;
use aqos_syscall::{dispatch, Args, Capabilities, Error, Number, TaskContext};
use bootloader_api::{config::Mapping, entry_point, BootInfo, BootloaderConfig};
use core::{arch::asm, panic::PanicInfo};
use x86_64::{
    registers::control::Cr3,
    registers::rflags::RFlags,
    registers::segmentation::SegmentSelector,
    structures::{
        idt::InterruptStackFrame,
        paging::{FrameAllocator, Page, PageSize, Size4KiB},
    },
    VirtAddr,
};

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

const USER_STACK_BASE: u64 = 0x0000_0000_0080_0000;

unsafe fn enter_user_mode(
    space: address_space::AddressSpace,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
) -> ! {
    space.activate();
    let frame = InterruptStackFrame::new(
        VirtAddr::new(address_space::USER_IMAGE_BASE),
        user_code,
        RFlags::from_bits_retain(0x202),
        VirtAddr::new(USER_STACK_BASE + Size4KiB::SIZE),
        user_data,
    );
    frame.iretq()
}

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
    let selectors = gdt::init();
    serial_print(b"AQ OS kernel: GDT and TSS OK\r\n");

    let space_a = unsafe {
        address_space::create_root_with_kernel_mappings(
            physical_memory_offset,
            &mut frame_allocator,
        )
    }
    .expect("user address-space root allocation failed");
    let space_b = unsafe {
        address_space::create_root_with_kernel_mappings(
            physical_memory_offset,
            &mut frame_allocator,
        )
    }
    .expect("second user address-space root allocation failed");
    let user_page =
        Page::<Size4KiB>::containing_address(VirtAddr::new(address_space::USER_IMAGE_BASE));
    let user_frame_a = frame_allocator
        .allocate_frame()
        .expect("user page frame allocation failed");
    let user_frame_b = frame_allocator
        .allocate_frame()
        .expect("second user page frame allocation failed");
    let user_stack_frame = frame_allocator
        .allocate_frame()
        .expect("user stack frame allocation failed");
    let mut mapper_a =
        unsafe { address_space::mapper_for_root(space_a.root_frame(), physical_memory_offset) };
    let mut mapper_b =
        unsafe { address_space::mapper_for_root(space_b.root_frame(), physical_memory_offset) };
    unsafe {
        address_space::map_user_page(&mut mapper_a, user_page, user_frame_a, &mut frame_allocator)
            .expect("user page mapping A failed");
        address_space::map_user_page(&mut mapper_b, user_page, user_frame_b, &mut frame_allocator)
            .expect("user page mapping B failed");
        address_space::map_user_page(
            &mut mapper_a,
            Page::<Size4KiB>::containing_address(VirtAddr::new(USER_STACK_BASE)),
            user_stack_frame,
            &mut frame_allocator,
        )
        .expect("user stack mapping failed");
    }
    unsafe {
        let code = (physical_memory_offset + user_frame_a.start_address().as_u64()) as *mut u8;
        core::ptr::write_bytes(code, 0xF4, Size4KiB::SIZE as usize);
        core::ptr::write(code, 0xCC);
        core::ptr::write(code.add(1), 0xEB);
        core::ptr::write(code.add(2), 0xFE);
    }
    assert!(address_space::same_virtual_page_is_isolated(
        &mapper_a, &mapper_b, user_page,
    ));
    assert!(!address_space::is_user_address(0));
    let (original_root, original_flags) = Cr3::read();
    unsafe {
        space_a.activate();
        assert_eq!(Cr3::read().0, space_a.root_frame());
        space_b.activate();
        assert_eq!(Cr3::read().0, space_b.root_frame());
        Cr3::write(original_root, original_flags);
    }
    assert_eq!(Cr3::read().0, original_root);
    serial_print(b"AQ OS kernel: user address spaces and CR3 switch OK\r\n");

    let allocation = Box::new(0xA005_u64);
    assert_eq!(*allocation, 0xA005_u64);
    serial_print(b"AQ OS kernel: memory manager OK\r\n");
    scheduler::register(0);
    scheduler::register(1);
    let task = TaskContext {
        id: 1,
        capabilities: Capabilities::CLOCK_READ,
    };
    let ticks = dispatch(task, Number::ClockGetTicks as u64, Args::default(), 7).unwrap();
    assert_eq!(ticks, 7);
    let denied = dispatch(
        task,
        Number::ConsoleWrite as u64,
        Args {
            a0: 0x1000,
            a1: 4,
            ..Args::default()
        },
        0,
    );
    assert_eq!(denied, Err(Error::PermissionDenied));
    serial_print(b"AQ OS kernel: syscall capability gate OK\r\n");

    interrupts::init_idt();
    serial_print(b"AQ OS: IDT OK\r\n");
    unsafe { interrupts::init_pics() };
    serial_print(b"AQ OS: PIC OK\r\n");
    x86_64::instructions::interrupts::disable();
    serial_print(b"AQ OS: interrupts configured\r\n");
    serial_print(b"AQ OS kernel: entering ring3 test\r\n");
    unsafe { enter_user_mode(space_a, selectors.user_code, selectors.user_data) }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_print(b"AQ OS kernel: PANIC\r\n");
    loop {
        core::hint::spin_loop();
    }
}
