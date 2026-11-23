#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod address_space;
mod elf;
mod gdt;
mod heap;
mod interrupts;
mod memory;
mod process;
mod scheduler;
mod syscall_entry;

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
    entry: u64,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
) -> ! {
    space.activate();
    let frame = InterruptStackFrame::new(
        VirtAddr::new(entry),
        user_code,
        RFlags::from_bits_retain(0x202),
        VirtAddr::new(USER_STACK_BASE + Size4KiB::SIZE),
        user_data,
    );
    frame.iretq()
}

const TEST_ELF_SIZE: usize = 0x1111;
static mut TEST_ELF: [u8; TEST_ELF_SIZE] = [0; TEST_ELF_SIZE];

fn build_test_elf() -> &'static [u8] {
    unsafe {
        let image = &mut *core::ptr::addr_of_mut!(TEST_ELF);
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&2u16.to_le_bytes());
        image[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        image[24..32].copy_from_slice(&(address_space::USER_IMAGE_BASE + 0x100).to_le_bytes());
        image[32..40].copy_from_slice(&64u64.to_le_bytes());
        image[52..54].copy_from_slice(&64u16.to_le_bytes());
        image[54..56].copy_from_slice(&56u16.to_le_bytes());
        image[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64;
        image[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        image[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        image[ph + 8..ph + 16].copy_from_slice(&0x1100u64.to_le_bytes());
        image[ph + 16..ph + 24]
            .copy_from_slice(&(address_space::USER_IMAGE_BASE + 0x100).to_le_bytes());
        image[ph + 32..ph + 40].copy_from_slice(&17u64.to_le_bytes());
        image[ph + 40..ph + 48].copy_from_slice(&17u64.to_le_bytes());
        image[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        image[0x1100..0x1111].copy_from_slice(&[
            0xCC, 0xB8, 0, 0, 0, 0, 0x0F, 0x05,
            0xB8, 1, 0, 0, 0, 0x0F, 0x05, 0xEB, 0xFE,
        ]);
        core::slice::from_raw_parts(core::ptr::addr_of!(TEST_ELF) as *const u8, TEST_ELF_SIZE)
    }
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
    serial_print(b"AQ OS: process space A allocated\r\n");
    let space_b = unsafe {
        address_space::create_root_with_kernel_mappings(
            physical_memory_offset,
            &mut frame_allocator,
        )
    }
    .expect("second user address-space root allocation failed");
    serial_print(b"AQ OS: process space B allocated\r\n");
    let user_page =
        Page::<Size4KiB>::containing_address(VirtAddr::new(address_space::USER_IMAGE_BASE));
    let user_stack_frame = frame_allocator
        .allocate_frame()
        .expect("user stack frame allocation failed");
    let user_stack_frame_b = frame_allocator
        .allocate_frame()
        .expect("second user stack frame allocation failed");
    let mut mapper_a =
        unsafe { address_space::mapper_for_root(space_a.root_frame(), physical_memory_offset) };
    let mut mapper_b =
        unsafe { address_space::mapper_for_root(space_b.root_frame(), physical_memory_offset) };
    unsafe {
        address_space::map_user_page(
            &mut mapper_a,
            Page::<Size4KiB>::containing_address(VirtAddr::new(USER_STACK_BASE)),
            user_stack_frame,
            &mut frame_allocator,
        )
        .expect("user stack mapping failed");
        serial_print(b"AQ OS: process A stack mapped\r\n");
        address_space::map_user_page(
            &mut mapper_b,
            Page::<Size4KiB>::containing_address(VirtAddr::new(USER_STACK_BASE)),
            user_stack_frame_b,
            &mut frame_allocator,
        )
        .expect("second user stack mapping failed");
        serial_print(b"AQ OS: process B stack mapped\r\n");
    }
    serial_print(b"AQ OS: loading process A ELF\r\n");
    let loaded = unsafe {
        elf::load(
            build_test_elf(),
            &mut mapper_a,
            &mut frame_allocator,
            physical_memory_offset,
        )
    }
    .expect("ELF user image load failed");
    assert_eq!(loaded.load_segments, 1);
    let loaded_b = unsafe {
        elf::load(
            build_test_elf(),
            &mut mapper_b,
            &mut frame_allocator,
            physical_memory_offset,
        )
    }
    .expect("second ELF user image load failed");
    assert_eq!(loaded_b.entry, loaded.entry);
    serial_print(b"AQ OS kernel: ELF user image loaded OK\r\n");
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
    assert!(process::install(process::ProcessControlBlock {
        id: 0,
        address_space: space_a,
        entry: loaded.entry,
        user_stack_top: USER_STACK_BASE + Size4KiB::SIZE,
        state: process::State::Running,
    }));
    assert!(process::install(process::ProcessControlBlock {
        id: 1,
        address_space: space_b,
        entry: loaded_b.entry,
        user_stack_top: USER_STACK_BASE + Size4KiB::SIZE,
        state: process::State::Runnable,
    }));
    assert_eq!(process::current(), 0);
    serial_print(b"AQ OS kernel: user process table OK\r\n");

    interrupts::init_idt();
    serial_print(b"AQ OS: IDT OK\r\n");
    unsafe { interrupts::init_pics() };
    serial_print(b"AQ OS: PIC OK\r\n");
    unsafe {
        syscall_entry::init(selectors.kernel_code.0, selectors.user_code.0);
    }
    serial_print(b"AQ OS kernel: syscall MSRs OK\r\n");
    x86_64::instructions::interrupts::disable();
    serial_print(b"AQ OS: interrupts configured\r\n");
    serial_print(b"AQ OS kernel: entering ring3 test\r\n");
    unsafe {
        enter_user_mode(
            space_a,
            loaded.entry,
            selectors.user_code,
            selectors.user_data,
        )
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_print(b"AQ OS kernel: PANIC\r\n");
    loop {
        core::hint::spin_loop();
    }
}
