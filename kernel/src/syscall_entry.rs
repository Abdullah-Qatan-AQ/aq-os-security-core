use core::arch::{asm, global_asm};

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

#[repr(align(16))]
struct SyscallStack([u8; 8192]);

static mut SYSCALL_STACK: SyscallStack = SyscallStack([0; 8192]);
static mut SYSCALL_STACK_TOP: u64 = 0;

// SYSCALL does not switch stacks. swapgs selects this kernel-owned pointer,
// then the entry stub moves RSP before calling any Rust code.
global_asm!(
    ".global aqos_syscall_entry",
    ".type aqos_syscall_entry,@function",
    "aqos_syscall_entry:",
    "swapgs",
    "mov rsp, qword ptr gs:[0]",
    "push r11",
    "push rcx",
    "mov rdi, rax",
    "call aqos_syscall_handler",
    "pop rcx",
    "pop r11",
    "swapgs",
    "sysretq",
);

unsafe fn write_msr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nostack, preserves_flags)
    );
}

pub unsafe fn init(kernel_code_selector: u16, user_code_selector: u16) {
    SYSCALL_STACK_TOP = core::ptr::addr_of!(SYSCALL_STACK.0) as u64 + 8192;
    write_msr(
        IA32_KERNEL_GS_BASE,
        core::ptr::addr_of!(SYSCALL_STACK_TOP) as u64,
    );

    let efer = {
        let low: u32;
        let high: u32;
        asm!(
            "rdmsr",
            in("ecx") IA32_EFER,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        ((high as u64) << 32) | low as u64
    };
    write_msr(IA32_EFER, efer | 1);

    // SYSRET uses STAR[63:48] + 16 for user CS and + 8 for user SS.
    let sysret_base = user_code_selector.wrapping_sub(16);
    let star = ((sysret_base as u64) << 48) | ((kernel_code_selector as u64) << 32);
    write_msr(IA32_STAR, star);
    write_msr(IA32_LSTAR, aqos_syscall_entry as *const () as usize as u64);
    write_msr(IA32_FMASK, 1 << 9);
}

#[no_mangle]
extern "C" fn aqos_syscall_handler(number: u64) -> u64 {
    if number == 1 {
        crate::serial_print(b"AQ OS kernel: hardware syscall entry OK\r\n");
    } else {
        crate::serial_print(b"AQ OS kernel: unknown hardware syscall\r\n");
    }
    0
}

extern "C" {
    fn aqos_syscall_entry();
}
