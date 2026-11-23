use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex;

use crate::address_space::AddressSpace;

pub const MAX_PROCESSES: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Empty,
    Runnable,
    Running,
    Exited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessControlBlock {
    pub id: usize,
    pub address_space: AddressSpace,
    pub entry: u64,
    pub user_stack_top: u64,
    pub state: State,
}

static TABLE: Mutex<[Option<ProcessControlBlock>; MAX_PROCESSES]> = Mutex::new([None, None]);
static CURRENT: AtomicUsize = AtomicUsize::new(0);

pub fn install(pcb: ProcessControlBlock) -> bool {
    if pcb.id >= MAX_PROCESSES || pcb.state == State::Empty {
        return false;
    }
    let mut table = TABLE.lock();
    if table[pcb.id].is_some() {
        return false;
    }
    table[pcb.id] = Some(pcb);
    true
}

pub fn set_current(id: usize) -> bool {
    let mut table = TABLE.lock();
    if table.get(id).and_then(Option::as_ref).is_none() {
        return false;
    }
    for process in table.iter_mut().flatten() {
        if process.state == State::Running {
            process.state = State::Runnable;
        }
    }
    table[id].as_mut().expect("checked above").state = State::Running;
    CURRENT.store(id, Ordering::Release);
    true
}

pub fn current() -> usize {
    CURRENT.load(Ordering::Acquire)
}

/// Switch to the next runnable process and activate its CR3. This is called
/// from the syscall path while interrupts are masked by IA32_FMASK.
pub unsafe fn yield_next() -> Option<usize> {
    let mut table = TABLE.lock();
    let current = CURRENT.load(Ordering::Relaxed);
    let next = (1..=MAX_PROCESSES)
        .map(|offset| (current + offset) % MAX_PROCESSES)
        .find(|&id| table[id].is_some_and(|pcb| pcb.state == State::Runnable));
    let id = next?;
    let pcb = table[id]?;
    for process in table.iter_mut().flatten() {
        if process.state == State::Running {
            process.state = State::Runnable;
        }
    }
    table[id] = Some(ProcessControlBlock {
        state: State::Running,
        ..pcb
    });
    CURRENT.store(id, Ordering::Release);
    pcb.address_space.activate();
    Some(id)
}
