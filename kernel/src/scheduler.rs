use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

pub const MAX_TASKS: usize = 4;
static RUNNABLE: [AtomicU8; MAX_TASKS] = [const { AtomicU8::new(0) }; MAX_TASKS];
static CURRENT: AtomicUsize = AtomicUsize::new(0);

pub fn register(task_id: usize) -> bool {
    if task_id >= MAX_TASKS {
        return false;
    }
    RUNNABLE[task_id].store(1, Ordering::Release);
    true
}

pub fn current() -> usize {
    CURRENT.load(Ordering::Acquire)
}

pub fn on_timer_tick() -> usize {
    let start = (CURRENT.load(Ordering::Relaxed) + 1) % MAX_TASKS;
    for offset in 0..MAX_TASKS {
        let candidate = (start + offset) % MAX_TASKS;
        if RUNNABLE[candidate].load(Ordering::Acquire) != 0 {
            CURRENT.store(candidate, Ordering::Release);
            return candidate;
        }
    }
    0
}
