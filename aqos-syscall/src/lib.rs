#![no_std]

use core::{convert::TryFrom, marker::PhantomData, mem::size_of};

pub const USER_ADDRESS_MAX: u64 = 0x0000_7fff_ffff_ffff;
pub const MAX_WRITE: usize = 4096;

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Number {
    Yield = 0,
    ClockGetTicks = 1,
    ConsoleWrite = 2,
}

impl Number {
    pub fn from_raw(raw: u64) -> Result<Self, Error> {
        match raw {
            0 => Ok(Self::Yield),
            1 => Ok(Self::ClockGetTicks),
            2 => Ok(Self::ConsoleWrite),
            _ => Err(Error::UnknownSyscall),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Args {
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownSyscall = 1,
    PermissionDenied = 2,
    InvalidPointer = 3,
    InvalidLength = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities(u64);

impl Capabilities {
    pub const NONE: Self = Self(0);
    pub const CLOCK_READ: Self = Self(1 << 0);
    pub const CONSOLE_WRITE: Self = Self(1 << 1);

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskContext {
    pub id: u64,
    pub capabilities: Capabilities,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserPtr<T> {
    addr: u64,
    _marker: PhantomData<*const T>,
}

impl<T> UserPtr<T> {
    pub const fn new(addr: u64) -> Result<Self, Error> {
        if addr == 0 || addr > USER_ADDRESS_MAX {
            Err(Error::InvalidPointer)
        } else {
            Ok(Self {
                addr,
                _marker: PhantomData,
            })
        }
    }

    pub fn checked_range(self, count: usize) -> Result<(u64, usize), Error> {
        let bytes = count
            .checked_mul(size_of::<T>())
            .ok_or(Error::InvalidLength)?;
        if bytes > 0 {
            let last_offset = u64::try_from(bytes - 1).map_err(|_| Error::InvalidLength)?;
            let end = self
                .addr
                .checked_add(last_offset)
                .ok_or(Error::InvalidPointer)?;
            if end > USER_ADDRESS_MAX {
                return Err(Error::InvalidPointer);
            }
        }
        Ok((self.addr, bytes))
    }
}

pub fn dispatch(ctx: TaskContext, raw_number: u64, args: Args, ticks: u64) -> Result<u64, Error> {
    match Number::from_raw(raw_number)? {
        Number::Yield => Ok(0),
        Number::ClockGetTicks => {
            if !ctx.capabilities.contains(Capabilities::CLOCK_READ) {
                return Err(Error::PermissionDenied);
            }
            Ok(ticks)
        }
        Number::ConsoleWrite => {
            if !ctx.capabilities.contains(Capabilities::CONSOLE_WRITE) {
                return Err(Error::PermissionDenied);
            }
            if args.a1 > MAX_WRITE as u64 {
                return Err(Error::InvalidLength);
            }
            let count = usize::try_from(args.a1).map_err(|_| Error::InvalidLength)?;
            UserPtr::<u8>::new(args.a0)?.checked_range(count)?;
            Ok(args.a1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_syscalls_and_missing_capabilities_are_denied() {
        let task = TaskContext {
            id: 1,
            capabilities: Capabilities::NONE,
        };
        assert_eq!(
            dispatch(task, 99, Args::default(), 7),
            Err(Error::UnknownSyscall)
        );
        assert_eq!(
            dispatch(task, Number::ClockGetTicks as u64, Args::default(), 7),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn capabilities_and_user_ranges_are_checked() {
        let task = TaskContext {
            id: 2,
            capabilities: Capabilities::CONSOLE_WRITE,
        };
        let args = Args {
            a0: 0x1000,
            a1: 12,
            ..Args::default()
        };
        assert_eq!(dispatch(task, Number::ConsoleWrite as u64, args, 0), Ok(12));
        let bad = Args {
            a0: USER_ADDRESS_MAX,
            a1: 2,
            ..Args::default()
        };
        assert_eq!(
            dispatch(task, Number::ConsoleWrite as u64, bad, 0),
            Err(Error::InvalidPointer)
        );
    }
}
