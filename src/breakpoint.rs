use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use nix::sys::ptrace::{read, write};
use nix::unistd::Pid;
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub(crate) struct BreakpointSite {
    pid: Pid,
    id: usize,
    address: u64,
    saved_data: Option<u8>,
    is_enabled: bool,
}

impl BreakpointSite {
    pub fn new(pid: Pid, address: u64) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        BreakpointSite {
            pid,
            id,
            address,
            saved_data: None,
            is_enabled: false,
        }
    }

    pub fn enable(&mut self) -> Result<()> {
        if self.is_enabled {
            return Ok(());
        }
        let address = self.address as *mut std::ffi::c_void;
        let data = read(self.pid, address)? as u64;
        self.saved_data = Some((data & 0xff) as u8);
        let int3: u64 = 0xcc;
        let data_with_int3 = (data & !0xff) | int3;
        write(self.pid, address, data_with_int3 as i64)?;
        self.is_enabled = true;
        Ok(())
    }

    pub fn disable(&mut self) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }
        let address = self.address as *mut std::ffi::c_void;
        let data = read(self.pid, address)? as u64;
        let saved_data = self.saved_data.ok_or_else(|| {
            anyhow::anyhow!("Saved data not found for breakpoint with ID: {}", self.id)
        })?;
        let restored_data = (data & !0xff) | saved_data as u64;
        write(self.pid, address, restored_data as i64)?;
        self.is_enabled = false;
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub fn at_address(&self, address: u64) -> bool {
        self.address == address
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn saved_data(&self) -> Option<u8> {
        self.saved_data
    }

    pub fn in_range(&self, start: u64, end: u64) -> bool {
        self.address >= start && self.address <= end
    }
    pub fn id(&self) -> usize {
        self.id
    }
}

impl fmt::Display for BreakpointSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: address: {:#x}, {}",
            self.id,
            self.address,
            if self.is_enabled {
                "enabled"
            } else {
                "disabled"
            }
        )
    }
}
