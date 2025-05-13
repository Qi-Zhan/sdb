use std::io::IoSliceMut;

use anyhow::Result;
use nix::sys::personality::Persona;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::{ForkResult, Pid, execvp, fork, pipe2};
use nix::{
    sys::{
        personality,
        ptrace::{self, kill},
        uio::process_vm_readv,
        wait::{WaitStatus, waitpid},
    },
    unistd::close,
};

use crate::breakpoint::BreakpointSite;
use crate::disassembler::print_disassemble;

#[derive(Debug, Clone, Copy)]
enum ProcessState {
    Running,
    Stopped,
    // Exited,
    // Terminated,
}

#[derive(Debug)]
pub struct Process {
    pid: Pid,
    terminate_on_end: bool,
    state: ProcessState,
    breakpoints: Vec<BreakpointSite>,
}

impl Process {
    pub fn launch(program: &str) -> Result<Self> {
        let (read, write) = pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let fork_result = unsafe { fork()? };
        match fork_result {
            ForkResult::Parent { child: pid } => {
                close(write)?;
                let mut buf = [0; 1024];
                let chars_read = nix::unistd::read(&read, &mut buf)?;
                close(read)?;
                let content = String::from_utf8(buf[..chars_read].to_vec())?;
                if chars_read > 0 {
                    waitpid(pid, None)?;
                    return Err(anyhow::anyhow!(content));
                }
                let process = Process::new(pid, true);
                process.wait_on_signal()?;
                println!("Lauched process with PID: {}", pid);
                Ok(process)
            }
            ForkResult::Child => {
                personality::set(Persona::ADDR_NO_RANDOMIZE)?;
                close(read)?;
                ptrace::traceme()?;
                let path = std::ffi::CString::new(program)?;
                let argv = [path.clone()];
                match execvp(&path, &argv) {
                    Ok(_) => unreachable!(),
                    Err(err) => {
                        let error_message = format!("Error executing program: {}", err);
                        let bytes = error_message.as_bytes();
                        nix::unistd::write(write, bytes)?;
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    pub fn attach(pid: i32) -> Result<Self> {
        let pid = Pid::from_raw(pid);
        ptrace::attach(pid)?;
        let process = Process::new(pid, false);
        process.wait_on_signal()?;
        println!("Lauched process with PID: {}", pid);
        Ok(process)
    }

    pub fn handle_command(&mut self, command: &str) -> Result<()> {
        let args = command.split_whitespace().collect::<Vec<_>>();
        let command = args[0];
        match command {
            "continue" | "c" => {
                self.resume()?;
                let reason = self.wait_on_signal()?;
                println!("Process {:?}", reason);
                if let WaitStatus::Stopped(_, _) = reason {
                    let pc = self.get_pc()?;
                    self.print_assembly(pc, 5)?;
                }
                Ok(())
            }
            "step" | "s" => {
                self.step_instruction()?;
                let reason = self.wait_on_signal()?;
                println!("Process {:?}", reason);
                if let WaitStatus::Stopped(_, _) = reason {
                    let pc = self.get_pc()?;
                    self.print_assembly(pc, 1)?;
                }
                Ok(())
            }
            "break" | "b" => {
                if args.len() == 1 {
                    println!("Current breakpoints:");
                    for b in &self.breakpoints {
                        println!("{b}");
                    }
                } else {
                    if args.len() == 2 {
                        return Err(anyhow::anyhow!("Usage: break set <address>"));
                    }
                    match args[1] {
                        "set" => {
                            let address = if args[2].starts_with("0x") {
                                u64::from_str_radix(&args[2][2..], 16)?
                            } else {
                                args[2].parse::<u64>()?
                            };
                            self.create_breakpoint_site(address, true)?;
                        }
                        "delete" => {
                            let id = args[2].parse::<usize>()?;
                            self.breakpoints.retain(|bp| bp.id() != id);
                        }
                        "enable" => {
                            let id = args[2].parse::<usize>()?;
                            if let Some(bp) = self.breakpoints.iter_mut().find(|bp| bp.id() == id) {
                                bp.enable()?;
                            }
                        }
                        "disable" => {
                            let id = args[2].parse::<usize>()?;
                            if let Some(bp) = self.breakpoints.iter_mut().find(|bp| bp.id() == id) {
                                bp.disable()?;
                            }
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Usage: breakpoint set|delete|enable|disable address|id"
                            ));
                        }
                    }
                }
                Ok(())
            }
            "reg" => {
                if args.len() > 1 {
                    let reg = args[1];
                    match args[0] {
                        "read" => {
                            let value = self.read_register(reg)?;
                            println!("Register: {}, Value: {:0x}", reg, value);
                        }
                        "write" => {
                            if args.len() > 2 {
                                let value = args[2];
                                let value = value.parse::<u64>()?;
                                self.write_register(reg, value)?;
                            } else {
                                println!("Usage: reg write <register> <value>");
                            }
                        }
                        _ => {
                            println!("Usage: reg read|write <register>");
                        }
                    }
                } else {
                    println!("Usage: reg read|write <register>");
                }
                Ok(())
            }
            "memory" | "mem" => self.handle_memory_command(&args[1..]),
            "help" => {
                println!("Available commands:");
                println!("  continue (c) - Continue the process");
                println!("  step (s)     - Step to the next instruction");
                println!("  break (b)    - Manage breakpoints");
                println!("  reg          - Read or write registers");
                println!("  memory       - Read or write memory");
                println!("  help - Show this help message");
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Unknown command: {}", command)),
        }
    }

    fn handle_memory_command(&self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            return Err(anyhow::anyhow!(
                "Usage: memory read|write <address> [<data>]"
            ));
        }
        let command = args[0];
        match command {
            "read" => {
                let address = if args[1].starts_with("0x") {
                    u64::from_str_radix(&args[1][2..], 16)?
                } else {
                    args[1].parse::<u64>()?
                };
                print!("0x{:#x}: ", address);
                let data = self.read_memory(address, 32)?;
                for byte in &data[..16] {
                    print!("{:02x} ", byte);
                }
                println!();
                print!("0x{:#x}: ", address + 16);
                for byte in &data[16..32] {
                    print!("{:02x} ", byte);
                }
                println!();
            }
            "write" => {
                if args.len() < 3 {
                    return Err(anyhow::anyhow!("Usage: memory write <address> <data>"));
                }
                let address = args[1].parse::<u64>()?;
                let data = args[2].parse::<u64>()?;
                let data = data.to_ne_bytes();
                self.write_memory(address, &data)?;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Usage: memory read|write <address> [<data>]"
                ));
            }
        }
        Ok(())
    }

    fn read_memory(&self, mut address: u64, mut amount: usize) -> Result<Vec<u8>> {
        let mut ret = vec![0; amount];
        let mut local_iov = vec![IoSliceMut::new(&mut ret)];
        let mut remote_iov = vec![];
        while amount > 0 {
            let up_to_next_page = 0x1000 - (address % 0xfff);
            let chunk_size = amount.min(up_to_next_page as usize);
            remote_iov.push(RemoteIoVec {
                base: address as usize,
                len: chunk_size,
            });
            amount -= chunk_size;
            address += chunk_size as u64;
        }

        let pid = self.pid;
        process_vm_readv(pid, &mut local_iov, &remote_iov)?;
        Ok(ret)
    }

    fn read_memory_without_traps(&self, address: u64, amount: usize) -> Result<Vec<u8>> {
        let mut memory = self.read_memory(address, amount)?;
        for bt in &self.breakpoints {
            if bt.in_range(address, address + amount as u64) && bt.is_enabled() {
                let offset = bt.address() - address;
                memory[offset as usize] = bt.saved_data().unwrap();
            }
        }
        Ok(memory)
    }

    fn write_memory(&self, address: u64, data: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < data.len() {
            let remaining = data.len() - written;
            let word = if remaining >= 8 {
                i64::from_ne_bytes(data[written..written + 8].try_into().unwrap())
            } else {
                let read = self.read_memory(address + written as u64, 8)?;
                let mut word = [0; 8];
                word[..remaining].copy_from_slice(&data[written..]);
                word[remaining..].copy_from_slice(&read[remaining..]);
                i64::from_ne_bytes(word)
            };
            ptrace::write(
                self.pid,
                (address + written as u64) as *mut libc::c_void,
                word,
            )?;
            written += 8;
        }
        Ok(())
    }

    fn read_register(&self, reg: &str) -> Result<u64> {
        // Implement register reading logic here
        let pid = self.pid;
        let reg_value = ptrace::getregs(pid)?;
        match reg {
            "rax" => Ok(reg_value.rax),
            "rbx" => Ok(reg_value.rbx),
            "rcx" => Ok(reg_value.rcx),
            "rdx" => Ok(reg_value.rdx),
            "rsi" => Ok(reg_value.rsi),
            "rdi" => Ok(reg_value.rdi),
            "rip" => Ok(reg_value.rip),
            _ => Err(anyhow::anyhow!("Unknown register: {}", reg)),
        }
    }

    fn write_register(&self, reg: &str, value: u64) -> Result<()> {
        let pid = self.pid;
        let mut reg_value = ptrace::getregs(pid)?;
        match reg {
            "rax" => reg_value.rax = value,
            "rbx" => reg_value.rbx = value,
            "rcx" => reg_value.rcx = value,
            "rdx" => reg_value.rdx = value,
            "rsi" => reg_value.rsi = value,
            "rdi" => reg_value.rdi = value,
            "rip" => reg_value.rip = value,
            _ => return Err(anyhow::anyhow!("Unknown register: {}", reg)),
        }
        ptrace::setregs(pid, reg_value)?;
        Ok(())
    }

    fn step_instruction(&mut self) -> Result<()> {
        let pc = self.get_pc()?;
        if self.enabled_stoppoint_at_address(pc) {
            let bp = self
                .breakpoints
                .iter_mut()
                .find(|bp| bp.at_address(pc) && bp.is_enabled())
                .unwrap();
            bp.disable()?;
            ptrace::step(self.pid, None)?;
            waitpid(self.pid, None)?;
            bp.enable()?;
        } else {
            ptrace::step(self.pid, None)?;
        }
        Ok(())
    }

    fn resume(&mut self) -> Result<()> {
        let pc = self.get_pc()?;
        if self.enabled_stoppoint_at_address(pc) {
            let bp = self
                .breakpoints
                .iter_mut()
                .find(|bp| bp.at_address(pc) && bp.is_enabled())
                .unwrap();
            bp.disable()?;
            ptrace::step(self.pid, None)?;
            waitpid(self.pid, None)?;
            bp.enable()?;
        }
        ptrace::cont(self.pid, None)?;
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    fn print_assembly(&self, address: u64, max_instructions: usize) -> Result<()> {
        let bytes = self.read_memory_without_traps(address, max_instructions * 15)?;
        print_disassemble(&bytes, address, max_instructions);
        Ok(())
    }

    fn wait_on_signal(&self) -> Result<WaitStatus> {
        let reason = waitpid(self.pid, None)?;
        if let WaitStatus::Stopped(_, signal) = reason {
            if signal == nix::sys::signal::Signal::SIGTRAP {
                let instr_begin = self.get_pc()? - 1;
                if self.enabled_stoppoint_at_address(instr_begin) {
                    self.set_pc(instr_begin)?;
                }
            }
        }
        Ok(reason)
    }

    fn enabled_stoppoint_at_address(&self, address: u64) -> bool {
        self.breakpoints
            .iter()
            .any(|bp| bp.at_address(address) && bp.is_enabled())
    }

    fn create_breakpoint_site(&mut self, address: u64, enabled: bool) -> Result<()> {
        let mut bp = BreakpointSite::new(self.pid, address);
        if enabled {
            bp.enable()?;
        }
        println!("{bp}");
        self.breakpoints.push(bp);
        Ok(())
    }

    fn get_pc(&self) -> Result<u64> {
        let pid = self.pid;
        let regs = ptrace::getregs(pid)?;
        Ok(regs.rip)
    }

    fn set_pc(&self, address: u64) -> Result<()> {
        let pid = self.pid;
        let mut regs = ptrace::getregs(pid)?;
        regs.rip = address;
        ptrace::setregs(pid, regs)?;
        Ok(())
    }

    fn new(pid: Pid, terminate_on_end: bool) -> Self {
        Process {
            pid,
            terminate_on_end,
            state: ProcessState::Stopped,
            breakpoints: vec![],
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        ptrace::detach(self.pid, None).unwrap_or_default();
        if self.terminate_on_end {
            let _ = kill(self.pid);
        }
    }
}
