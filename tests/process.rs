use nix::{sys::ptrace::kill, unistd::Pid};
use sdb::Process;

fn process_exists(pid: Pid) -> bool {
    kill(pid).is_ok()
}

#[test]
fn test_launch_success() {
    let process = Process::launch("yes").unwrap();
    assert!(process_exists(process.pid()));
}

#[test]
fn test_launch_failure() {
    let result = Process::launch("nonexistent_program");
    println!("Launch result: {:?}", result);
    assert!(result.is_err());
}
