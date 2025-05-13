use sdb::Process;

use anyhow::Result;
use clap::Parser;
use rustyline::Editor;

#[derive(Parser)]
struct Args {
    program: Option<String>,
    #[clap(short, long)]
    pid: Option<i32>,
}

fn attach(program: Option<String>, pid: Option<i32>) -> Result<Process> {
    match (program, pid) {
        (Some(prog), None) => Process::launch(&prog),
        (None, Some(p)) => Process::attach(p),
        _ => Err(anyhow::anyhow!("Either program or pid must be provided.")),
    }
}

fn main() {
    let args = Args::parse();
    let mut process = attach(args.program, args.pid).unwrap();

    let mut rl: rustyline::DefaultEditor = Editor::new().unwrap();
    loop {
        let line = rl.readline("sdb> ");
        match line {
            Ok(input) => {
                let _ = rl.add_history_entry(input.as_str());
                if let Err(err) = process.handle_command(&input) {
                    eprintln!("{err}");
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}
