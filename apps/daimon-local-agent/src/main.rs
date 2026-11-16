use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        eprintln!("usage: daimon-local-agent [--check] CONFIG.json");
        return ExitCode::from(2);
    };
    let (check, path) = if first == "--check" {
        let Some(path) = arguments.next() else {
            eprintln!("usage: daimon-local-agent [--check] CONFIG.json");
            return ExitCode::from(2);
        };
        (true, path)
    } else {
        (false, first)
    };
    if arguments.next().is_some() {
        eprintln!("usage: daimon-local-agent [--check] CONFIG.json");
        return ExitCode::from(2);
    }
    let config = match daimon_local_agent::load(path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if check {
        println!("local agent configuration valid");
        return ExitCode::SUCCESS;
    }
    match daimon_local_agent::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("local agent daemon: {error}");
            ExitCode::FAILURE
        }
    }
}
