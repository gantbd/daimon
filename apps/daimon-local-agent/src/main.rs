use std::{env, io, process::ExitCode};

const USAGE: &str = "usage: daimon-local-agent [--check | --supervised] CONFIG.json";

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (check, supervised, path) = if first == "--check" || first == "--supervised" {
        let Some(path) = arguments.next() else {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        };
        (first == "--check", first == "--supervised", path)
    } else {
        (false, false, first)
    };
    if arguments.next().is_some() {
        eprintln!("{USAGE}");
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
    let result = if supervised {
        daimon_local_agent::run_supervised(config, io::stdin())
    } else {
        daimon_local_agent::run(config)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("local agent daemon: {error}");
            ExitCode::FAILURE
        }
    }
}
