use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        eprintln!("usage: daimon-local-model [--check] CONFIG.json");
        return ExitCode::from(2);
    };
    let (check, path) = if first == "--check" {
        let Some(path) = arguments.next() else {
            eprintln!("usage: daimon-local-model [--check] CONFIG.json");
            return ExitCode::from(2);
        };
        (true, path)
    } else {
        (false, first)
    };
    if arguments.next().is_some() {
        eprintln!("usage: daimon-local-model [--check] CONFIG.json");
        return ExitCode::from(2);
    }
    let config = match daimon_local_model::load(path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if check {
        println!("local model configuration valid");
        return ExitCode::SUCCESS;
    }
    match daimon_local_model::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("local model daemon: {error}");
            ExitCode::FAILURE
        }
    }
}
