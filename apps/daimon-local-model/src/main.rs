use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        eprintln!("usage: daimon-local-model [--check | --describe-providers] CONFIG.json");
        return ExitCode::from(2);
    };
    let (check, describe, path) = if first == "--check" || first == "--describe-providers" {
        let Some(path) = arguments.next() else {
            eprintln!("usage: daimon-local-model [--check | --describe-providers] CONFIG.json");
            return ExitCode::from(2);
        };
        (first == "--check", first == "--describe-providers", path)
    } else {
        (false, false, first)
    };
    if arguments.next().is_some() {
        eprintln!("usage: daimon-local-model [--check | --describe-providers] CONFIG.json");
        return ExitCode::from(2);
    }
    if describe {
        return match daimon_local_model::provider_catalog_json(path) {
            Ok(catalog) => {
                println!("{catalog}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
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
