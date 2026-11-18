use std::{env, io, process::ExitCode};

const USAGE: &str =
    "usage: daimon-local-model [--check | --describe-providers | --supervised] CONFIG.json";

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (check, describe, supervised, path) =
        if first == "--check" || first == "--describe-providers" || first == "--supervised" {
            let Some(path) = arguments.next() else {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            };
            (
                first == "--check",
                first == "--describe-providers",
                first == "--supervised",
                path,
            )
        } else {
            (false, false, false, first)
        };
    if arguments.next().is_some() {
        eprintln!("{USAGE}");
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
    let result = if supervised {
        daimon_local_model::run_supervised(config, io::stdin())
    } else {
        daimon_local_model::run(config)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("local model daemon: {error}");
            ExitCode::FAILURE
        }
    }
}
