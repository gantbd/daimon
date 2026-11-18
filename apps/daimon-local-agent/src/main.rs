use std::{
    env,
    io::{self, Read},
    process::ExitCode,
};

const USAGE: &str = "usage: daimon-local-agent [--check | --describe-providers | --plan-provider-edit | --apply-provider-edit | --supervised] CONFIG.json";
const MAX_EDIT_REQUEST_BYTES: u64 = 256 * 1024;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (check, describe, plan_edit, apply_edit, supervised, path) = if first == "--check"
        || first == "--describe-providers"
        || first == "--plan-provider-edit"
        || first == "--apply-provider-edit"
        || first == "--supervised"
    {
        let Some(path) = arguments.next() else {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        };
        (
            first == "--check",
            first == "--describe-providers",
            first == "--plan-provider-edit",
            first == "--apply-provider-edit",
            first == "--supervised",
            path,
        )
    } else {
        (false, false, false, false, false, first)
    };
    if arguments.next().is_some() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    if describe {
        return match daimon_local_agent::provider_catalog_json(path) {
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
    if plan_edit || apply_edit {
        let mut request = Vec::new();
        if io::stdin()
            .lock()
            .take(MAX_EDIT_REQUEST_BYTES + 1)
            .read_to_end(&mut request)
            .is_err()
            || request.len() as u64 > MAX_EDIT_REQUEST_BYTES
        {
            eprintln!("provider edit: request exceeds the bounded input limit");
            return ExitCode::FAILURE;
        }
        let result = if plan_edit {
            daimon_local_agent::plan_provider_edit_json(path, &request)
        } else {
            daimon_local_agent::apply_provider_edit_json(path, &request)
        };
        return match result {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
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
