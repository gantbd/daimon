use std::{
    env,
    io::{self, Read},
    process::ExitCode,
};

const USAGE: &str = "usage: daimon-local-model [--check | --describe-providers | --describe-provider-edit | --plan-provider-edit | --apply-provider-edit | --qualify-provider | --supervised] CONFIG.json";
const MAX_EDIT_REQUEST_BYTES: u64 = 256 * 1024;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (check, describe, describe_edit, plan_edit, apply_edit, qualify, supervised, path) =
        if first == "--check"
            || first == "--describe-providers"
            || first == "--describe-provider-edit"
            || first == "--plan-provider-edit"
            || first == "--apply-provider-edit"
            || first == "--qualify-provider"
            || first == "--supervised"
        {
            let Some(path) = arguments.next() else {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            };
            (
                first == "--check",
                first == "--describe-providers",
                first == "--describe-provider-edit",
                first == "--plan-provider-edit",
                first == "--apply-provider-edit",
                first == "--qualify-provider",
                first == "--supervised",
                path,
            )
        } else {
            (false, false, false, false, false, false, false, first)
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
    if describe_edit {
        return match daimon_local_model::provider_edit_form_json(path) {
            Ok(form) => {
                println!("{form}");
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
            daimon_local_model::plan_provider_edit_json(&path, &request)
        } else {
            daimon_local_model::apply_provider_edit_json(&path, &request)
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
    if qualify {
        let mut request = Vec::new();
        if io::stdin().read_to_end(&mut request).is_err() || request.len() > 64 * 1024 {
            eprintln!("local model provider qualification: invalid bounded request");
            return ExitCode::FAILURE;
        }
        return match daimon_local_model::qualify_provider_json(&path, &request) {
            Ok(receipt) => {
                println!("{receipt}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("local model provider qualification: {error}");
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
