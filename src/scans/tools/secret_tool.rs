use std::{fs, time::Instant};

use serde_json::{json, Value};

use crate::utils::common::{checkout, count_env_variables, execute_command, print_error};

pub struct SecretTool;

impl SecretTool {
    pub fn new() -> Self {
        SecretTool
    }

    pub async fn run_scan(
        &self,
        _path: &str,
        _commit_id: Option<&str>,
        _branch: Option<&str>,
        verbose: bool,
    ) {
        let start_time = Instant::now();
        if !std::path::Path::new("/tmp/app").exists() {
            if _path.starts_with("http") {
                if verbose {
                    println!("[+] Cloning git repo...");
                }
                if let Some(_branch) = _branch {
                    if _commit_id.is_some() {
                        let branch = Some(_branch);
                        let out = checkout(_path, "/tmp/app", _commit_id, branch);
                        if out.is_err() {
                            println!("Error while cloning: {}", out.err().unwrap());
                        }
                    } else {
                        let branch = Some(_branch);
                        let out = checkout(_path, "/tmp/app", None, branch);
                        if out.is_err() {
                            println!("Error while cloning: {}", out.err().unwrap());
                        }
                    }
                } else {
                    let out = checkout(_path, "/tmp/app", None, None);
                    if out.is_err() {
                        println!("Error while cloning: {}", out.err().unwrap());
                    }
                }
            } else {
                if verbose {
                    println!("[+] Copying project to /tmp/app...");
                }
                let copy_command = format!("cp -r {} /tmp/app", _path.clone());
                execute_command(&copy_command, true).await;
            }
        }
        let mut _path = format!("/tmp/app");
        let mut excluded_folders = Vec::new();
        excluded_folders.push("node_modules");
        excluded_folders.push("build");
        excluded_folders.push("bundles");
        excluded_folders.push("dist");
        excluded_folders.push("__tests__");
        excluded_folders.push("test");

        // list all folders under _path recursively and then delete excluded folders
        let mut folders = fs::read_dir(_path.clone()).unwrap();
        while let Some(folder) = folders.next() {
            let folder = folder.unwrap();
            let folder_path = folder.path();
            let folder_path = folder_path.to_str().unwrap();
            println!("[+] Checking if folder: {} is excluded...", folder_path);
            if excluded_folders.contains(&folder.file_name().to_str().unwrap()) {
                println!("[+] Deleting folder: {}, as it is excluded...", folder_path);
                let delete_command = format!("rm -rf {}", folder_path);
                execute_command(&delete_command, true).await;
            }
        }

        let cmd = format!("trufflehog filesystem --no-update {} --json --exclude-detectors=FLOAT,SIGNABLE,YANDEX,OANDA,CIRCLE,PARSEUR,URI,SENTRYTOKEN,SIRV,ETSYAPIKEY,UNIFYID,MIRO,FRESHDESK,ALIBABA,YELP,FLATIO,GETRESPONSE,ATERA,GITTER,SONARCLOUD,AZURESEARCHADMINKEY", _path);
        let output_data = execute_command(&cmd, true).await;
        let mut results: Vec<Value> = Vec::new();
        for line in output_data.lines() {
            let json_output: serde_json::Value =
                serde_json::from_str(&line).expect("Error parsing JSON");

            // if it have key SourceMetadata only then add it to results
            if json_output["SourceMetadata"].is_null() {
                continue;
            }
            // if file path contains ".git/config"
            if json_output["SourceMetadata"]["Data"]["Filesystem"]["file"]
                .as_str()
                .unwrap()
                .contains(".git/config")
            {
                println!("[+] Skipping .git/config file...");
                continue;
            }
            // if "Raw" is in json_output and not null then check if it contains environment variables
            if json_output["Raw"].is_string() && !json_output["Raw"].is_null() {
                if count_env_variables(&json_output["Raw"].as_str().unwrap()) > 0 {
                    continue;
                }
            }
            results.push(json_output);
        }
        // ## iterate into each results and implement checks for specific DetectorName
        let mut new_results: Vec<Value> = Vec::new();
        for result in results.iter_mut() {
            if result["DetectorName"].as_str().unwrap() == "JDBC" {
                // if not contains password then continue
                if !result["Raw"].as_str().unwrap().contains("password") {
                    continue;
                }
            }
            new_results.push(result.clone());
        }
        results = new_results;
        let json_output = serde_json::json!({
            "results": results
        });
        let json_output = serde_json::to_string_pretty(&json_output).unwrap();
        std::fs::write("/tmp/secrets.json", json_output).expect("Unable to write file");
        let is_file_exists = std::path::Path::new("/tmp/secrets.json").exists();
        if !is_file_exists {
            print_error(
                "Error: Secret Scanner not generated results, please contact support team!",
                101,
            );
        }
        let json_output = std::fs::read_to_string("/tmp/secrets.json").expect("Error reading file");
        let json_output: serde_json::Value =
            serde_json::from_str::<serde_json::Value>(&json_output).unwrap();

        // save data in output.json and before that get json data from output.json file if it exists and then append new data to it
        // output.json data will be in format {"sast":{}, "sca":{}, "secret":{}, "license":{}}
        let mut output_json = json!({});
        if std::path::Path::new("/tmp/output.json").exists() {
            let output_json_data = std::fs::read_to_string("/tmp/output.json").unwrap();
            output_json = serde_json::from_str::<serde_json::Value>(&output_json_data).unwrap();
        }
        output_json["secret"] = json_output.clone();
        std::fs::write(
            "/tmp/output.json",
            serde_json::to_string_pretty(&output_json).unwrap(),
        )
        .unwrap();

        let end_time = Instant::now();
        let elapsed_time = end_time - start_time;
        let elapsed_seconds = elapsed_time.as_secs_f64().round();
        println!(
            "Execution time for Secret scan: {:?} seconds",
            elapsed_seconds
        );
    }
}
