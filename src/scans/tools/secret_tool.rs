use std::{fs, time::Instant};

use serde_json::{Value, json};

use crate::utils::common::{execute_command, print_error, count_env_variables};

pub struct SecretTool;

impl SecretTool {
    pub fn new() -> Self {
        SecretTool
    }

    pub async fn run_scan(&self, _path: &str, _commit_id: Option<&str>, _branch: Option<&str>, verbose: bool) {
      let start_time = Instant::now();
      if !std::path::Path::new("/tmp/app").exists() {
            if _path.starts_with("http") {
                if verbose {
                    println!("[+] Cloning git repo...");
                }
                if let Some(_branch) = _branch {
                    let clone_command = format!("git clone -b {} {} /tmp/app", _branch, _path);
                    execute_command(&clone_command, false).await;
                }else{
                    let clone_command = format!("git clone {} /tmp/app", _path);
                    execute_command(&clone_command, false).await;
                }
            }else{
                if verbose {
                    println!("[+] Copying project to /tmp/app...");
                }
                let copy_command = format!("cp -r {} /tmp/app", _path);
                execute_command(&copy_command, false).await;
            }
        }
        let mut _path = format!("/tmp/app");
        
        if let Some(commit_id) = _commit_id {
            if verbose {
                println!("[+] Checking out to commit id: {}", commit_id);
            }
            let checkout_command = format!("cd {} && git checkout {}", _path, commit_id);
            execute_command(&checkout_command, true).await;
            // now copy only modified files from that commitID to new folder /tmp/code after creating code folder
            // make a new folder /tmp/code
            let copy_command = format!("mkdir -p /tmp/code");
            execute_command(&copy_command, true).await;
            let copy_command = format!("cd {} && git diff-tree --no-commit-id --name-only -r {} | xargs -I {{}} git ls-tree --name-only {} {{}} | xargs git archive --format=tar {} | tar -x -C /tmp/code", _path, commit_id, commit_id, commit_id);
            execute_command(&copy_command, true).await;
            // now run secret scan on /tmp/code folder
            _path = format!("/tmp/code");
        }

        let mut excluded_folders = Vec::new();
        excluded_folders.push("node_modules");
        excluded_folders.push("build");
        excluded_folders.push("bundles");
        excluded_folders.push("dist");
        excluded_folders.push(".github");
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

        let cmd = format!("trufflehog filesystem --no-update {} --json --exclude-detectors=FLOAT,SIGNABLE,YANDEX,OANDA,CIRCLE,PARSEUR,URI,SENTRYTOKEN,SIRV,ETSYAPIKEY,UNIFYID,MIRO,FRESHDESK,ALIBABA,YELP,FLATIO", _path);
        let output_data = execute_command(&cmd, true).await;
        let mut results: Vec<Value> = Vec::new();
        for line in output_data.lines() {
            let json_output: serde_json::Value = serde_json::from_str(&line).expect("Error parsing JSON");
            
            // if it have key SourceMetadata only then add it to results
            if json_output["SourceMetadata"].is_null() {
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
            print_error("Error: Secret Scanner not generated results, please contact support team!", 101);
        }
        let json_output = std::fs::read_to_string("/tmp/secrets.json").expect("Error reading file");
        let json_output: serde_json::Value = serde_json::from_str::<serde_json::Value>(&json_output).unwrap();
            
        // save data in output.json and before that get json data from output.json file if it exists and then append new data to it
        // output.json data will be in format {"sast":{}, "sca":{}, "secret":{}, "license":{}}
        let mut output_json = json!({});
        if std::path::Path::new("/tmp/output.json").exists() {
            let output_json_data = std::fs::read_to_string("/tmp/output.json").unwrap();
            output_json = serde_json::from_str::<serde_json::Value>(&output_json_data).unwrap();
        }
        output_json["secret"] = json_output.clone();
        std::fs::write("/tmp/output.json", serde_json::to_string_pretty(&output_json).unwrap()).unwrap();

        let end_time = Instant::now();
        let elapsed_time = end_time - start_time;
        let elapsed_seconds = elapsed_time.as_secs_f64().round();
        println!("Execution time for Secret scan: {:?} seconds", elapsed_seconds);
    }
}
