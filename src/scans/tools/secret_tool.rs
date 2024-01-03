use serde_json::{Value, json};

use crate::utils::common::{execute_command, print_error, post_json_data, count_env_variables};

pub struct SecretTool;

impl SecretTool {
    pub fn new() -> Self {
        SecretTool
    }

    pub async fn run_scan(&self, _path: &str, _commit_id: Option<&str>, _branch: Option<&str>, _server_url: Option<&str>, verbose: bool) {
        /*
            1. Clone Repo
            2. Get Commit ID to scan and checkout to that commit ID using git checkout <Commit-ID>
            3. Now copy only modified files from that commitID to another folder for scanning using git diff-tree --no-commit-id --name-only -r <Commit-ID> | xargs -I {} cp {} ~/Desktop/code/
        */
        // check if path is a local path ore git link and then clone it
        // if /tmp/app not exists then run below commands
        if !std::path::Path::new("/tmp/app").exists() {
            if _path.starts_with("http") {
                if verbose {
                    println!("[+] Cloning git repo...");
                }
                if let Some(_branch) = _branch {
                    let clone_command = format!("git clone -b {} {} /tmp/app", _branch, _path);
                    execute_command(&clone_command, true).await;
                }else{
                    let clone_command = format!("git clone {} /tmp/app", _path);
                    execute_command(&clone_command, true).await;
                }
            }else{
                if verbose {
                    println!("[+] Copying project to /tmp/app...");
                }
                let copy_command = format!("cp -r {} /tmp/app", _path);
                execute_command(&copy_command, true).await;
            }
        }
        let mut _path = format!("/tmp/app");
        
        // if commit_id is provided then checkout to that commit id
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

        let cmd = "trufflehog";
        let out = execute_command(cmd, true).await;
        if out == "" {
            print_error("Error: Secret Scanner is not configured properly, please contact support team!", 101);
        }

        let remove_git_folder = format!("rm -rf {}/.git", _path);
        execute_command(&remove_git_folder, true).await;

        let cmd = format!("trufflehog filesystem --no-update {} --json --exclude-detectors=FLOAT", _path);
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
        
        if _server_url.is_some() {
            println!("[+] Posting Secret scan data to server...");
            let post_link = format!("{}/secret", _server_url.unwrap());
            let post_data = post_json_data(&post_link, json_output.clone()).await;

            if verbose {
                if post_data.get("status").unwrap() == "200 OK" {
                    println!("Successfully posted Secret scan data to server!");
                }else{
                    println!("Error while posting Secret scan data to server!");
                }
            }
        }
            
        // save data in output.json and before that get json data from output.json file if it exists and then append new data to it
        // output.json data will be in format {"sast":{}, "sca":{}, "secret":{}, "license":{}}
        let mut output_json = json!({});
        if std::path::Path::new("/tmp/output.json").exists() {
            let output_json_data = std::fs::read_to_string("/tmp/output.json").unwrap();
            output_json = serde_json::from_str::<serde_json::Value>(&output_json_data).unwrap();
        }
        output_json["secret"] = json_output.clone();
        std::fs::write("/tmp/output.json", serde_json::to_string_pretty(&output_json).unwrap()).unwrap();
    }
}
