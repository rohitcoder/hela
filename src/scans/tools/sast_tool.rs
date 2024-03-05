use std::time::Instant;

use serde_json::json;

use crate::utils::common::{execute_command, print_error, post_json_data};

pub struct SastTool;

impl SastTool {
    pub fn new() -> Self {
        SastTool
    }

    pub async fn run_scan(&self, _path: &str, _commit_id: Option<&str>, _branch: Option<&str>, _server_url: Option<&str>, rule_path: String, verbose: bool) {
        let start_time = Instant::now();
        if verbose {
            println!("[+] Running SAST scan on path: {}", _path);
        }
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

        let cmd = "semgrep --version";
        let out = execute_command(cmd, false).await;
        if out == "" {
            print_error("Error: SAST Scanner is not configured properly, please contact support team!", 101);
        }
        
        
        let mut _path = format!("/tmp/app");

        // if commit_id is provided then checkout to that commit id
        if let Some(commit_id) = _commit_id {
            if verbose {
                println!("[+] Checking out to commit id: {}", commit_id);
            }
            let checkout_command = format!("cd {} && git checkout {}", _path, commit_id);
            execute_command(&checkout_command, true).await;

            let copy_command = format!("mkdir -p /tmp/code");
            execute_command(&copy_command, true).await;
            let copy_command = format!("cd {} && git diff-tree --no-commit-id --name-only -r {} | xargs -I {{}} git ls-tree --name-only {} {{}} | xargs git archive --format=tar {} | tar -x -C /tmp/code", _path, commit_id, commit_id, commit_id);
            println!("copy_command: {}", copy_command);
            execute_command(&copy_command, true).await;
            // now run secret scan on /tmp/code folder
            _path = format!("/tmp/code");
        }
        if !std::path::Path::new("/tmp/sast-rules").exists() {
            if verbose {
                println!("[+] Downloading Rules");
            }
            if rule_path != "" && rule_path.starts_with("http") {
                println!("[+] Downloading Rules from {}", rule_path);
                let clone_command = format!("git clone {} /tmp/sast-rules", rule_path);
                execute_command(&clone_command, false).await;
            }else {
                println!("[+] Downloading Rules from default repo");
                let clone_command = format!("git clone {} /tmp/sast-rules", "https://github.com/rohitcodergroww/semgrep-rules");
                execute_command(&clone_command, false).await;
            }
            if verbose {
                println!("[+] Rules Downloaded");
            }
        }

        // Lets RUN SAST SCAN using let cmd = format!("semgrep --config {}/sast-rules {} {} {} --verbose --metrics off --max-target-bytes 1000000 --json -o {}/sast_output.json", tmp_folder, folder_path, exclude_flags, exclude_rules, tmp_folder);
        if verbose {
            println!("[+] Running SAST scan...");
        }
        let mut excluded_folders = Vec::new();
        excluded_folders.push("node_modules");
        excluded_folders.push("build");
        excluded_folders.push("bundles");
        excluded_folders.push("charts");
        excluded_folders.push("public");
        excluded_folders.push("dist");
        excluded_folders.push(".git");
        
        let exclude_flags = excluded_folders.iter().map(|x| format!("--exclude='{}' ", x)).collect::<Vec<String>>().join(" ");
        let cmd = format!("semgrep --config /tmp/sast-rules {} --verbose --json -o /tmp/sast_output.json {}", _path, exclude_flags);
        execute_command(&cmd, true).await;
        if verbose {
            println!("[+] SAST scan completed!");
        }
        // parse output and show it in terminal
        let is_file_exists = std::path::Path::new("/tmp/sast_output.json").exists();
       
        if !is_file_exists {
            print_error("Error: SAST Scanner not generated results, please contact support team!", 101);
        }

        let json_output = std::fs::read_to_string("/tmp/sast_output.json").expect("Error reading file");
        let json_output = serde_json::from_str::<serde_json::Value>(&json_output.to_string()).unwrap();
        // pick results key from json_output
        let json_output = json_output.as_object().unwrap().get("results").unwrap().as_array().unwrap();
        if _server_url.is_some() {
            println!("Posting SAST scan data to server...");
            let post_link = format!("{}/sast", _server_url.unwrap());
            let post_data = post_json_data(&post_link, serde_json::Value::Array(json_output.clone())).await;
            if verbose {
                if post_data.get("status").unwrap() == "200 OK" {
                    println!("Successfully posted SAST scan data to server!");
                }else{
                    println!("Error while posting SAST scan data to server!");
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
        output_json["sast"] = serde_json::Value::Array(json_output.clone());

        std::fs::write("/tmp/output.json", serde_json::to_string_pretty(&output_json).unwrap()).unwrap();

        let end_time = Instant::now();
        let elapsed_time = end_time - start_time;
        let elapsed_seconds = elapsed_time.as_secs_f64().round();
        println!("Execution time for SAST scan: {:?} seconds", elapsed_seconds);
    }
}
