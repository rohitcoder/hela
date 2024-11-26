use std::{fs, time::Instant};

use serde_json::json;

use crate::utils::common::{checkout, execute_command, print_error};

pub struct SastTool;

impl SastTool {
    pub fn new() -> Self {
        SastTool
    }

    pub async fn run_scan(
        &self,
        _path: &str,
        base_branch: Option<&str>,
        pr_branch: Option<&str>,
        rule_path: String,
        verbose: bool,
    ) {
        let start_time = Instant::now();
        if verbose {
            println!("[+] Running SAST scan on path: {}", _path);
        }
        println!("Base Branch: {:?}", base_branch);
        println!("PR Branch: {:?}", pr_branch);
        if !std::path::Path::new("/tmp/app").exists() {
            if _path.starts_with("http") {
                if verbose {
                    println!("[+] Cloning git repo...");
                }
                if let Some(pr_branch) = pr_branch {
                    if base_branch.is_some() {
                        let branch = Some(pr_branch);
                        let out = checkout(_path, "/tmp/app", base_branch, branch);
                        if out.is_err() {
                            println!("Error while cloning: {}", out.err().unwrap());
                            std::process::exit(0);
                        }
                    } else {
                        let branch = Some(pr_branch);
                        let out = checkout(_path, "/tmp/app", None, branch);
                        if out.is_err() {
                            println!("Error while cloning: {}", out.err().unwrap());
                            std::process::exit(0);
                        }
                    }
                } else {
                    let out = checkout(_path, "/tmp/app", None, None);
                    if out.is_err() {
                        println!("Error while cloning: {}", out.err().unwrap());
                        std::process::exit(0);
                    }
                }
            } else {
                if verbose {
                    println!("[+] Copying project to /tmp/app...");
                }
                let copy_command = format!("cp -r {} /tmp/app", _path);
                execute_command(&copy_command, true).await;
            }
        }

        let mut _path = format!("/tmp/app");
        if !std::path::Path::new("/tmp/sast-rules").exists() {
            if verbose {
                println!("[+] Downloading Rules");
            }
            if rule_path != "" && rule_path.starts_with("http") {
                println!("[+] Downloading Rules from {}", rule_path);
                let clone_command = format!("git clone {} /tmp/sast-rules", rule_path);
                execute_command(&clone_command, true).await;
            } else {
                println!("[+] Downloading Rules from default repo");
                let clone_command = format!(
                    "git clone https://github.com/rohitcodergroww/semgrep-rules /tmp/sast-rules"
                );
                execute_command(&clone_command, true).await;
            }
            // Remove .github folder from rules
            let remove_git_folder = format!("rm -rf /tmp/sast-rules/.github");
            execute_command(&remove_git_folder, true).await;

            if verbose {
                println!("[+] Rules Downloaded");
            }
        }

        if verbose {
            println!("[+] Running SAST scan...");
        }

        let mut excluded_folders = Vec::new();
        excluded_folders.push("node_modules");
        excluded_folders.push("build");
        excluded_folders.push("bundles");
        excluded_folders.push("charting_library");
        excluded_folders.push("dist");
        excluded_folders.push("__tests__");
        excluded_folders.push("test");

        // Read the contents of the directory
        let entries = fs::read_dir(_path.clone()).unwrap();

        // Collect file names into a vector
        let files_list: Vec<_> = entries
            .filter_map(|entry| {
                // Convert the `DirEntry` to a `PathBuf`
                let entry = entry.unwrap();
                let path = entry.path();
                let path = path.to_str().unwrap().to_string();
                Some(path)
            })
            .collect();

        // now delete file whose name is in excluded_folders
        for file in files_list.iter() {
            for folder in excluded_folders.iter() {
                if file.contains(folder) {
                    println!(
                        "Removing folder/file: {} as it is in excluded_folders",
                        file
                    );
                    let remove_command = format!("rm -rf {}", file);
                    execute_command(&remove_command, true).await;
                }
            }
        }

        // now iterate over files and delete file whose
        let exclude_flags = excluded_folders
            .iter()
            .map(|x| format!("--exclude='{}' ", x))
            .collect::<Vec<String>>()
            .join(" ");
        let cmd = format!(
            "semgrep --config /tmp/sast-rules {} --verbose --json -o /tmp/sast_output.json {}",
            _path, exclude_flags
        );
        execute_command(&cmd, true).await;
        if verbose {
            println!("[+] SAST scan completed!");
        }
        // parse output and show it in terminal
        let is_file_exists = std::path::Path::new("/tmp/sast_output.json").exists();

        if !is_file_exists {
            print_error(
                "Error: SAST Scanner not generated results, please contact support team!",
                101,
            );
        }

        let json_output =
            std::fs::read_to_string("/tmp/sast_output.json").expect("Error reading file");
        let json_output =
            serde_json::from_str::<serde_json::Value>(&json_output.to_string()).unwrap();
        // pick results key from json_output
        let json_output = json_output
            .as_object()
            .unwrap()
            .get("results")
            .unwrap()
            .as_array()
            .unwrap();
        // save data in output.json and before that get json data from output.json file if it exists and then append new data to it
        // output.json data will be in format {"sast":{}, "sca":{}, "secret":{}, "license":{}}
        let mut output_json = json!({});
        if std::path::Path::new("/tmp/output.json").exists() {
            let output_json_data = std::fs::read_to_string("/tmp/output.json").unwrap();
            output_json = serde_json::from_str::<serde_json::Value>(&output_json_data).unwrap();
        }
        output_json["sast"] = serde_json::Value::Array(json_output.clone());

        std::fs::write(
            "/tmp/output.json",
            serde_json::to_string_pretty(&output_json).unwrap(),
        )
        .unwrap();

        let end_time = Instant::now();
        let elapsed_time = end_time - start_time;
        let elapsed_seconds = elapsed_time.as_secs_f64().round();
        println!(
            "Execution time for SAST scan: {:?} seconds",
            elapsed_seconds
        );
    }
}
