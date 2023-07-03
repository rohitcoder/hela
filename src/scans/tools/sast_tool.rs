use serde_json::json;

use crate::utils::common::{execute_command, print_error, post_json_data};

pub struct SastTool;

impl SastTool {
    pub fn new() -> Self {
        SastTool
    }

    pub async fn run_scan(&self, _path: &str, _commit_id: Option<&str>, _branch: Option<&str>, _server_url: Option<&str>) {
        println!("Running SAST scan on path: {}", _path);
        if !std::path::Path::new("/tmp/app").exists() {
            if _path.starts_with("http") {
                println!("Cloning git repo...");
                if let Some(_branch) = _branch {
                    let clone_command = format!("git clone -b {} {} /tmp/app", _branch, _path);
                    execute_command(&clone_command, true).await;
                }else{
                    let clone_command = format!("git clone {} /tmp/app", _path);
                    execute_command(&clone_command, true).await;
                }
            }else{
                println!("Copying project to /tmp/app...");
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
            println!("Checking out to commit id: {}", commit_id);
            let checkout_command = format!("cd {} && git checkout {}", _path, commit_id);
            execute_command(&checkout_command, true).await;

            let copy_command = format!("mkdir -p /tmp/new_code");
            execute_command(&copy_command, true).await;
            let copy_command = format!("cd {} && git diff-tree --no-commit-id --name-only -r {} | xargs -I {{}} git ls-tree --name-only {} {{}} | xargs git archive --format=tar {} | tar -x -C /tmp/new_code", _path, commit_id, commit_id, commit_id);
            execute_command(&copy_command, true).await;
            // now run secret scan on /tmp/new_code folder
            _path = format!("/tmp/new_code");
        }

        // clone repo https://github.com/rohitcodergroww/semgrep-rules to /tmp/sast-rules
        if !std::path::Path::new("/tmp/sast-rules").exists() {
            println!("Cloning sast-rules repo...");
            let clone_command = format!("git clone {} /tmp/sast-rules", "https://github.com/rohitcodergroww/semgrep-rules");
            execute_command(&clone_command, true).await;
        }

        // Lets RUN SAST SCAN using let cmd = format!("semgrep --config {}/sast-rules {} {} {} --verbose --metrics off --max-target-bytes 1000000 --json -o {}/sast_output.json", tmp_folder, folder_path, exclude_flags, exclude_rules, tmp_folder);
        let cmd = format!("semgrep --config /tmp/sast-rules {} --verbose --json -o /tmp/sast_output.json", _path);
        execute_command(&cmd, true).await;
        // parse output and show it in terminal
        let is_file_exists = std::path::Path::new("/tmp/sast_output.json").exists();
       
        if !is_file_exists {
            print_error("Error: SAST Scanner not generated results, please contact support team!", 101);
        }

        let json_output = std::fs::read_to_string("/tmp/sast_output.json").expect("Error reading file");
        let json_output: serde_json::Value = serde_json::from_str(&json_output).expect("Error parsing JSON");
        println!("SAST Scanner Results:");
        let json_output = json!(json_output);
        let post_link = format!("{}/sast", _server_url.unwrap_or("https://eol9ssu6pz3y2ju.m.pipedream.net"));
        let post_data = post_json_data(&post_link, json_output).await;
        if post_data.get("status").unwrap() == "200 OK" {
            println!("Successfully posted SAST scan data to server!");
        }else{
            println!("Error while posting SAST scan data to server!");
        }
        
    }
}
