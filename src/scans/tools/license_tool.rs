use std::{collections::HashMap, hash::Hash};

use mongodb::bson::uuid;
use serde_json::json;

use crate::{utils::{common::{execute_command, post_json_data}, file_utils::find_files_recursively}, scans::tools::sca_tool::SUPPORTED_MANIFESTS};

use super::sca_tool::DETECT_MANIFESTS;

pub struct LicenseTool;

impl LicenseTool {
    pub fn new() -> Self {
        LicenseTool
    }
    
    pub async fn run_scan(&self, _path: &str, _commit_id: Option<&str>, _branch: Option<&str>, _server_url: Option<&str>) {
        println!("Running License compliance scan on path: {}", _path);
        
        let mut ignore_dirs = Vec::new();
        ignore_dirs.push("node_modules");
        ignore_dirs.push("bin");
        ignore_dirs.push("venv");
        ignore_dirs.push(".venv");

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
        let mut _path = format!("/tmp/app");
        if let Some(commit_id) = _commit_id {
            let checkout_command = format!("cd {} && git checkout {}", _path, commit_id);
            execute_command(&checkout_command, true).await;

            let copy_command = format!("mkdir -p /tmp/new_code");
            execute_command(&copy_command, true).await;
            let copy_command = format!("cd {} && git diff-tree --no-commit-id --name-only -r {} | xargs -I {{}} git ls-tree --name-only {} {{}} | xargs git archive --format=tar {} | tar -x -C /tmp/new_code", _path, commit_id, commit_id, commit_id);
            execute_command(&copy_command, true).await;
            // now run secret scan on /tmp/new_code folder
            _path = format!("/tmp/new_code");
        }
        
        let manifests = find_files_recursively(&_path, SUPPORTED_MANIFESTS.to_vec(), ignore_dirs).await;
        //println!("Found manifests: {:?}", manifests);
        for manifest in manifests.iter() {
            let file_name = manifest.split("/").last().unwrap();
            let folder_path = manifest.replace(file_name, "");
            let random_file_name = format!("{}.json", uuid::Uuid::new().to_string());
            let license_command = format!("cd {} && cdxgen -o {}", folder_path, random_file_name);
            execute_command(&license_command, true).await;
            // Read JSON file and parse data
            let license_json = std::fs::read_to_string(format!("{}/{}", folder_path, random_file_name)).unwrap();
            let json_data = serde_json::from_str::<serde_json::Value>(&license_json).unwrap();
            // extract license data from "components" key there will be list of components so grab licenses from there
            let components = json_data["components"].as_array().unwrap();
            let mut component_licenses = HashMap::new();
            for component in components.iter() {
                let component_name = component["name"].as_str().unwrap();
                let component_version = component["version"].as_str().unwrap();
                let licenses = component["licenses"].as_array().unwrap();
                let mut license_names = Vec::new();
                for license in licenses.iter() {
                    let license = license["license"].as_object().unwrap();
                    if license.contains_key("id") {
                        license_names.push(license["id"].as_str().unwrap().to_string());
                    }
                }
                component_licenses.insert(format!("{}@{}", component_name, component_version), license_names);
            }
            let post_link = format!("{}/license_data", _server_url.unwrap_or("https://eol9ssu6pz3y2ju.m.pipedream.net"));
            let post_data = post_json_data(&post_link, json!(component_licenses)).await;
            if post_data.get("status").unwrap() == "200 OK" {
                println!("Successfully posted SCA scan data to server!");
            }else{
                println!("Error while posting SCA scan data to server!");
            }
        }
    }
}