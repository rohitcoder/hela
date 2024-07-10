use std::{collections::HashMap, time::Instant};

use mongodb::bson::uuid;
use serde_json::json;

use crate::{
    scans::tools::sca_tool::SUPPORTED_MANIFESTS,
    utils::{
        common::{checkout, execute_command, post_json_data},
        file_utils::find_files_recursively,
    },
};

pub struct LicenseTool;

impl LicenseTool {
    pub fn new() -> Self {
        LicenseTool
    }

    pub async fn run_scan(
        &self,
        _path: &str,
        _commit_id: Option<&str>,
        _branch: Option<&str>,
        verbose: bool,
    ) {
        let start_time = Instant::now();
        if verbose {
            println!("[+] Running License compliance scan on path: {}", _path);
        }
        let mut ignore_dirs = Vec::new();
        ignore_dirs.push("node_modules");
        ignore_dirs.push("bin");
        ignore_dirs.push("venv");
        ignore_dirs.push(".venv");

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
        let manifests =
            find_files_recursively(&_path, unsafe { SUPPORTED_MANIFESTS.to_vec() }, ignore_dirs)
                .await;
        let mut manifest_license = HashMap::new();
        for manifest in manifests.iter() {
            let file_name = manifest.split("/").last().unwrap();
            let folder_path = manifest.replace(file_name, "");
            let random_file_name = format!("{}.json", uuid::Uuid::new().to_string());
            // if manifest ends with pom.xml then pass -t java otherwise nothing
            let mut license_command =
                format!("cd {} && cdxgen -o {}", folder_path, random_file_name);
            if file_name.ends_with("pom.xml") {
                license_command = format!(
                    "cd {} && cdxgen -o {} -t java",
                    folder_path, random_file_name
                );
            }
            execute_command(&license_command, false).await;
            // Read JSON file and parse data
            let license_json =
                std::fs::read_to_string(format!("{}/{}", folder_path, random_file_name)).unwrap();
            let json_data = serde_json::from_str::<serde_json::Value>(&license_json).unwrap();
            // extract license data from "components" key there will be list of components so grab licenses from there
            let components = json_data["components"].as_array().unwrap();
            let mut component_licenses: HashMap<String, Vec<String>> = HashMap::new();
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
                component_licenses.insert(
                    format!("{}@{}", component_name, component_version),
                    license_names,
                );
                manifest_license.insert(
                    format!("{}/{}", folder_path, file_name),
                    component_licenses.clone(),
                );
            }
        }
        // save data in output.json and before that get json data from output.json file if it exists and then append new data to it
        // output.json data will be in format {"sast":{}, "sca":{}, "secret":{}, "license":{}}
        let mut output_json = json!({});
        if std::path::Path::new("/tmp/output.json").exists() {
            let output_json_data = std::fs::read_to_string("/tmp/output.json").unwrap();
            output_json = serde_json::from_str::<serde_json::Value>(&output_json_data).unwrap();
        }
        output_json["license"] = json!(manifest_license);
        std::fs::write(
            "/tmp/output.json",
            serde_json::to_string_pretty(&output_json).unwrap(),
        )
        .unwrap();
        let end_time = Instant::now();
        let elapsed_time = end_time - start_time;
        let elapsed_seconds = elapsed_time.as_secs_f64().round();
        println!(
            "Execution time for License Compliance scan: {:?} seconds",
            elapsed_seconds
        );
    }
}
