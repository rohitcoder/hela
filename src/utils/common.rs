use mongodb::bson::{doc, Document};
use mongodb::{options::ClientOptions, Client};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use std::{collections::HashMap, process::Command};

// define static exit codes and message
pub const EXIT_CODE_LICENSE_FAILED: i32 = 101;
pub const LICENSE_FAILED_MSG: &str = "License scan failed";
pub const EXIT_CODE_SCA_FAILED: i32 = 102;
pub const SCA_FAILED_MSG: &str = "SCA failed";
pub const EXIT_CODE_SAST_FAILED: i32 = 103;
pub const SAST_FAILED_MSG: &str = "SAST failed";
pub const EXIT_CODE_SECRET_FAILED: i32 = 104;
pub const SECRET_FAILED_MSG: &str = "Secret scan failed";

pub fn hash_text(input: &str) -> String {
    // Create a SHA-256 hasher.
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hashed_string = format!("{:x}", hasher.finalize());
    hashed_string
}

pub async fn upload_to_defect_dojo(
    is_new_import: bool,
    token: &str,
    url: &str,
    product_name: &str,
    engagement_name: &str,
    filename: &str,
) -> Result<(), reqwest::Error> {
    let mut file = File::open(filename.clone()).unwrap();

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let client = reqwest::Client::builder()
        // Increase timeout to allow more time for server response
        .timeout(Duration::from_secs(300))
        .pool_max_idle_per_host(0)
        .build()?;
    let product_name = product_name.to_string();
    let engagement_name = engagement_name.to_string();
    let form = reqwest::multipart::Form::new()
        .part(
            "file",
            reqwest::multipart::Part::bytes(buffer).file_name(filename.to_string()),
        )
        .part("scan_type", reqwest::multipart::Part::text("SARIF"))
        .part("product_name", reqwest::multipart::Part::text(product_name))
        .part(
            "engagement_name",
            reqwest::multipart::Part::text(engagement_name),
        );
    let endpoint = if is_new_import {
        "/api/v2/import-scan/"
    } else {
        "/api/v2/reimport-scan/"
    };
    let request = client
        .post(url.to_string() + endpoint)
        .multipart(form)
        .header("Authorization", format!("Token {}", token));

    request.send().await?;
    Ok(())
}

pub async fn slack_alert(url: &str, message: &str) {
    let mut payload = HashMap::new();
    payload.insert("text".to_string(), message.to_string());
    // if document found print, there is already one hash, otherwise post_json_data
    let _ = post_json_data(url, serde_json::to_value(payload).unwrap()).await;
    return;
}

pub async fn check_hash_exists(message: &str, mongo_uri: &str) -> bool {
    let hashed_message = hash_text(message);
    match connect_to_mongodb(mongo_uri, "code-security-open-source").await {
        Ok(client) => match find_message_in_hashes(&client, &hashed_message).await {
            Ok(result) => {
                if result.is_none() {
                    println!("[+] Hash not found in database, adding it...");
                    register_hash(&message, mongo_uri).await;
                    return false;
                } else {
                    println!("[+] Hash found in database, skipping...");
                    return true;
                }
            }
            Err(e) => {
                print_error(&format!("Error: {}", e.to_string()), 101);
                return false;
            }
        },
        Err(e) => {
            print_error(&format!("Error: {}", e.to_string()), 101);
            return false;
        }
    }
}

pub async fn register_hash(message: &str, mongo_uri: &str) {
    let hashed_message = hash_text(message);
    match connect_to_mongodb(mongo_uri, "code-security-open-source").await {
        Ok(client) => {
            let collection = client
                .database("code-security-open-source")
                .collection("hashes");
            let document = doc! { "message": hashed_message };
            collection.insert_one(document, None).await.unwrap();
        }
        Err(e) => {
            print_error(&format!("Error: {}", e.to_string()), 101);
        }
    }
}
pub fn print_error(error: &str, error_code: i32) {
    if error.to_lowercase().starts_with("warning") {
        println!("[❕] {}", error);
    } else {
        println!("[‼️] {}", error);
    }
    if error_code != 101 {
        std::process::exit(error_code);
    }
}

pub fn count_env_variables(input: &str) -> i128 {
    let pattern = Regex::new(r"\$\{([^}]*)\}").unwrap();
    let count = pattern.captures_iter(input).count();
    count as i128
}

pub fn redact_github_token(input: &str) -> String {
    let exploded = input.split("@").collect::<Vec<&str>>();
    let secret = exploded[0].split("/").last().unwrap();
    let redacted_string = input.replace(secret, "********");
    redacted_string
}

async fn connect_to_mongodb(
    mongo_uri: &str,
    db_name: &str,
) -> Result<Client, mongodb::error::Error> {
    let client_options = ClientOptions::parse(mongo_uri).await?;
    let client = Client::with_options(client_options)?;
    Ok(client)
}

async fn find_message_in_hashes(
    client: &Client,
    message: &str,
) -> Result<Option<Document>, mongodb::error::Error> {
    let collection = client
        .database("code-security-open-source")
        .collection("hashes");
    let filter = doc! { "message": message };
    let result = collection.find_one(filter, None).await?;
    Ok(result)
}

pub async fn execute_command(command: &str, suppress_error: bool) -> String {
    let suppress_error = suppress_error || false;
    let exec_name = command.split_whitespace().next().unwrap();
    let exec_args = command.split_whitespace().skip(1).collect::<Vec<&str>>();
    let output;

    if command.contains("&&") {
        output = match Command::new("sh").arg("-c").arg(command).output() {
            Ok(output) => output,
            Err(e) => {
                if !suppress_error {
                    print_error(
                        &format!("Error: {} : {}", &command.to_string(), e.to_string()),
                        101,
                    );
                }
                return "".to_string();
            }
        };
    } else {
        output = match Command::new(exec_name).args(exec_args).output() {
            Ok(output) => output,
            Err(e) => {
                if !suppress_error {
                    print_error(
                        &format!("Error: {} : {}", &command.to_string(), e.to_string()),
                        101,
                    );
                }
                return "".to_string();
            }
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // check if the command executed successfully
    if !stderr.is_empty() {
        if !suppress_error {
            print_error(
                format!("{}: {}", "Error executing process: ", stderr).as_str(),
                101,
            );
        }
    }

    if stdout.is_empty() {
        return stderr.to_string();
    }

    stdout.to_string()
}

pub fn checkout(
    clone_url: &str,
    clone_path: &str,
    commit_ids: Option<&str>,
    branch_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let commit_hashes: Vec<&str> = match commit_ids {
        Some(ids) => ids.split(',').collect(),
        None => vec![],
    };
    let depth = commit_hashes.len() + 1;
    let mut clone_cmd = Command::new("git");
    clone_cmd
        .arg("clone")
        .arg("--depth")
        .arg(depth.to_string())
        .arg(clone_url);
    if let Some(branch) = branch_name {
        clone_cmd.arg("--branch").arg(branch);
    }
    clone_cmd.arg(clone_path);
    let output = clone_cmd.output()?;

    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to clone repository: {}", error_msg).into());
    }

    let cloned_path = Path::new(clone_path).canonicalize()?;
    env::set_current_dir(&cloned_path)?;

    for commit in &commit_hashes {
        let output = Command::new("git")
            .arg("fetch")
            .arg("origin")
            .arg(commit)
            .output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to fetch commit {}: {}", commit, error_msg).into());
        }
    }

    let mut all_files = String::new();
    for commit in commit_hashes {
        let output = Command::new("git")
            .arg("reset")
            .arg("--hard")
            .arg(commit)
            .output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to reset to commit {}: {}", commit, error_msg).into());
        }

        let output = Command::new("git")
            .arg("diff")
            .arg("--name-only")
            .arg(format!("{}^", commit))
            .arg(commit)
            .stdout(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(
                format!("Failed to list files for commit {}: {}", commit, error_msg).into(),
            );
        }

        let files = String::from_utf8_lossy(&output.stdout);
        all_files.push_str(&files);
    }

    println!("FILES\n______\n{}", all_files);

    delete_except(&all_files, &cloned_path)?;

    delete_empty_directories(&cloned_path)?;

    Ok(())
}

fn delete_except(files: &str, base_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let files_to_keep: Vec<PathBuf> = files
        .lines()
        .map(|line| base_dir.join(line.trim()))
        .collect();

    traverse_and_delete(base_dir, &files_to_keep)?;

    Ok(())
}

fn traverse_and_delete(base_dir: &Path, files_to_keep: &[PathBuf]) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(base_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            traverse_and_delete(&path, files_to_keep)?;
        }

        // Check if the path should be deleted (only delete files)
        if path.is_file() && !files_to_keep.contains(&path.canonicalize()?) {
            fs::remove_file(&path)?;
        }
    }

    Ok(())
}

fn delete_empty_directories(start_dir: &Path) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(start_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            delete_empty_directories(&path)?;
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(&path)?;
            }
        }
    }

    Ok(())
}

pub async fn post_json_data(url: &str, json_data: Value) -> HashMap<String, String> {
    if !url.starts_with("http") {
        return HashMap::new();
    }
    let client = reqwest::Client::new();
    let mut _headers = reqwest::header::HeaderMap::new();
    _headers.insert("Content-Type", "application/json".parse().unwrap());
    let response = match client
        .post(url)
        .headers(_headers)
        .body(json_data.to_string())
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            print_error(
                format!("Error for request url {}: {}", url, e.to_string()).as_str(),
                101,
            );
            return HashMap::new();
        }
    };
    let mut reply = HashMap::new();
    reply.insert("status".to_string(), response.status().to_string());
    reply.insert("url".to_string(), url.to_string());
    reply.insert("body".to_string(), response.text().await.unwrap());
    reply
}
