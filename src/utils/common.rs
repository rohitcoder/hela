use bson::to_bson;

use futures::StreamExt;
use mongodb::{
    bson::{doc, Bson, Document},
    error::Error,
    options::{ClientOptions, FindOptions},
    Client, Collection,
};

use chrono::Utc;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use std::{collections::HashMap, process::Command};
use std::{collections::HashSet, env};

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

pub async fn bulk_check_hash_exists(
    hashes: &[String],
    mongo_uri: &str,
) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let client = connect_to_mongodb(mongo_uri, "code-security-open-source").await?;
    let existing_hashes = find_messages_in_hashes(&client, hashes).await?;
    Ok(existing_hashes)
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

pub async fn find_messages_in_hashes(
    client: &Client,
    hashes: &[String],
) -> Result<HashSet<String>, mongodb::error::Error> {
    let collection: Collection<Document> = client
        .database("code-security-open-source")
        .collection("hashes");

    // Create the filter to match any of the hashes
    let filter = doc! { "hash": { "$in": hashes } };

    // Query the database
    let mut cursor = collection.find(filter, None).await?;
    let mut existing_hashes = HashSet::new();

    while let Some(doc) = cursor.next().await {
        match doc {
            Ok(document) => {
                if let Some(hash) = document.get_str("hash").ok() {
                    existing_hashes.insert(hash.to_string());
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(existing_hashes)
}

pub async fn insert_job_info(
    mongo_uri: &str,
    job_id: &str,
    msg: &str,
    status: &i32,
    results: Vec<Value>,
) -> Result<(), Error> {
    // Connect to MongoDB
    let client = connect_to_mongodb(mongo_uri, "code-security-open-source").await?;

    // Get the collection
    let collection = client
        .database("code-security-open-source")
        .collection("jobs");

    // Convert serde_json::Value to Bson
    let bson_results: Vec<Bson> = results
        .into_iter()
        .map(|v| to_bson(&v).unwrap_or(Bson::Null))
        .collect();
    // Create the document to insert
    let document = doc! {
        "job_id": job_id,
        "message": msg,
        "status": status,
        "result": bson_results,
        "created_at": Utc::now().to_rfc3339(),
    };

    // Insert the document into the collection
    collection.insert_one(document, None).await?;

    Ok(())
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

fn save_commit_map(
    file_commit_map: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let commit_map_path = "/tmp/commit_map.json";
    let file = File::create(commit_map_path)?;
    serde_json::to_writer(file, file_commit_map)?;
    println!("Commit map saved to: {}", commit_map_path);
    Ok(())
}

fn delete_except(files: &str, base_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Deleting all files except the following:");
    println!("__________________________________________ {:?}", files);
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

        // Skip the .git directory
        if path.is_dir() && path.file_name().map_or(false, |name| name == ".git") {
            continue;
        }

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

        // Skip the .git directory
        if path.is_dir() && path.file_name().map_or(false, |name| name == ".git") {
            continue;
        }

        if path.is_dir() {
            delete_empty_directories(&path)?;
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(&path)?;
            }
        }
    }

    Ok(())
}

fn get_cumulative_pr_files(
    base_branch: Option<&str>,
    pr_branch: Option<&str>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if let Some(base) = base_branch {
        // Step 1: Create and checkout a temporary branch from the base branch
        Command::new("git").args(&["checkout", base]).output()?;
        Command::new("git")
            .args(&["checkout", "-b", "temp_pr_merge_branch"])
            .output()?;

        if let Some(pr) = pr_branch {
            // Step 2: Merge the PR branch without fast-forwarding
            let merge_output = Command::new("git")
                .args(&["merge", "--no-ff", pr])
                .output()?;
            if !merge_output.status.success() {
                let error_msg = String::from_utf8_lossy(&merge_output.stderr);
                return Err(format!("Failed to merge PR branch: {}", error_msg).into());
            }

            // Step 3: Get the list of changed files in the cumulative diff
            let output = Command::new("git")
                .args(&["diff", "--name-only", base, "temp_pr_merge_branch"])
                .output()?;
            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                return Err(format!("Failed to get cumulative PR files: {}", error_msg).into());
            }

            let files = String::from_utf8_lossy(&output.stdout);
            let file_names = files.lines().map(String::from).collect();

            // Cleanup: Delete the temporary branch
            Command::new("git").args(&["checkout", base]).output()?;
            Command::new("git")
                .args(&["branch", "-D", "temp_pr_merge_branch"])
                .output()?;

            Ok(file_names)
        } else {
            Err("PR branch is required when base branch is specified.".into())
        }
    } else {
        Err("Base branch is required.".into())
    }
}

pub fn checkout(
    clone_url: &str,
    clone_path: &str,
    branch: Option<&str>,
    pr_branch: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Clone the repository; use the specified branch or default branch if `branch` is None
    let mut clone_cmd = Command::new("git");
    clone_cmd.arg("clone").arg(clone_url).arg(clone_path);
    if let Some(branch_name) = branch {
        clone_cmd.arg("--branch").arg(branch_name);
    }
    let output = clone_cmd.output()?;
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to clone repository: {}", error_msg).into());
    }

    // Set the working directory to the cloned path
    let cloned_path = Path::new(clone_path).canonicalize()?;
    env::set_current_dir(&cloned_path)?;

    // Configure Git user for commits in this repository
    Command::new("git")
        .args(&["config", "user.email", "ci@hela.int"])
        .output()?;
    Command::new("git")
        .args(&["config", "user.name", "CI Bot"])
        .output()?;

    // If a pr_branch is provided, fetch it as a local branch and compare with the base branch
    if let Some(pr_branch_name) = pr_branch {
        // Fetch the PR branch and create a local branch
        let fetch_output = Command::new("git")
            .args(&[
                "fetch",
                "origin",
                &format!("{}:{}", pr_branch_name, pr_branch_name),
            ])
            .output()?;
        if !fetch_output.status.success() {
            let error_msg = String::from_utf8_lossy(&fetch_output.stderr);
            return Err(format!(
                "Failed to fetch PR branch '{}': {}",
                pr_branch_name, error_msg
            )
            .into());
        }

        // Perform a diff between `branch` (or the default branch) and `pr_branch`
        let base_branch = branch.unwrap_or("HEAD");
        let diff_output = Command::new("git")
            .args(&["diff", "--name-only", base_branch, pr_branch_name])
            .output()?;

        if !diff_output.status.success() {
            let error_msg = String::from_utf8_lossy(&diff_output.stderr);
            return Err(format!("Failed to diff branches: {}", error_msg).into());
        }

        // Parse the diff output
        let changed_files = String::from_utf8_lossy(&diff_output.stdout)
            .lines()
            .map(String::from)
            .collect::<Vec<String>>();

        println!(
            "Changed files in PR branch '{}': {:?}",
            pr_branch_name, changed_files
        );
    } else {
        // If no PR branch, list all files in the base branch
        let list_output = Command::new("git")
            .args(&["ls-tree", "-r", "--name-only", "HEAD"])
            .output()?;

        if !list_output.status.success() {
            let error_msg = String::from_utf8_lossy(&list_output.stderr);
            return Err(format!("Failed to list files in base branch: {}", error_msg).into());
        }

        let files = String::from_utf8_lossy(&list_output.stdout)
            .lines()
            .map(String::from)
            .collect::<Vec<String>>();

        println!(
            "Files in branch '{}': {:?}",
            branch.unwrap_or("default branch"),
            files
        );
    }

    Ok(())
}

pub fn find_commit_for_snippet(
    file_path: &str,
    code_snippet: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let repo_dir = "/tmp/app";
    // Ensure the repo directory exists
    let repo_path = Path::new(repo_dir);
    if !repo_path.exists() {
        return Err(format!("Repository directory '{}' does not exist", repo_dir).into());
    }

    // Run `git log` command from within the repository directory
    let output = Command::new("git")
        .args(&["log", "-p", "--pretty=format:%H", "--", file_path])
        .current_dir(repo_path) // Set the working directory to the repo directory
        .output()?;

    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to get log for file '{}': {}", file_path, error_msg).into());
    }

    // Parse the output to find the commit with the code snippet
    let log_output = String::from_utf8_lossy(&output.stdout);
    let mut commit_id = None;

    // Split the log output by commit
    for commit in log_output.split("commit ") {
        if let Some(commit_hash) = commit.lines().next() {
            // Check if the commit contains the code snippet
            if commit.contains(code_snippet) {
                commit_id = Some(commit_hash.to_string());
                break;
            }
        }
    }

    Ok(commit_id)
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
