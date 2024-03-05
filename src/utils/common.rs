use std::{collections::HashMap, process::Command};
use serde_json::Value;
use regex::Regex;
use mongodb::{options::ClientOptions, Client};
use mongodb::bson::{doc, Document};
use sha2::{Digest, Sha256};

// define static exit codes and message
pub const EXIT_CODE_LICENSE_FAILED: i32 = 101;
pub const LICENSE_FAILED_MSG: &str = "License scan failed";
pub const EXIT_CODE_SCA_FAILED: i32 = 102;
pub const SCA_FAILED_MSG: &str = "SCA failed";
pub const EXIT_CODE_SAST_FAILED: i32 = 103;
pub const SAST_FAILED_MSG: &str = "SAST failed";
pub const EXIT_CODE_SECRET_FAILED: i32 = 104;
pub const SECRET_FAILED_MSG: &str = "Secret scan failed";

fn hash_text(input: &str) -> String {
    // Create a SHA-256 hasher.
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hashed_string = format!("{:x}", hasher.finalize());
    hashed_string
}

pub async fn slack_alert(url: &str, message: &str, mongo_uri: &str) {
    let mut payload = HashMap::new();
    payload.insert("text".to_string(), message.to_string());
    // if document found print, there is already one hash, otherwise post_json_data
    let hashed_message = hash_text(message);
    if mongo_uri == "" {
        let _ = post_json_data(url, serde_json::to_value(payload).unwrap()).await;
        return;
    }
    match connect_to_mongodb(mongo_uri, "code-security-open-source").await {
        Ok(client) => {
            match find_message_in_hashes(&client, &hashed_message).await {
                Ok(result) => {
                    if result.is_none() {
                        let _ = post_json_data(url, serde_json::to_value(payload).unwrap()).await;
                        let collection = client.database("code-security-open-source").collection("hashes");
                        let document = doc! { "message": hashed_message };
                        collection.insert_one(document, None).await.unwrap();
                    }else{
                        println!("[❕] Alert already sent for this message");
                    }
                },
                Err(e) => {
                    print_error(&format!("Error: {}", e.to_string()), 101);
                }
            }
        },
        Err(e) => {
            print_error(&format!("Error: {}", e.to_string()), 101);
        }
    }
}

pub fn print_error(error: &str, error_code: i32) {
    if error.to_lowercase().starts_with("warning") {
        println!("[❕] {}", error);
    }else{
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

async fn connect_to_mongodb(mongo_uri: &str, db_name: &str) -> Result<Client, mongodb::error::Error> {
    let client_options = ClientOptions::parse(mongo_uri).await?;
    let client = Client::with_options(client_options)?;
    Ok(client)
}

async fn find_message_in_hashes(client: &Client, message: &str) -> Result<Option<Document>, mongodb::error::Error> {
    let collection = client.database("code-security-open-source").collection("hashes");
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
        output = match Command::new("sh")
            .arg("-c")
            .arg(command)
            .output() {
                Ok(output) => output,
                Err(e) => {
                    if !suppress_error {
                        println!("{:?}", e.to_string());
                        print_error(&format!("Error: {} : {}", &command.to_string(), e.to_string()), 101);
                    }
                    return "".to_string();
                }
            };
    } else {
        output = match Command::new(exec_name).args(exec_args).output() {
            Ok(output) => output,
            Err(e) => {
                if !suppress_error {
                    println!("{:?}", e.to_string());
                    print_error(&format!("Error: {} : {}", &command.to_string(), e.to_string()), 101);
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
            print_error(format!("{}: {}", "Error executing process: ", stderr).as_str(), 101);
        }
    }
    
    if stdout.is_empty() {
        return stderr.to_string();
    }
    
    stdout.to_string()
}

pub async fn post_json_data(url: &str, json_data: Value) -> HashMap<String, String> {
    if !url.starts_with("http") {
        return HashMap::new();
    }
    let client = reqwest::Client::new();
    let mut _headers = reqwest::header::HeaderMap::new();
    _headers.insert("Content-Type", "application/json".parse().unwrap());
    let response = match client.post(url).headers(_headers).body(json_data.to_string()).send().await {
        Ok(response) => response,
        Err(e) => {
            print_error(format!("Error for request url {}: {}", url, e.to_string()).as_str(), 101);
            return HashMap::new();
        }
    };
    let mut reply = HashMap::new();
    reply.insert("status".to_string(), response.status().to_string());
    reply.insert("url".to_string(), url.to_string());
    reply.insert("body".to_string(), response.text().await.unwrap());
    reply
}