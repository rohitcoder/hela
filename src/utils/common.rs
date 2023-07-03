use std::collections::HashMap;
use std::{process::Command, os::unix::process::ExitStatusExt};
use futures::StreamExt;
use reqwest::Client;
use reqwest::header::HeaderMap;
use serde_json::Value;

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
                    print_error(&format!("Error: {} : {}", &command.to_string(), e.to_string()), 101);
                }
                return "".to_string();
            }
        };
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = &output.status;
    
    if !stderr.is_empty() && status != &std::process::ExitStatus::from_raw(0) {
        if !suppress_error {
            println!("For command: {}", command);
            print_error(format!("{}: {}", "Error executing process: ", stderr).as_str(), 101);
        }
    }
    
    if stdout.is_empty() {
        return stderr.to_string();
    }
    
    stdout.to_string()
}


pub async fn http_get_request(url: &str) -> HashMap<String, String> {
    //println!("{} {}", "Requesting: ".green(), url);
    let client = reqwest::Client::new();
    let mut _headers = reqwest::header::HeaderMap::new();
    _headers.insert("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36".parse().unwrap());
    let response = match client.get(url).headers(_headers).send().await {
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

pub async fn send_parallel_requests(urls: Vec<&str>, limit: usize) -> Vec<HashMap<String, String>> {
    let mut futures = vec![];
    for url in urls {
        let resp = http_get_request(url);
        futures.push(resp);
    }
    let responses = futures::stream::iter(futures)
        .buffer_unordered(limit)
        .collect::<Vec<_>>()
        .await;
    responses
}

pub async fn post_json_data(url: &str, json_data: Value) -> HashMap<String, String> {
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