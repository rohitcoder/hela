mod scans;
mod utils;
mod api;

use std::{env, process::exit};
use scans::scanner::ScanRunner;
use crate::scans::tools::{sast_tool::SastTool, sca_tool::ScaTool, secret_tool::SecretTool, license_tool::LicenseTool};
use actix_web::{App, HttpServer};
use dotenv::dotenv;
use argparse::{ArgumentParser, StoreTrue, Store};

async fn execute_scan(scan_type: &str, path: &str, commit_id: Option<&str>) {
    let scanner = ScanRunner::new(
        SastTool::new(),
        ScaTool::new(),
        SecretTool::new(),
        LicenseTool::new(),
    );

    scanner.execute_scan(scan_type, path, commit_id).await;
}

async fn start_server() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .configure(api::scan::config)
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}

#[actix_web::main]
async fn main() {
    dotenv().ok();
    // Parse command-line arguments
    let mut is_sast = false;
    let mut is_sca = false;
    let mut is_secret = false;
    let mut is_license_compliance = false;
    let mut is_start_server = false;
    let mut verbose = false;
    let mut path = String::new();
    let mut commit_id = String::new();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Scan CLI tool");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "Enable verbose mode!");
        ap.refer(&mut path)
            .add_option(&["-p", "--path"], Store, "Pass the path of the project to scan (Local Path or HTTP Git URL)");
        ap.refer(&mut commit_id)
            .add_option(&["-i", "--commit-id"], Store, "Pass the commit ID to scan (Optional)");
        ap.refer(&mut is_sast)
            .add_option(&["-s", "--sast"], StoreTrue, "Run SAST scan");
        ap.refer(&mut is_sca)
            .add_option(&["-c", "--sca"], StoreTrue, "Run SCA scan");
        ap.refer(&mut is_secret)
            .add_option(&["-e", "--secret"], StoreTrue, "Run Secret scan");
        ap.refer(&mut is_license_compliance)
            .add_option(&["-l", "--license-compliance"], StoreTrue, "Run License Compliance scan");
        ap.refer(&mut is_start_server)
            .add_option(&["-a", "--start-server"], StoreTrue, "Start API server");
        ap.parse_args_or_exit();
    }

    if verbose {
        println!("Verbose mode enabled!");
    }

    if is_start_server {
        println!("Starting API server...");
        if let Err(err) = start_server().await {
            println!("Failed to start API server: {}", err);
            exit(1)
        }
        println!("API server started successfully!");
    }

    if is_sast {
        execute_scan("sast", &path, if commit_id.is_empty() { None } else { Some(&commit_id) }).await;
    }

    if is_sca {
        execute_scan("sca", &path, if commit_id.is_empty() { None } else { Some(&commit_id) }).await;
    }

    if is_secret {
        execute_scan("secret", &path, if commit_id.is_empty() { None } else { Some(&commit_id) }).await;
    }

    if is_license_compliance {
        execute_scan("license-compliance", &path, if commit_id.is_empty() { None } else { Some(&commit_id) }).await;
    }

    if !is_start_server && !is_sast && !is_sca && !is_secret && !is_license_compliance {
        println!("Invalid command. Available commands: start-server, sast, sca, secret, license-compliance");
    }
}
