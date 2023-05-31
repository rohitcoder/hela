mod scans;
mod utils;
mod api;

use std::{env, process::exit};
use scans::scanner::ScanRunner;
use crate::scans::tools::{sast_tool::SastTool, sca_tool::ScaTool, secret_tool::SecretTool, license_tool::LicenseTool};
use actix_web::{App, HttpServer};
use dotenv::dotenv;

fn execute_scan(scan_type: &str, path: &str) {
    let scanner = ScanRunner::new(
        SastTool::new(),
        ScaTool::new(),
        SecretTool::new(),
        LicenseTool::new(),
    );

    scanner.execute_scan(scan_type, path);
}

#[actix_web::main]
async fn start_server() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .configure(api::scan::config)
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}

fn main() {
    dotenv().ok();
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Please provide a command.");
        return;
    }

    let command = &args[1];

    match command.as_str() {
        "start-server" => {
            println!("Starting API server...");
            if let Err(err) = start_server() {
                println!("Failed to start API server: {}", err);
                exit(1)
            }
            println!("API server started successfully!");
        }
        "sast" | "sca" | "secret" | "license-compliance" => {
            if args.len() < 3 {
                println!("Please provide target for the provided scan type.");
                return;
            }
            let scan_type = &args[1];
            let path = &args[2];
            execute_scan(scan_type, path);
        }
        _ => println!("Invalid command. Available commands: start-server, sast, sca, secret, license-compliance"),
    }
}
