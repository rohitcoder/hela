mod scans;
mod utils;

use std::env;
use scans::scanner::ScanRunner;
use crate::scans::tools::{sast_tool::SastTool, sca_tool::ScaTool, secret_tool::SecretTool, license_tool::LicenseTool};

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Please provide a scan type as an argument.");
        return;
    }

    if args.len() < 3 {
        println!("Please provide target for provided scan type.");
        return;
    }

    // Initialize the scanner
    let scanner = ScanRunner::new(
        SastTool::new(),
        ScaTool::new(),
        SecretTool::new(),
        LicenseTool::new(),
    );

    // Execute the requested scan
    let scan_type = &args[1];
    let path = &args[2];
    scanner.execute_scan(scan_type, path);
}
