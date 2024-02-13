mod scans;
mod utils;



use scans::scanner::ScanRunner;
use utils::pipeline;
use crate::scans::tools::{sast_tool::SastTool, sca_tool::ScaTool, secret_tool::SecretTool, license_tool::LicenseTool};
use argparse::{ArgumentParser, StoreTrue, Store};

async fn execute_scan(scan_type: &str, path: &str, commit_id: Option<&str>, branch: Option<&str>, server_url: Option<&str>, no_install:bool, root_only: bool, build_args: String,  manifests: String, rule_path: String, verbose: bool) {
    let scanner = ScanRunner::new(
        SastTool::new(),
        ScaTool::new(),
        SecretTool::new(),
        LicenseTool::new(),
    );

    scanner.execute_scan(scan_type, path, commit_id, branch, server_url, no_install, root_only, build_args, manifests, rule_path.clone(), verbose).await;
}

#[actix_web::main]
async fn main() {
    // Parse command-line arguments
    let mut no_install = false;
    let mut root_only = false;
    let mut is_sast = false;
    let mut is_sca = false;
    let mut is_secret = false;
    let mut is_license_compliance = false;
    let mut verbose = false;
    let mut path = String::new();
    let mut rule_path = String::new();
    let mut commit_id = String::new();
    let mut server_url = String::new();
    let mut branch = String::new();
    let mut policy_url = String::new();
    let mut build_args = String::new();
    let mut manifests = String::new();
    let mut json = false;
    let mut slack_url = String::new();
    let mut mongo_uri = String::new();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Scan CLI tool");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "Enable verbose mode!");
        ap.refer(&mut path)
            .add_option(&["-p", "--code-path"], Store, "Pass the path of the project to scan (Local Path or HTTP Git URL)");
        ap.refer(&mut rule_path)
            .add_option(&["-t", "--rule-path"], Store, "Pass the path of the rules to use (Local Path or HTTP Git URL)");
        ap.refer(&mut commit_id)
            .add_option(&["-i", "--commit-id"], Store, "Pass the commit ID to scan (Optional)");
        ap.refer(&mut branch)
            .add_option(&["-b", "--branch"], Store, "Pass the branch name to scan (Optional)");
        ap.refer(&mut is_sast)
            .add_option(&["-s", "--sast"], StoreTrue, "Run SAST scan");
        ap.refer(&mut server_url)
            .add_option(&["-u", "--server-url"], Store, "Pass the server URL to post scan results");
        ap.refer(&mut is_sca)
            .add_option(&["-c", "--sca"], StoreTrue, "Run SCA scan");
        ap.refer(&mut is_secret)
            .add_option(&["-e", "--secret"], StoreTrue, "Run Secret scan");
        ap.refer(&mut is_license_compliance)
            .add_option(&["-l", "--license-compliance"], StoreTrue, "Run License Compliance scan");
        ap.refer(&mut json)
            .add_option(&["-j", "--json"], StoreTrue, "Print JSON output, Note: This won't work with pipeline check implementation");
        ap.refer(&mut policy_url)
            .add_option(&["-y", "--policy-url"], Store, "Pass the policy url to check if pipeline should fail");
        ap.refer(&mut no_install)
            .add_option(&["-n", "--no-install"], StoreTrue, "Skip installing dependencies");
        ap.refer(&mut root_only)
            .add_option(&["-r", "--root-only"], StoreTrue, "Scan manifests only in the root directory, don't look for manifests in subdirectories");
        ap.refer(&mut build_args)
            .add_option(&["-d", "--build-args"], Store, "Pass the build context args to scan");
        ap.refer(&mut manifests)
            .add_option(&["-m", "--manifests"], Store, "Pass the manifests pom.xml, requirements.txt etc to scan and we will look for only that kind of manifests");
        ap.refer(&mut slack_url)
            .add_option(&["-k", "--slack-url"], Store, "Pass the slack url to receive scan alerts");
        ap.refer(&mut mongo_uri)
            .add_option(&["-o", "--mongo-uri"], Store, "Pass the mongo uri to store scan results");
        ap.parse_args_or_exit();
    }

    if verbose {
        println!("[+] Verbose mode enabled!");
    }
    if mongo_uri != "" {
        println!("dbConnection");
    }else{
        println!("No mongo uri provided");
    }
    if is_sast {
        execute_scan("sast", &path, if commit_id.is_empty() { None } else { Some(&commit_id) },  if branch.is_empty() { None } else { Some(&branch) }, if server_url.is_empty() { None } else { Some(&server_url) }, no_install, root_only, build_args.clone(),  manifests.clone(), rule_path.clone(), verbose).await;
    }

    if is_sca {
        execute_scan("sca", &path, if commit_id.is_empty() { None } else { Some(&commit_id) }, if branch.is_empty() { None } else { Some(&branch) }, if server_url.is_empty() { None } else { Some(&server_url) }, no_install, root_only,  build_args.clone(), manifests.clone(), rule_path.clone(), verbose).await;
    }

    if is_secret {
        execute_scan("secret", &path, if commit_id.is_empty() { None } else { Some(&commit_id) }, if branch.is_empty() { None } else { Some(&branch) }, if server_url.is_empty() { None } else { Some(&server_url) },no_install, root_only,  build_args.clone(),  manifests.clone(), rule_path.clone(), verbose).await;
    }

    if is_license_compliance {
        execute_scan("license-compliance", &path, if commit_id.is_empty() { None } else { Some(&commit_id) }, if branch.is_empty() { None } else { Some(&branch) }, if server_url.is_empty() { None } else { Some(&server_url) }, no_install, root_only,  build_args.clone(),  manifests.clone(), rule_path.clone(), verbose).await;
    }

    if !is_sast && !is_sca && !is_secret && !is_license_compliance {
        println!("Invalid command. Available commands: sast, sca, secret, license-compliance");
    }

    if json {
        if std::path::Path::new("/tmp/output.json").exists() {
            let output = std::fs::read_to_string("/tmp/output.json").unwrap();
            println!("{}", output);
        }
    }else {
        pipeline::pipeline_failure(path.clone(), is_sast, is_sca, is_secret, is_license_compliance, policy_url, slack_url, commit_id, mongo_uri).await;
    }
}
