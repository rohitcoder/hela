use crate::scans::tools::{sast_tool::SastTool, sca_tool::ScaTool, secret_tool::SecretTool, license_tool::LicenseTool};

pub struct ScanRunner {
    sast_tool: SastTool,
    sca_tool: ScaTool,
    secret_tool: SecretTool,
    license_tool: LicenseTool,
}

impl ScanRunner {
    pub fn new(sast_tool: SastTool, sca_tool: ScaTool, secret_tool: SecretTool, license_tool: LicenseTool) -> Self {
        ScanRunner {
            sast_tool,
            sca_tool,
            secret_tool,
            license_tool,
        }
    }

    pub async fn execute_scan(&self, scan_type: &str, path: &str, commit_id: Option<&str>, branch: Option<&str>, no_install: bool, root_only:bool, build_args:String, manifests: String, rule_path: String, verbose: bool) {
        if verbose {

            if let Some(commit_id) = commit_id {
                println!("Commit ID: {}", commit_id);
            }else {
                println!("Commit ID: None");
            }
        }
        match scan_type {
            "sast" => self.sast_tool.run_scan(path, commit_id, branch, rule_path, verbose).await,
            "sca" => self.sca_tool.run_scan(path, commit_id, branch, no_install, root_only, build_args, manifests, verbose).await,
            "secret" => self.secret_tool.run_scan(path, commit_id, branch, verbose).await,
            "license-compliance" => self.license_tool.run_scan(path, commit_id, branch, verbose).await,
            _ => println!("Invalid scan type: {}", scan_type),
        }
    }
}
