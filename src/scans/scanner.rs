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

    pub async fn execute_scan(&self, scan_type: &str, path: &str, commit_id: Option<&str>, branch: Option<&str>, server_url: Option<&str>) {
        if let Some(commit_id) = commit_id {
            println!("Commit ID: {}", commit_id);
        }else {
            println!("Commit ID: None");
        }
        match scan_type {
            "sast" => self.sast_tool.run_scan(path, commit_id, branch, server_url).await,
            "sca" => self.sca_tool.run_scan(path, commit_id, branch, server_url).await,
            "secret" => self.secret_tool.run_scan(path, commit_id, branch, server_url).await,
            "license-compliance" => self.license_tool.run_scan(path, commit_id, branch, server_url).await,
            _ => println!("Invalid scan type: {}", scan_type),
        }
    }
}
