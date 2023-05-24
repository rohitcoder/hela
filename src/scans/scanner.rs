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

    pub fn execute_scan(&self, scan_type: &str, path: &str) {
        match scan_type {
            "sast" => self.sast_tool.run_scan(path),
            "sca" => self.sca_tool.run_scan(path),
            "secret" => self.secret_tool.run_scan(path),
            "license-compliance" => self.license_tool.run_scan(path),
            _ => println!("Invalid scan type: {}", scan_type),
        }
    }
}
