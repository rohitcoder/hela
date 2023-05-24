use crate::scans::tools::license_tool::LicenseTool;

pub struct LicenseCompliance {
    license_tool: LicenseTool,
}

impl LicenseCompliance {
    pub fn new() -> Self {
        LicenseCompliance {
            license_tool: LicenseTool::new(),
        }
    }

    pub fn run_scan(&self) {
        // TODO: Implement license compliance scan logic using the license tool
        // You can utilize the license_tool instance here
        let target = "example_target";
        self.license_tool.run_scan(target);
    }
}
