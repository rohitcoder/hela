use crate::scans::tools::{
    license_tool::LicenseTool, sast_tool::SastTool, sca_tool::ScaTool, secret_tool::SecretTool,
};

pub struct ScanRunner {
    sast_tool: SastTool,
    sca_tool: ScaTool,
    secret_tool: SecretTool,
    license_tool: LicenseTool,
}

impl ScanRunner {
    pub fn new(
        sast_tool: SastTool,
        sca_tool: ScaTool,
        secret_tool: SecretTool,
        license_tool: LicenseTool,
    ) -> Self {
        ScanRunner {
            sast_tool,
            sca_tool,
            secret_tool,
            license_tool,
        }
    }

    pub async fn execute_scan(
        &self,
        mongo_uri: &str,
        scan_type: &str,
        path: &str,
        branch: Option<&str>,
        pr_branch: Option<&str>,
        no_install: bool,
        root_only: bool,
        build_args: String,
        manifests: String,
        rule_path: String,
        verbose: bool,
    ) {
        match scan_type {
            "sast" => {
                self.sast_tool
                    .run_scan(path, branch, pr_branch, rule_path, verbose)
                    .await
            }
            "sca" => {
                self.sca_tool
                    .run_scan(
                        path, branch, pr_branch, no_install, root_only, build_args, manifests,
                        verbose,
                    )
                    .await
            }
            "secret" => {
                self.secret_tool
                    .run_scan(path, branch, pr_branch, mongo_uri, verbose)
                    .await
            }
            "license-compliance" => {
                self.license_tool
                    .run_scan(path, branch, pr_branch, verbose)
                    .await
            }
            _ => println!("Invalid scan type: {}", scan_type),
        }
    }
}
