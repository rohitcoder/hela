use crate::scans::tools::sast_tool::SastTool;

pub struct Sast {
    sast_tool: SastTool,
}

impl Sast {
    pub fn new() -> Self {
        Sast {
            sast_tool: SastTool::new(),
        }
    }

    pub fn run_scan(&self) {
        // TODO: Implement SAST scan logic using the SAST tool
        // You can utilize the sast_tool instance here
        let target = "example_target";
        self.sast_tool.run_scan(target);
    }
}
