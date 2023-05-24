use crate::scans::tools::sca_tool::ScaTool;

pub struct Sca {
    sca_tool: ScaTool,
}

impl Sca {
    pub fn new() -> Self {
        Sca {
            sca_tool: ScaTool::new(),
        }
    }

    pub fn run_scan(&self) {
        // TODO: Implement SCA scan logic using the SCA tool
        // You can utilize the sca_tool instance here
        let target = "example_target";
        self.sca_tool.run_scan(target);
    }
}
