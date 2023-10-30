use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Cli {
    #[structopt(subcommand)]
    pub command: Option<ScanCommand>,
}

#[derive(StructOpt)]
pub enum ScanCommand {
    #[structopt(name = "sast")]
    Sast,
    #[structopt(name = "sca")]
    Sca,
    #[structopt(name = "secret")]
    Secret,
    #[structopt(name = "license-compliance")]
    LicenseCompliance,
}

impl Cli {
    pub fn parse() -> Self {
        Cli::from_args()
    }
}
