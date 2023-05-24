mod cli;
mod scanner;

use cli::Cli;
use scanner::Scanner;

fn main() {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Initialize scanner
    let scanner = Scanner::new();

    // Execute the requested scan
    match cli.command {
        Some(command) => scanner.execute_scan(command),
        None => println!("No command specified."),
    }
}
