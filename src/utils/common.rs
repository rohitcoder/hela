use std::{process::Command, os::unix::process::ExitStatusExt};

pub fn print_error(error: &str, error_code: i32) {
    if error.to_lowercase().starts_with("warning") {
        println!("[❕] {}", error);
    }else{
        println!("[‼️] {}", error);
    }
    if error_code != 101 {
        std::process::exit(error_code);
    }
}

pub async fn execute_command(command: &str, suppress_error: bool) -> String {
    let suppress_error = suppress_error || false;
    let exec_name = command.split_whitespace().next().unwrap();
    let exec_args = command.split_whitespace().skip(1).collect::<Vec<&str>>();
    let output;
    
    if command.contains("&&") {
        output = match Command::new("sh")
            .arg("-c")
            .arg(command)
            .output() {
                Ok(output) => output,
                Err(e) => {
                    if !suppress_error {
                        print_error(&format!("Error: {} : {}", &command.to_string(), e.to_string()), 101);
                    }
                    return "".to_string();
                }
            };
    } else {
        output = match Command::new(exec_name).args(exec_args).output() {
            Ok(output) => output,
            Err(e) => {
                if !suppress_error {
                    print_error(&format!("Error: {} : {}", &command.to_string(), e.to_string()), 101);
                }
                return "".to_string();
            }
        };
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = &output.status;
    
    if !stderr.is_empty() && status != &std::process::ExitStatus::from_raw(0) {
        if !suppress_error {
            println!("For command: {}", command);
            print_error(format!("{}: {}", "Error executing process: ", stderr).as_str(), 101);
        }
    }
    
    if stdout.is_empty() {
        return stderr.to_string();
    }
    
    stdout.to_string()
}
