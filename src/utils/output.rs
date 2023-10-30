pub struct Output;

impl Output {
    pub fn format_results(results: Vec<String>) {
        // TODO: Implement result formatting logic
        println!("Scan results:");
        for result in results {
            println!("{}", result);
        }
    }

    pub fn log(message: &str) {
        // TODO: Implement logging logic
        println!("LOG: {}", message);
    }
}
