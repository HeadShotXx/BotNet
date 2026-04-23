use std::path::PathBuf;
use chromelevator_injector::run_abe_bypass;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: chromelevator.exe <chrome|edge> [-v] [-o <output_path>]");
        return;
    }

    let target = &args[1];
    let verbose = args.contains(&"-v".to_string());
    let mut output_path = PathBuf::from("output");

    if let Some(pos) = args.iter().position(|a| a == "-o") {
        if pos + 1 < args.len() {
            output_path = PathBuf::from(&args[pos + 1]);
        }
    }

    match run_abe_bypass(target, verbose, output_path) {
        Ok(_) => println!("[+] Operation completed successfully"),
        Err(e) => eprintln!("[-] Error: {}", e),
    }
}
