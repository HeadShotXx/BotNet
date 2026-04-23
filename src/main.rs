use anti_vm;

fn main() {
    println!("Checking for virtualization...");

    if anti_vm::is_virtualized() {
        println!("Virtual machine or sandbox environment detected!");
        // In a real scenario, you might want to terminate the process or change behavior.
        std::process::exit(1);
    } else {
        println!("Running on physical hardware.");
        // Proceed with normal execution.
    }
}
