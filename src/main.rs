use anti_vm::is_virtualized;

fn main() {
    if is_virtualized() {
        println!("A virtual machine was detected.");
    } else {
        println!("No virtual machine was detected.");
    }
}
