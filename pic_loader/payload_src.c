void _start() {
    __asm__ volatile (
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "lea msg(%%rip), %%rsi\n"
        "mov $31, %%rdx\n" // "Payload executed successfully!\n" is 31 bytes
        "syscall\n"
        "mov $60, %%rax\n"
        "xor %%rdi, %%rdi\n"
        "syscall\n"
        "msg: .ascii \"Payload executed successfully!\\n\"\n"
        : : : "rax", "rdi", "rsi", "rdx", "memory"
    );
}
