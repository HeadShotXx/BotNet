/**
 * Simple Windows x64 PIC Payload
 * This payload doesn't do anything visible because it's hard to do so without resolving APIs,
 * but it serves as a valid piece of shellcode for the loader to execute.
 */

void payload_entry() {
    // Just return.
    // In a real scenario, you would resolve MessageBoxA or similar here.
    return;
}
