import base64
import sys
import os
import subprocess

def build(payload_path, loader_c, output_bin):
    # 1. Encode payload
    with open(payload_path, "rb") as f:
        encoded_payload = base64.b64encode(f.read()).decode()

    # 2. Update loader.c with the payload
    # We use a wrapper to ensure it stays in .text and is searchable
    full_payload_str = f"---PAYLOAD:{encoded_payload}---"

    with open(loader_c, "r") as f:
        c_content = f.read()

    placeholder = 'const char payload_b64[] = "---PAYLOAD_PLACEHOLDER---";'
    if placeholder not in c_content:
        print("Error: Could not find placeholder in loader.c")
        sys.exit(1)

    new_c_content = c_content.replace(placeholder, f'const char payload_b64[] = "{full_payload_str}";')

    with open("loader_final.c", "w") as f:
        f.write(new_c_content)

    # 3. Compile loader
    loader_exe = "loader_temp.exe"
    compile_cmd = [
        "x86_64-w64-mingw32-gcc", "loader_final.c", "-o", loader_exe,
        "-nostdlib", "-e", "LoaderEntry", "-ffreestanding",
        "-fno-stack-protector", "-fno-common", "-fno-asynchronous-unwind-tables",
        "-Os", "-s"
    ]
    print("Compiling loader...")
    subprocess.run(compile_cmd, check=True)

    # 4. Extract shellcode
    print("Extracting shellcode...")
    extract_cmd = ["x86_64-w64-mingw32-objcopy", "-O", "binary", "--only-section=.text", loader_exe, output_bin]
    subprocess.run(extract_cmd, check=True)

    # Cleanup
    os.remove(loader_exe)
    os.remove("loader_final.c")

    print(f"Successfully created final shellcode: {output_bin} ({os.path.getsize(output_bin)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 builder.py <payload.exe> <loader.c> <output.bin>")
        sys.exit(1)
    build(sys.argv[1], sys.argv[2], sys.argv[3])
