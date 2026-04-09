import base64
import sys
import os

def build(payload_path, loader_source):
    if not os.path.exists(payload_path):
        print(f"Error: Payload {payload_path} not found.")
        sys.exit(1)

    with open(payload_path, "rb") as f:
        encoded_payload = base64.b64encode(f.read()).decode()

    if not os.path.exists(loader_source):
        print(f"Error: Loader source {loader_source} not found.")
        sys.exit(1)

    with open(loader_source, "r") as f:
        content = f.readlines()

    new_content = []
    for line in content:
        if line.startswith('const char* payload_b64 = '):
            new_content.append(f'const char* payload_b64 = "{encoded_payload}";\n')
        else:
            new_content.append(line)

    with open(loader_source, "w") as f:
        f.writelines(new_content)

    print(f"Successfully embedded {payload_path} into {loader_source}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 builder.py <payload.exe> <loader.c>")
        sys.exit(1)

    build(sys.argv[1], sys.argv[2])
