#!/usr/bin/env python3
import os
import sys

def transform_data(data, key):
    if not key:
        return data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def main():
    if len(sys.argv) not in [2, 3]:
        print(f"Usage: {sys.argv[0]} <input-file> [output-dir]")
        return

    path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) == 3 else "."
    print(f"[*] Reading file: {path}")

    try:
        with open(path, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"[✗] Failed to read file: {e}")
        return

    print(f"[+] File size: {len(data)} bytes")

    key = os.urandom(32)
    print("[+] Generated a new random 32-byte SECRET_KEY.")

    obfuscated_data = transform_data(data, key)

    key_output = "    "
    for i, byte in enumerate(key):
        key_output += f"0x{byte:02x}, "
        if (i + 1) % 16 == 0:
            key_output += "\n    "
    if key_output.endswith(", "):
        key_output = key_output[:-2]

    payload_output = "    "
    for i, byte in enumerate(obfuscated_data):
        payload_output += f"0x{byte:02x}, "
        if (i + 1) % 16 == 0:
            payload_output += "\n    "
    if payload_output.endswith(", "):
        payload_output = payload_output[:-2]

    key_path = os.path.join(output_dir, "key.rs")
    payload_path = os.path.join(output_dir, "payload.rs")

    try:
        with open(key_path, 'w') as f:
            f.write(key_output)
        print(f"[+] SECRET_KEY written to {key_path}")
    except IOError as e:
        print(f"[✗] Failed to write {key_path}: {e}")
        return

    try:
        with open(payload_path, 'w') as f:
            f.write(payload_output)
        print(f"[+] PAYLOAD written to {payload_path}")
    except IOError as e:
        print(f"[✗] Failed to write {payload_path}: {e}")
        return

    print("\n[+] Successfully generated files.")

if __name__ == "__main__":
    main()
