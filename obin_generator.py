#!/usr/bin/env python3
import os
import sys

def transform_data(data, key):
    if not key:
        return data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input-file>")
        return

    path = sys.argv[1]
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

    key_output = "const SECRET_KEY: &[u8] = &[\n    "
    for i, byte in enumerate(key):
        key_output += f"0x{byte:02x}, "
        if (i + 1) % 16 == 0:
            key_output += "\n    "
    if key_output.endswith(", "):
        key_output = key_output[:-2]
    key_output += "\n];\n"

    payload_output = "const PAYLOAD: &[u8] = &[\n    "
    for i, byte in enumerate(obfuscated_data):
        payload_output += f"0x{byte:02x}, "
        if (i + 1) % 16 == 0:
            payload_output += "\n    "
    if payload_output.endswith(", "):
        payload_output = payload_output[:-2]
    payload_output += "\n];"

    try:
        with open("key.rs", 'w') as f:
            f.write(key_output)
        print("[+] SECRET_KEY written to key.rs")
    except IOError as e:
        print(f"[✗] Failed to write key.rs: {e}")
        return

    try:
        with open("payload.rs", 'w') as f:
            f.write(payload_output)
        print("[+] PAYLOAD written to payload.rs")
    except IOError as e:
        print(f"[✗] Failed to write payload.rs: {e}")
        return

    print("\n[+] Successfully generated files. Please copy the contents of key.rs and payload.rs into your tulpar project.")

if __name__ == "__main__":
    main()
