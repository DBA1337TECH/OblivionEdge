import subprocess
import sys
import json

def decrypt_log(key, enc_file="smtp_debug.json.enc"):
    try:
        result = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-d", "-salt", "-pass", f"pass:{key}", "-in", enc_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        output = result.stdout.decode()

        # Split based on the closing brace of each JSON object
        entries = output.strip().split("}\n")

        for entry in entries:
            if not entry.strip():
                continue
            entry = entry.strip()
            if not entry.endswith("}"):
                entry += "}"
            try:
                entry = entry.replace("\r", "").replace("\n", "")
                data = json.loads(entry)
                print(json.dumps(data, indent=4))
            except json.JSONDecodeError as e:
                print("❌ Failed to parse this JSON block:")
                print(entry)
                print("🔺 JSON error:", e)

    except subprocess.CalledProcessError as e:
        print("❌ OpenSSL decryption failed:", e.stderr.decode().strip())
    except Exception as e:
        print("❌ Unexpected error:", str(e))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 decrypt_smtp_log.py <encryption_key> [encrypted_file]")
        sys.exit(1)

    key = sys.argv[1]
    enc_file = sys.argv[2] if len(sys.argv) > 2 else "smtp_debug.json.enc"

    decrypt_log(key, enc_file)

