from flask import Flask, request, jsonify
import threading, requests, socket
from des import (
    encrypt_block_hex, decrypt_block_hex,
    generate_subkeys_from_keyhex, text_to_hex_blocks,
    hex_blocks_to_text, generate_key_hex
)

SERVER_IP = input("Masukkan IP server (misal 192.168.1.10): ").strip()
SERVER_URL = f"http://{SERVER_IP}:5000"

app = Flask(__name__)

client_id = None
client_port = None

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

client_ip = get_local_ip()
@app.route('/deliver', methods=['POST'])
def deliver_message():
    data = request.json
    sender = data["from"]
    key = data["key"]
    cipher = data["cipher"]

    subkeys = generate_subkeys_from_keyhex(key)
    plain_blocks = []
    for i in range(0, len(cipher), 16):
        block = cipher[i:i+16]
        plain_hex = decrypt_block_hex(block, subkeys)
        plain_blocks.append(plain_hex)
    decrypted = hex_blocks_to_text(plain_blocks)

    print(f"\n[CLIENT-{client_id}] Pesan dari {sender}:")
    print(f"Cipher: {cipher}")
    print(f"Key: {key}")
    print(f"Plain (decrypted): {decrypted}\n")
    return jsonify({"status": "received"})

def start_client_server():
    app.run(host="0.0.0.0", port=client_port, debug=False, use_reloader=False)

def send_message(to_id, text):
    key_hex = generate_key_hex()
    subkeys = generate_subkeys_from_keyhex(key_hex)
    blocks = text_to_hex_blocks(text)
    cipher_blocks = [encrypt_block_hex(b, subkeys) for b in blocks]
    cipher_text = ''.join(cipher_blocks)

    payload = {
        "from": client_id,
        "to": to_id,
        "plain": text,
        "key": key_hex,
        "cipher": cipher_text
    }

    try:
        res = requests.post(f"{SERVER_URL}/send", json=payload)
        print(f"[CLIENT-{client_id}] Mengirim pesan ke {to_id}: {text}")
        print("Status:", res.json())
    except Exception as e:
        print(f"[CLIENT-{client_id}] Gagal mengirim pesan ke server: {e}")

if __name__ == "__main__":
    print("=== Client DES ===")
    client_id = input("Masukkan ID client (misal: client1): ").strip()
    client_port = int(input("Masukkan port client (misal: 5001): ").strip())
    threading.Thread(target=start_client_server, daemon=True).start()

    try:
        requests.post(f"{SERVER_URL}/register", json={
            "id": client_id,
            "ip": client_ip,
            "port": client_port
        })
        print(f"[CLIENT-{client_id}] Terdaftar di server ({client_ip}:{client_port})\n")
    except Exception as e:
        print(f"[CLIENT-{client_id}] Gagal mendaftar ke server: {e}")
        exit()

    try:
        res = requests.get(f"{SERVER_URL}/pending/{client_id}")
        pending = res.json().get("messages", [])
        for msg in pending:
            requests.post(f"http://127.0.0.1:{client_port}/deliver", json=msg)
    except Exception as e:
        print(f"[CLIENT-{client_id}] Tidak dapat memeriksa pesan pending: {e}")

    while True:
        to_id = input("Kirim ke client ID (atau 'exit' untuk keluar): ").strip()
        if to_id.lower() == "exit":
            break
        text = input("Pesan: ")
        send_message(to_id, text)