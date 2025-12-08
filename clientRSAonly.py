from flask import Flask, request, jsonify
import threading, requests, socket, os, json, hashlib
from rsa import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    int_from_bytes, int_to_bytes, rsa_sign_int, rsa_verify_int
)

SERVER_IP = input("Masukkan IP server (misal 192.168.1.10): ").strip()
SERVER_URL = f"http://{SERVER_IP}:5000"

app = Flask(__name__)

client_id = None
client_port = None

RSA_PRIV_FILE = "client_priv.json"
RSA_PUB_FILE = "client_pub.json"

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

def load_or_generate_rsa_keys(bits=512):
    if os.path.exists(RSA_PRIV_FILE) and os.path.exists(RSA_PUB_FILE):
        with open(RSA_PRIV_FILE, 'r') as f:
            priv = json.load(f)
        with open(RSA_PUB_FILE, 'r') as f:
            pub = json.load(f)
        return (priv['d'], priv['n']), (pub['e'], pub['n'])
    pub, priv = generate_rsa_keypair(bits)
    with open(RSA_PRIV_FILE, 'w') as f:
        json.dump({'d': priv[0], 'n': priv[1]}, f)
    with open(RSA_PUB_FILE, 'w') as f:
        json.dump({'e': pub[0], 'n': pub[1]}, f)
    return priv, pub

def sign_message(text, privkey):
    msg_hash = hashlib.sha256(text.encode('utf-8')).digest()
    msg_int = int_from_bytes(msg_hash)
    signature = rsa_sign_int(msg_int, privkey)
    return str(signature)

def verify_signature(text, signature_str, pubkey):
    signature = int(signature_str)
    msg_hash = hashlib.sha256(text.encode('utf-8')).digest()
    msg_int = int_from_bytes(msg_hash)
    decrypted_hash_int = rsa_verify_int(signature, pubkey)
    return decrypted_hash_int == msg_int

client_ip = "100.71.69.67"
RSA_PRIV, RSA_PUB = load_or_generate_rsa_keys()

@app.route('/deliver', methods=['POST'])
def deliver_message():
    data = request.json
    sender = data["from"]
    cipher_int = int(data["cipher"])
    signature = data["signature"]

    try:
        pub_info = requests.get(f"{SERVER_URL}/client_pub/{sender}").json()
        pubkey_sender = (int(pub_info['e']), int(pub_info['n']))
    except:
        pubkey_sender = None

    decrypted_int = rsa_decrypt(cipher_int, RSA_PRIV)
    decrypted_bytes = int_to_bytes(decrypted_int)
    decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')

    valid = False
    if pubkey_sender:
        valid = verify_signature(decrypted_text, signature, pubkey_sender)

    print(f"\n[CLIENT-{client_id}] Pesan dari {sender}:")
    print(f"Cipher: {cipher_int}")
    print(f"Plain: {decrypted_text}")
    print(f"Signature valid: {valid}\n")

    return jsonify({"status": "received"})

def start_client_server():
    app.run(host="0.0.0.0", port=client_port, debug=False, use_reloader=False)

def send_message(to_id, text):
    try:
        pub_info = requests.get(f"{SERVER_URL}/client_pub/{to_id}").json()
        pubkey_to = (int(pub_info['e']), int(pub_info['n']))
    except:
        print(f"[CLIENT-{client_id}] Gagal ambil public key {to_id}")
        return

    msg_bytes = text.encode('utf-8')
    msg_int = int_from_bytes(msg_bytes)

    cipher_int = rsa_encrypt(msg_int, pubkey_to)

    signature = sign_message(text, RSA_PRIV)

    payload = {
        "from": client_id,
        "to": to_id,
        "cipher": str(cipher_int),
        "signature": signature
    }

    try:
        res = requests.post(f"{SERVER_URL}/send", json=payload)
        print(f"[CLIENT-{client_id}] Mengirim pesan terenkripsi ke {to_id}")
        print(f"Cipher: {cipher_int}")
        print(f"Signature: {signature}")
        print("Status:", res.json())
    except Exception as e:
        print(f"[CLIENT-{client_id}] Gagal mengirim pesan ke server: {e}")

if __name__ == "__main__":
    print("=== Client Pure RSA + Signature ===")
    client_id = input("Masukkan ID client (misal: client1): ").strip()
    client_port = int(input("Masukkan port client (misal: 5001): ").strip())
    threading.Thread(target=start_client_server, daemon=True).start()

    try:
        requests.post(f"{SERVER_URL}/register", json={
            "id": client_id,
            "ip": client_ip,
            "port": client_port,
            "public_key": {"e": RSA_PUB[0], "n": RSA_PUB[1]}
        })
        print(f"[CLIENT-{client_id}] Terdaftar di server ({client_ip}:{client_port})\n")
    except Exception as e:
        print(f"[CLIENT-{client_id}] Gagal mendaftar ke server: {e}")
        exit()

    while True:
        to_id = input("Kirim ke client ID (atau 'exit' untuk keluar): ").strip()
        if to_id.lower() == "exit":
            break
        text = input("Pesan: ")
        send_message(to_id, text)