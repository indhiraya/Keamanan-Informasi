from flask import Flask, request, jsonify
import threading, requests, socket, time, secrets
import rsa, des
from des import encrypt_block_hex, decrypt_block_hex, generate_subkeys_from_keyhex, text_to_hex_blocks, hex_blocks_to_text
from rsa import int_from_bytes, int_to_bytes

app = Flask(__name__)

SERVER_IP = input("Masukkan IP server (misal 192.168.1.10): ").strip()
SERVER_URL = f"http://{SERVER_IP}:5000"

client_id = None
client_port = None
client_ip = None

LOCAL_PRIV = None
LOCAL_PUB = None
KNOWN_PUB = {}
SESSION_KEYS = {}

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

@app.route('/deliver', methods=['POST'])
def deliver_message():
    data = request.json
    kind = data.get("kind", "app")
    sender = data.get("from")
    if kind == "kdc_session_for_target":
        enc_hex = data.get("enc_hex")
        enc_int = int(enc_hex, 16)
        m_int = rsa.rsa_decrypt(enc_int, LOCAL_PRIV)
        sk_bytes = int_to_bytes(m_int)
        if len(sk_bytes) < 8:
            sk_bytes = (b'\x00' * (8 - len(sk_bytes))) + sk_bytes
        session_key = sk_bytes.hex().upper()
        SESSION_KEYS[sender] = session_key
        print(f"\n[CLIENT-{client_id}] Received session key for conversation with {sender}: {session_key}\n")
        return jsonify({"status": "ok"})
    if kind == "challenge":
        subtype = data.get("subtype")
        if subtype == "nonce1":
            enc_int = int(data.get("enc"), 16)
            m_int = rsa.rsa_decrypt(enc_int, LOCAL_PRIV)
            m_bytes = int_to_bytes(m_int)
            n1 = int.from_bytes(m_bytes[:8], 'big')
            idA = m_bytes[8:].decode('utf-8', errors='ignore')
            n2 = secrets.randbits(64)
            print(f"[CLIENT-{client_id}] Menerima N1 dari {idA}: {n1}")
            print(f"[CLIENT-{client_id}] Menghasilkan N2: {n2}")
            if idA not in KNOWN_PUB:
                fetch_and_store_pub(idA)
            e_a, n_a = KNOWN_PUB[idA]["pub_e"], KNOWN_PUB[idA]["pub_n"]
            payload = n1.to_bytes(8,'big') + n2.to_bytes(8,'big')
            payload_int = int_from_bytes(payload)
            enc_to_a = rsa.rsa_encrypt(payload_int, (e_a, n_a))
            requests.post(f"{SERVER_URL}/send", json={
                "from": client_id,
                "to": idA,
                "kind": "challenge",
                "subtype": "nonce1resp",
                "enc": format(enc_to_a, 'x')
            })
            SESSION_KEYS[f"nonce_expect_{idA}"] = n2
            print(f"[CLIENT-{client_id}] Challenge: got N1 from {idA}, responded with N1||N2")
            return jsonify({"status": "ok"})
        elif subtype == "nonce1resp":
            enc_int = int(data.get("enc"), 16)
            m_int = rsa.rsa_decrypt(enc_int, LOCAL_PRIV)
            m_bytes = int_to_bytes(m_int)
            n1 = int.from_bytes(m_bytes[:8], 'big')
            n2 = int.from_bytes(m_bytes[8:16], 'big')
            target = data.get("from")
            print(f"[CLIENT-{client_id}] Menerima N1: {n1} dan N2: {n2} dari {target}")
            if target not in KNOWN_PUB:
                fetch_and_store_pub(target)
            e_b, n_b = KNOWN_PUB[target]["pub_e"], KNOWN_PUB[target]["pub_n"]
            enc_n2 = rsa.rsa_encrypt(n2, (e_b, n_b))
            requests.post(f"{SERVER_URL}/send", json={
                "from": client_id,
                "to": target,
                "kind": "challenge",
                "subtype": "nonce2",
                "enc": format(enc_n2, 'x')
            })
            print(f"[CLIENT-{client_id}] Received N1||N2 from {target}, sent N2 back.")
            return jsonify({"status": "ok"})
        elif subtype == "nonce2":
            enc_int = int(data.get("enc"), 16)
            m_int = rsa.rsa_decrypt(enc_int, LOCAL_PRIV)
            n2 = m_int
            expect = SESSION_KEYS.get(f"nonce_expect_{data.get('from')}")
            print(f"[CLIENT-{client_id}] Menerima N2 dari {data.get('from')}: {n2}")
            print(f"[CLIENT-{client_id}] N2 yang seharusnya: {expect}")
            if expect is not None and n2 == expect:
                print(f"[CLIENT-{client_id}] Challenge SUCCESS with {data.get('from')}")
            else:
                print(f"[CLIENT-{client_id}] Challenge FAILED with {data.get('from')}")
            return jsonify({"status": "ok"})
    key = data.get("key")
    cipher = data.get("cipher")
    print(f"[CLIENT-{client_id}] Cipher text diterima dari {sender}: {cipher}")
    print(f"[CLIENT-{client_id}] PRIVATE KEY yang digunakan untuk decrypt:")
    print(f"   d = {LOCAL_PRIV[0]}")
    print(f"   n = {LOCAL_PRIV[1]}")
    print()
    try:
        subkeys = generate_subkeys_from_keyhex(key)
        plain_hex_blocks = []
        for i in range(0, len(cipher), 16):
            block = cipher[i:i+16]
            pt_hex = des.decrypt_block_hex(block, subkeys)
            plain_hex_blocks.append(pt_hex)
        plain_text = des.hex_blocks_to_text(plain_hex_blocks)
        print(f"\n[CLIENT-{client_id}] Pesan dari {sender}: {plain_text}\n")
    except Exception as e:
        print(f"[CLIENT-{client_id}] GAGAL dekripsi pesan dari {sender}: {e}")
    return jsonify({"status": "received"})

def start_client_server():
    app.run(host="0.0.0.0", port=client_port, debug=False, use_reloader=False)

def fetch_and_store_pub(cid):
    try:
        res = requests.get(f"{SERVER_URL}/get_cert/{cid}", timeout=5)
        if res.status_code == 200:
            j = res.json()
            KNOWN_PUB[cid] = {
                "pub_e": int(j["pub_e"]),
                "pub_n": int(j["pub_n"]),
                "cert": j.get("cert")
            }
            print(f"[CLIENT-{client_id}] Public key {cid} diperoleh.")
            return True
    except Exception as e:
        print(f"[CLIENT-{client_id}] Gagal fetch pubkey {cid}: {e}")
    return False

def register_self():
    global LOCAL_PUB, LOCAL_PRIV
    print("[CLIENT] Generating RSA keypair...")
    PUB, PRIV = rsa.generate_rsa_keypair(bits=512)
    LOCAL_PUB, LOCAL_PRIV = PUB, PRIV
    print(f"\n[CLIENT-{client_id}] === RSA KEYPAIR ===")
    print(f"PUBLIC KEY  (e, n): {PUB}")
    print(f"PRIVATE KEY (d, n): {PRIV}\n")
    payload = {
        "id": client_id,
        "ip": client_ip,
        "port": client_port,
        "pub_e": LOCAL_PUB[0],
        "pub_n": LOCAL_PUB[1]
    }
    try:
        res = requests.post(f"{SERVER_URL}/register", json=payload, timeout=5)
        if res.status_code == 200:
            print(f"[CLIENT-{client_id}] Registered to server.")
            cert = res.json().get("cert")
            KNOWN_PUB[client_id] = {
                "pub_e": LOCAL_PUB[0],
                "pub_n": LOCAL_PUB[1],
                "cert": cert
            }
        else:
            print("[CLIENT] Register failed", res.text)
    except Exception as e:
        print(f"[CLIENT] Register exception: {e}")

def request_session_key(target):
    payload = {"from": client_id, "to": target}
    try:
        res = requests.post(f"{SERVER_URL}/kdc_request", json=payload, timeout=5)
        j = res.json()
        if j.get("status") != "ok":
            print("[CLIENT] KDC request failed:", j)
            return None, None
        enc_for_requester = j["session_key_for_requester"]
        enc_for_target = j["session_key_for_target"]
        enc_int = int(enc_for_requester, 16)
        m_int = rsa.rsa_decrypt(enc_int, LOCAL_PRIV)
        sk_bytes = int_to_bytes(m_int)
        if len(sk_bytes) < 8:
            sk_bytes = (b'\x00' * (8 - len(sk_bytes))) + sk_bytes
        session_key = sk_bytes.hex().upper()
        SESSION_KEYS[target] = session_key
        requests.post(f"{SERVER_URL}/send", json={
            "from": client_id,
            "to": target,
            "kind": "kdc_session_for_target",
            "enc_hex": enc_for_target
        })
        print(f"[CLIENT-{client_id}] Session key untuk {target}: {session_key}")
        return session_key, enc_for_target
    except Exception as e:
        print(f"[CLIENT] KDC error: {e}")
        return None, None

def do_challenge_with_peer(peer):
    if peer not in KNOWN_PUB:
        fetch_and_store_pub(peer)
    e_b, n_b = KNOWN_PUB[peer]["pub_e"], KNOWN_PUB[peer]["pub_n"]
    n1 = secrets.randbits(64)
    print(f"[CLIENT-{client_id}] Menghasilkan N1: {n1}")
    payload = n1.to_bytes(8,'big') + client_id.encode('utf-8')
    payload_int = int_from_bytes(payload)
    enc_to_b = rsa.rsa_encrypt(payload_int, (e_b, n_b))
    requests.post(f"{SERVER_URL}/send", json={
        "from": client_id,
        "to": peer,
        "kind": "challenge",
        "subtype": "nonce1",
        "enc": format(enc_to_b, 'x')
    })
    SESSION_KEYS[f"sent_nonce_{peer}"] = n1
    print(f"[CLIENT-{client_id}] Challenge: sent N1 to {peer}")
    return True

def send_message_to_peer(peer, text):
    if peer not in KNOWN_PUB:
        print(f"[CLIENT-{client_id}] Public key {peer} tidak ada, fetch dari server...")
        if not fetch_and_store_pub(peer):
            print(f"[CLIENT] Tidak bisa mengambil public key {peer}")
            return
    if peer not in SESSION_KEYS or SESSION_KEYS[peer] is None:
        sk, _ = request_session_key(peer)
        if not sk:
            print("[CLIENT] Tidak bisa mendapatkan session key")
            return
        do_challenge_with_peer(peer)
        time.sleep(1)
    key_hex = SESSION_KEYS.get(peer)
    if not key_hex:
        print("[CLIENT] Tidak ada session key.")
        return
    target_pub = KNOWN_PUB[peer]
    print(f"[CLIENT-{client_id}] Menggunakan PUBLIC KEY {peer}: (e={target_pub['pub_e']}, n={target_pub['pub_n']})")
    subkeys = generate_subkeys_from_keyhex(key_hex)
    blocks = text_to_hex_blocks(text)
    cipher_blocks = [encrypt_block_hex(b, subkeys) for b in blocks]
    cipher_text = ''.join(cipher_blocks)
    print(f"[CLIENT-{client_id}] Cipher text yang dikirim ke {peer}: {cipher_text}")
    payload = {
        "from": client_id,
        "to": peer,
        "kind": "app",
        "plain": text,
        "key": key_hex,
        "cipher": cipher_text
    }
    try:
        requests.post(f"{SERVER_URL}/send", json=payload, timeout=5)
        print(f"[CLIENT-{client_id}] Pesan terenkripsi dikirim ke {peer}")
    except Exception as e:
        print(f"[CLIENT-{client_id}] Gagal kirim pesan: {e}")
if __name__ == "__main__":
    print("=== Client DES + RSA Hybrid (Auto Mode) ===")
    client_id = input("Masukkan ID client (misal: client1): ").strip()
    client_port = int(input("Masukkan port client (misal: 5001): ").strip())
    client_ip = "100.71.69.67"
    threading.Thread(target=start_client_server, daemon=True).start()
    time.sleep(0.5)
    register_self()
    while True:
        peer = input("\nPenerima pesan: ").strip()
        text = input("Pesan: ")
        send_message_to_peer(peer, text)