from flask import Flask, request, jsonify
import requests, threading
import rsa 
import random, secrets

app = Flask(__name__)

CLIENT_INFO = {}   
AUTH_PUB, AUTH_PRIV = rsa.generate_rsa_keypair(bits=512)  

def sign_client_pubkey(client_id, pub_e, pub_n):
    import hashlib
    msg = f"{client_id}:{pub_e}:{pub_n}".encode('utf-8')
    h = hashlib.sha256(msg).digest()
    m_int = rsa.int_from_bytes(h)
    sig_int = rsa.rsa_sign_int(m_int, AUTH_PRIV)
    return {
        "signed_hash": format(sig_int, 'x'),
        "hash_hex": h.hex(),
        "authority_pub_e": AUTH_PUB[0],
        "authority_pub_n": AUTH_PUB[1]
    }

@app.route('/register', methods=['POST'])
def register_client():
    data = request.json
    cid = data.get("id")
    ip = data.get("ip")
    port = data.get("port")
    pub_e = data.get("pub_e")
    pub_n = data.get("pub_n")
    if not all([cid, ip, port, pub_e, pub_n]):
        return {"status": "missing"}, 400
    CLIENT_INFO[cid] = {
        "ip": ip,
        "port": port,
        "pub_e": int(pub_e),
        "pub_n": int(pub_n)
    }
    cert = sign_client_pubkey(cid, int(pub_e), int(pub_n))
    CLIENT_INFO[cid]["cert"] = cert
    print(f"[SERVER] Registered {cid} at {ip}:{port} pub_e={pub_e} n={pub_n}")
    return {"status": "registered", "cert": cert}, 200

@app.route('/get_cert/<cid>', methods=['GET'])
def get_cert(cid):
    info = CLIENT_INFO.get(cid)
    if not info:
        return {"status": "notfound"}, 404
    return {
        "id": cid,
        "pub_e": info["pub_e"],
        "pub_n": info["pub_n"],
        "cert": info.get("cert")
    }, 200

@app.route('/kdc_request', methods=['POST'])
def kdc_request():
    data = request.json
    requester = data.get("from")
    target = data.get("to")
    if requester not in CLIENT_INFO or target not in CLIENT_INFO:
        return {"status": "unknown_client"}, 404
    hexchars = "0123456789ABCDEF"
    session_key = ''.join(secrets.choice(hexchars) for _ in range(16))
    target_info = CLIENT_INFO[target]
    req_info = CLIENT_INFO[requester]
    sk_bytes = bytes.fromhex(session_key)
    sk_int = rsa.int_from_bytes(sk_bytes)
    enc_for_target_int = rsa.rsa_encrypt(sk_int, (target_info["pub_e"], target_info["pub_n"]))
    enc_for_requester_int = rsa.rsa_encrypt(sk_int, (req_info["pub_e"], req_info["pub_n"]))
    resp = {
        "status": "ok",
        "session_key_for_requester": format(enc_for_requester_int, 'x'),
        "session_key_for_target": format(enc_for_target_int, 'x'),
        "note": "send session_key_for_target to target via server"
    }
    print(f"[KDC] session key {session_key} untuk {requester}<->{target}")
    return resp, 200

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    receiver = data.get("to")
    if receiver in CLIENT_INFO:
        client = CLIENT_INFO[receiver]
        ip = client["ip"]
        port = client["port"]
        try:
            requests.post(f"http://{ip}:{port}/deliver", json=data, timeout=5)
            print(f"[SERVER] Forwarded message to {receiver} ({ip}:{port})")
        except Exception as e:
            print(f"[SERVER] Failed to forward to {receiver} : {e}")
    else:
        print(f"[SERVER] {receiver} not registered.")
    return {"status": "ok"}, 200

if __name__ == "__main__":
    print("[SERVER] Authority/KDC/Router running on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)