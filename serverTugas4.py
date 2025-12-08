from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
CLIENTS = {}

@app.route('/register', methods=['POST'])
def register_client():
    data = request.json
    cid = data.get("id")
    ip = data.get("ip")
    port = data.get("port")
    pubkey = data.get("public_key") 

    if not cid or not ip or not port or not pubkey:
        return {"status": "error", "msg": "Incomplete registration"}, 400

    CLIENTS[cid] = {"ip": ip, "port": port, "public_key": pubkey}
    print(f"[SERVER] Client {cid} terdaftar di {ip}:{port} dengan public key {pubkey}")
    return {"status": "registered"}, 200

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get("from")
    receiver = data.get("to")

    if receiver in CLIENTS:
        client_info = CLIENTS[receiver]
        ip = client_info["ip"]
        port = client_info["port"]
        try:
            requests.post(f"http://{ip}:{port}/deliver", json=data)
            print(f"[SERVER] Pesan diteruskan ke {receiver} ({ip}:{port})")
        except Exception as e:
            print(f"[SERVER] Gagal mengirim ke {receiver}: {e}")

    return {"status": "ok"}, 200

@app.route('/client_pub/<cid>', methods=['GET'])
def get_client_pub(cid):
    client = CLIENTS.get(cid)
    if not client:
        return {"status":"error","msg":"client not found"}, 404
    return client["public_key"]

if __name__ == "__main__":
    print("[SERVER] Server berjalan di 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)