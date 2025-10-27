from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

CLIENT_PORTS = {}
MESSAGES = {}

@app.route('/register', methods=['POST'])
def register_client():
    data = request.json
    cid = data.get("id")
    ip = data.get("ip")
    port = data.get("port")

    CLIENT_PORTS[cid] = {"ip": ip, "port": port}
    print(f"[SERVER] Client {cid} terdaftar di {ip}:{port}")
    return {"status": "registered"}, 200

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get("from")
    receiver = data.get("to")
    plain = data.get("plain")
    key = data.get("key")
    cipher = data.get("cipher")

    print(f"\n[SERVER] Pesan diterima dari {sender} untuk {receiver}")
    print(f"Plain  : {plain}")
    print(f"Key    : {key}")
    print(f"Cipher : {cipher}\n")

    if receiver in CLIENT_PORTS:
        client_info = CLIENT_PORTS[receiver]
        ip = client_info["ip"]
        port = client_info["port"]
        try:
            requests.post(f"http://{ip}:{port}/deliver", json=data)
            print(f"[SERVER] Pesan diteruskan ke {receiver} ({ip}:{port})\n")
        except Exception as e:
            print(f"[SERVER] Gagal mengirim ke {receiver}: {e}")
    else:
        print(f"[SERVER] Client {receiver} belum terdaftar, pesan disimpan sementara.")
        MESSAGES.setdefault(receiver, []).append(data)

    return {"status": "ok"}, 200

@app.route('/pending/<cid>', methods=['GET'])
def get_pending(cid):
    msgs = MESSAGES.pop(cid, [])
    return jsonify({"messages": msgs})

if __name__ == "__main__":
    print("[SERVER] Server berjalan di semua interface jaringan (0.0.0.0:5000)")
    app.run(host="0.0.0.0", port=5000)