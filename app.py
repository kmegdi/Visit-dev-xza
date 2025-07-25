from flask import Flask, request, jsonify
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import asyncio
import urllib3
import os
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def load_tokens(region):
    try:
        if region == "ME":
            with open("token_me.json", "r") as f:
                tokens = json.load(f)
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception:
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception:
        return None

async def make_request_async(encrypt, region, token, session):
    try:
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "ME"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }

        async with session.post(url, data=edata, headers=headers, ssl=False, timeout=5) as response:
            if response.status != 200:
                return None
            binary = await response.read()
            return decode_protobuf(binary)
    except Exception:
        return None
        
@app.route('/visit', methods=['GET', 'POST'])
async def visit():
    if request.method == 'POST':
        uid = request.form.get("uid") or (request.json.get("uid") if request.is_json else None)
        region = request.form.get("region") or (request.json.get("region") if request.is_json else "").upper()
    else:
        uid = request.args.get("uid")
        region = request.args.get("region", "").upper()

    if not all([uid, region]):
        return jsonify({"error": "UID and region are required"}), 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens.")

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Failed to encrypt UID.")

        total_visits = len(tokens) * 20
        success_count = 0
        failed_count = 0
        total_responses = []
        player_name = None

        async with aiohttp.ClientSession() as session:
            tasks = []
            for token in tokens:
                for _ in range(20):
                    tasks.append(make_request_async(encrypted_uid, region, token['token'], session))

            responses = await asyncio.gather(*tasks)

        for response in responses:
            total_responses.append(response)
            if response:
                if not player_name:
                    jsone = MessageToJson(response)
                    data_info = json.loads(jsone)
                    player_name = data_info.get('AccountInfo', {}).get('PlayerNickname', '')
                success_count += 1
            else:
                failed_count += 1

        return jsonify({
            "TotalVisits": total_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "UID": int(uid),
            "TotalResponses": total_responses
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))