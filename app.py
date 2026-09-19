# api/access-jwt.py
from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import base64
import time
import hashlib
import requests
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime


# ═══════════════════════════════════════════════════════════
# ثوابت OB55
# ═══════════════════════════════════════════════════════════
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

HEADERS = {
    "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Accept": "*/*",
    "Accept-Encoding": "deflate, gzip",
    "X-Ga-Sv": "1789534056",
    "Authorization": "Bearer ",
    "X-Ga": "v1 1",
    "ReleaseVersion": "OB55",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2018.4.12f1",
}

LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"


# ═══════════════════════════════════════════════════════════
# Protobuf Writer (بسيط)
# ═══════════════════════════════════════════════════════════
class ProtoWriter:
    def varint(self, value):
        result = []
        while value > 127:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)

    def tag(self, field_num, wire_type):
        return self.varint((field_num << 3) | wire_type)

    def write_varint(self, field_num, value):
        return self.tag(field_num, 0) + self.varint(value)

    def write_string(self, field_num, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        return self.tag(field_num, 2) + self.varint(len(value)) + value

    def create_message(self, fields):
        result = bytearray()
        for field_num, value in sorted(fields.items()):
            if isinstance(value, int):
                result.extend(self.write_varint(field_num, value))
            elif isinstance(value, str):
                result.extend(self.write_string(field_num, value))
            elif isinstance(value, bytes):
                result.extend(self.write_string(field_num, value))
        return bytes(result)


def aes_encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def build_major_login(open_id, access_token, platform="3"):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fields = {
        3: current_time,
        4: "free fire",
        5: 1,
        7: "2.126.6",
        8: "Android OS 9 / API-28 (PQ3B.190801.03250903/G9650ZHU2ARC6)",
        9: "Handheld",
        10: "Mobinil",
        11: "WIFI",
        12: 1600, 13: 900, 14: "240",
        15: "x86-64 SSE3 SSE4.1 SSE4.2 AVX | 2865 | 6",
        16: 5955, 17: "Adreno (TM) 640", 18: "OpenGL ES 3.1 v1",
        19: "Google|8eab9762-c0ea-40d8-b64f-f152bc12e03b",
        20: "197.202.55.30", 21: "ar",
        22: open_id, 23: platform, 24: "Handheld",
        25: "Xiaomi 2304FPN6DG", 26: "ME",
        29: access_token, 30: 1,
        41: "Mobinil", 42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 50504, 61: 47169, 62: 2519, 63: 734,
        64: 23888, 65: 26628,
        74: "/data/app/com.dts.freefiremax-qjzX4V6JmeMtMehevolhVQ==/lib/arm64",
        77: "d508536b2a3c16bf2bebbd24233e9293|/data/app/com.dts.freefiremax-qjzX4V6JmeMtMehevolhVQ==/base.apk",
        78: 2, 79: 2, 81: "64", 83: "2019118045",
        85: 3, 86: "OpenGLES3", 87: 4095, 88: 4,
        91: "android", 92: 4903,
        94: "KqsHT+dw/OPMR6vKsRTZUHjrrrcWy4c3Gyt7K6IyAWXfe0r8Q9CibaAB16K58gBDMW1Ki9bcr8+xioK2xwdS9js0A=",
        95: 110009, 97: 1, 98: 1,
        99: platform, 100: platform, 103: 1,
    }
    return ProtoWriter().create_message(fields)


def get_open_id(access_token):
    """استخراج open_id من Access Token"""
    try:
        url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "GarenaMSDK/4.0.30P10(G011A ;Android 13;en;US;)",
        }
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        if 'error' in data:
            return None, data.get('error')
        return data['open_id'], str(data.get('platform', 3))
    except Exception as e:
        return None, str(e)


def decode_jwt(jwt_token):
    """فك JWT بدون تحقق من التوقيع"""
    try:
        parts = jwt_token.split('.')
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        return json.loads(payload_json)
    except Exception as e:
        return {"error": str(e)}


def do_major_login(access_token):
    """ينفذ MajorLogin ويعيد JWT + البيانات"""
    # 1) احصل على open_id
    open_id, platform = get_open_id(access_token)
    if not open_id:
        return {"success": False, "error": f"invalid_token: {platform}"}

    # 2) ابن payload
    payload = build_major_login(open_id, access_token, platform)
    encrypted = aes_encrypt(payload)

    # 3) أرسل الطلب
    try:
        resp = requests.post(
            LOGIN_URL,
            data=encrypted,
            headers=HEADERS,
            timeout=15,
            verify=False,
        )
    except Exception as e:
        return {"success": False, "error": f"connection_failed: {e}"}

    if resp.status != 200:
        return {
            "success": False,
            "error": f"major_login_failed: HTTP {resp.status}",
            "body": resp.text[:200],
        }

    # 4) استخرج JWT من الرد
    text = resp.content.decode('utf-8', errors='ignore')
    jwt_match = re.search(r'(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)', text)
    if not jwt_match:
        return {"success": False, "error": "jwt_not_found"}

    jwt_token = jwt_match.group(1)
    jwt_payload = decode_jwt(jwt_token)

    # 5) ابن الرد النهائي
    return {
        "success": True,
        "access_token_used": access_token[:20] + "...",
        "open_id": open_id,
        "platform_type_used": int(platform),
        "account_uid": jwt_payload.get("account_id"),
        "Uid": jwt_payload.get("external_uid"),
        "region": jwt_payload.get("noti_region"),
        "lock_region": jwt_payload.get("lock_region"),
        "nickname_encoded": jwt_payload.get("nickname"),
        "signature_md5": jwt_payload.get("signature_md5"),
        "client_version": jwt_payload.get("client_version"),
        "release_version": jwt_payload.get("release_version"),
        "exp": jwt_payload.get("exp"),
        "jwt_decoded": {
            "header": {"alg": "HS256", "svr": "1", "typ": "JWT"},
            "payload": jwt_payload,
        },
        "token": jwt_token,
        "timestamp": int(time.time()),
    }


# ═══════════════════════════════════════════════════════════
# HTTP Handler (Vercel Serverless)
# ═══════════════════════════════════════════════════════════
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # رخّص CORS
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        try:
            # استخرج access_token من query
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            access_token = params.get('access_token', [None])[0]

            if not access_token:
                result = {
                    "success": False,
                    "error": "missing_parameter: access_token",
                    "usage": "/access-jwt?access_token=YOUR_ACCESS_TOKEN",
                }
            else:
                result = do_major_login(access_token)

            self.wfile.write(json.dumps(result, ensure_ascii=False, indent=2).encode('utf-8'))

        except Exception as e:
            err = {"success": False, "error": f"server_error: {str(e)}"}
            self.wfile.write(json.dumps(err, ensure_ascii=False, indent=2).encode('utf-8'))
