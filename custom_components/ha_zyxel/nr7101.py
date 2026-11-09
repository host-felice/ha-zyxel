# Vendored from https://github.com/zulufoxtrot/nr7101 (v2.0.2, MIT, see
# LICENSE.nr7101) with an optional requests.Session for all calls, trimmed to
# what this integration uses (setup, login, request encryption). Kept here
# so this fork does not wait for an nr7101 release.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import json
import base64
import os
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

import requests
import urllib3

logger = logging.getLogger(__name__)


class NR7101:
    def __init__(self, url, username, password, params={}, session=None):
        # A requests.Session reuses one keep-alive connection for all calls;
        # without one, every call opens (and closes) its own connection.
        self.http = session if session is not None else requests
        self.url = url
        self.params = params
        self.rsa_key = None
        self.encryption_required = False
        password_b64 = base64.b64encode(password.encode("utf-8")).decode("utf-8")

        # NR7101 is using by default self-signed certificates, so ignore the warnings
        self.params["verify"] = False
        urllib3.disable_warnings()

        # Step 1: Call GetInfoNoLogin to establish session
        info_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        info_params = self.params.copy()
        info_params['headers'] = info_headers

        with self.http.get(self.url + "/GetInfoNoLogin", **info_params) as info_r:
            if info_r.cookies:
                self.params["cookies"] = requests.utils.dict_from_cookiejar(info_r.cookies)

        # Step 2: Get RSA public key
        rsa_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'If-Modified-Since': 'Thu, 01 Jun 1970 00:00:00 GMT',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        rsa_params = self.params.copy()
        if 'headers' in rsa_params:
            rsa_params['headers'].update(rsa_headers)
        else:
            rsa_params['headers'] = rsa_headers

        with self.http.get(self.url + "/getRSAPublickKey", **rsa_params) as r:
            # Update session cookies from the RSA key request (if any)
            if r.cookies:
                if "cookies" not in self.params:
                    self.params["cookies"] = {}
                new_cookies = requests.utils.dict_from_cookiejar(r.cookies)
                self.params["cookies"].update(new_cookies)

            if r.status_code == 200:
                try:
                    response_json = r.json()
                    self.rsa_key = response_json.get("RSAPublicKey", None)
                    if self.rsa_key == "None":     # router can return a "None" str
                        self.rsa_key = None
                except Exception:
                    self.rsa_key = None
            else:
                self.rsa_key = None

            self.encryption_required = bool(self.rsa_key)
            self.aes_key = os.urandom(32)  # 256-bit AES key
            self.iv = os.urandom(32)       # 32-byte IV to match browser behavior

        # Login parameters
        self.login_params = {
            "Input_Account": username,
            "Input_Passwd": password_b64,
            "currLang": "en",
            "RememberPassword": 0,
        }
        self.sessionkey = None

    def login(self):
        if self.encryption_required:
           login_json = self.encrypt_request(self.login_params)
        else:
            login_json = json.dumps(self.login_params)

        login_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'If-Modified-Since': 'Thu, 01 Jun 1970 00:00:00 GMT',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': self.url,
            'DNT': '1',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Referer': f'{self.url}/login',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        login_params = self.params.copy()
        if 'headers' in login_params:
            login_params['headers'].update(login_headers)
        else:
            login_params['headers'] = login_headers

        with self.http.post(
            self.url + "/UserLogin", data=login_json.encode('utf-8'), **login_params
        ) as r:
            if r.status_code != 200:
                return False

            # Update cookies with any new ones from login response
            if r.cookies:
                new_cookies = requests.utils.dict_from_cookiejar(r.cookies)
                if "cookies" not in self.params:
                    self.params["cookies"] = {}
                self.params["cookies"].update(new_cookies)

            if self.encryption_required:
                response_data = self.decrypt_response(r.json())
            else:
                response_data = r.json()
            self.sessionkey = response_data["sessionkey"]
            return True

    def encrypt_request(self, json_data: dict) -> str:
        # Use compact JSON formatting to match browser behavior
        json_body = json.dumps(json_data, separators=(',', ':')).encode('utf-8')
        padded = pad(json_body, 16)

        # Encrypt the login parameters using AES (use only first 16 bytes of IV for CBC)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv[:16])
        ciphertext = cipher.encrypt(padded)
        content_b64 = base64.b64encode(ciphertext).decode()

        if not self.rsa_key:
            raise Exception("No RSA key available for encryption")

        try:
            rsa_key = RSA.import_key(self.rsa_key.encode('utf-8'))
            cipher_rsa = PKCS1_v1_5.new(rsa_key)

            # Encrypt the base64-encoded AES key
            base64_encoded_key = base64.b64encode(self.aes_key)
            encrypted_key = cipher_rsa.encrypt(base64_encoded_key)
            key_b64 = base64.b64encode(encrypted_key).decode()

            iv_b64 = base64.b64encode(self.iv).decode()

            return json.dumps({
                "content": content_b64,
                "key": key_b64,
                "iv": iv_b64
            })

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt_response(self, encrypted_json: dict) -> dict:
        # Decode base64 values
        response_iv = base64.b64decode(encrypted_json["iv"])
        ciphertext = base64.b64decode(encrypted_json["content"])

        # Use the response IV for decryption (first 16 bytes for AES-CBC)
        iv_for_decrypt = response_iv[:16]

        # Decrypt with AES (CBC mode) using the same key as request encryption
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv_for_decrypt)
        decrypted_padded = cipher.decrypt(ciphertext)

        # Try standard unpadding first
        try:
            decrypted_data = unpad(decrypted_padded, 16)
        except ValueError:
            # Fallback for routers that don't use proper PKCS7 padding
            try:
                # Remove trailing null bytes
                decrypted_data = decrypted_padded.rstrip(b'\x00')
                if len(decrypted_data) == len(decrypted_padded) and len(decrypted_padded) > 0:
                    # Try manual PKCS7 unpadding
                    padding_length = decrypted_padded[-1]
                    if 0 < padding_length <= 16:
                        decrypted_data = decrypted_padded[:-padding_length]
                    else:
                        decrypted_data = decrypted_padded
            except Exception:
                # Last resort: use raw decrypted data
                decrypted_data = decrypted_padded

        # Decode and parse as JSON
        try:
            json_string = decrypted_data.decode("utf-8")
            return json.loads(json_string)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            logger.error(f"Error processing JSON response: {e}")
            raise Exception(f"Failed to process decrypted response: {e}")
