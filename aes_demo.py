"""
# @File     : aes_demo.py
# @Author   : jade
# @Date     : 2025/4/22 16:26
# @Email    : jadehh@1ive.com
# @Software : Samples
# @Desc     : aes_demo.py
"""
# !/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
def base64Encode(str):
    string_bytes = str.encode('utf-8')
    # Encode to Base64
    base64_encoded = base64.b64encode(string_bytes)
    # Convert Base64 bytes back to string
    plain_text = base64_encoded.decode('utf-8')
    return plain_text
def base64Decode(str):
    string_bytes = str.encode('utf-8')
    # Encode to Base64
    base64_encoded = base64.b64decode(string_bytes)
    return base64_encoded

def encrypt(text, key, iv,mode="AES/ECB/NoPadding"):
    if mode == "AES/CBC/PKCS7Padding":
        cipher = AES.new(base64Decode(key), AES.MODE_CBC, base64Decode(iv)[:16])
        encrypted_data = cipher.encrypt(pad(base64Decode(text), AES.block_size))
        return base64.b64encode(encrypted_data)
    elif mode == "AES/ECB/NoPadding":
        cipher = AES.new(base64Decode(key), AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(base64Decode(text), AES.block_size))
        return base64.b64encode(encrypted_data)
def decrypt(text, key, iv,mode="AES/ECB/NoPadding"):
    if mode == "AES/CBC/PKCS7Padding":
        cipher = AES.new(base64Decode(key), AES.MODE_CBC, base64Decode(iv)[:16])
        return unpad(cipher.decrypt(base64Decode(text)), AES.block_size).decode("utf-8")
    elif mode == "AES/ECB/NoPadding":
        cipher = AES.new(base64Decode(key), AES.MODE_ECB)
        decrypted_data = cipher.decrypt((base64Decode(text)))
        return unpad(decrypted_data, AES.block_size).decode('utf-8')

if __name__ == '__main__':
    text = base64Encode("Hello World")
    key = base64Encode("B374A26A71490437AA024E4FADD5B49F")
    iv = base64Encode("0C925434E4A6A8D00F1D2D3E4C5B6A7")
    mode1 = "AES/CBC/PKCS7Padding"
    mode2 = "AES/ECB/NoPadding"
    aesCBCText = 'rGMo9u1pEsPpOB8BD5vnEA=='
    ecbCBCText = 'ApQrErEOpaGFn8UuIbJwJw=='
    print(encrypt(text,key,iv,mode=mode1))
    print(encrypt(text,key,iv,mode=mode2))
    print(decrypt(aesCBCText,key,iv,mode=mode1))
    print(decrypt(ecbCBCText,key,iv,mode=mode2))