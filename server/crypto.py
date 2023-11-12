import binascii
import os
from constants import *

from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA


def crc32(data):
    print("crc = ", binascii.crc32(data) & 0xFFFFFFFF)
    return binascii.crc32(data) & 0xFFFFFFFF


def generate_aes():
    return os.urandom(AES_CBC_KEY_SIZE)

def encrypt_aes_key(public_key: bytes, aes_key: bytes):
    key = RSA.importKey(public_key)
    encrypted_aes = PKCS1_OAEP.new(key).encrypt(aes_key)
    return encrypted_aes


def decrypt_file(encrypted_file: bytes, aes_key: bytes) -> bytes:

    decryptor = AES.new(key=aes_key, mode=AES.MODE_CBC, iv=(b'\0' * 16))
    file = decryptor.decrypt(encrypted_file)
    file = unpad(file, AES.block_size)
    return file
