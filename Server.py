import os
import time

from fastapi import FastAPI

from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, BestAvailableEncryption, PrivateFormat
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


master = '12345678901234567890123456789012'


def get_hkdf_key(master_key):

    salt = os.urandom(16)
    info = b"SecCheck_01"

    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=info,
    )

    key = hkdf.derive(master_key)

    return (salt, key)


def check_TOTP(id, value):

    key = id
    totp = TOTP(key, 8, SHA256(), 30)
    time_value = time.time()
    try:
        totp.verify(value, int(time_value))
        return (key)
    except InvalidToken:
        pass

    return (b'0')


def open_p_key_file(f_name):
    try:
        with open(f_name, 'r') as f:
            key = f.read().encode('utf-8')
    except FileNotFoundError:
        return ('ERRORE')

    return (key)


def p_key_refactor(key, pwd0, pwd1):

    try:
        p_key0 = load_pem_private_key(key, password=pwd0)
    except ValueError:
        return (b'0')

    p_key1 = p_key0.private_bytes(Encoding.PEM, 
                                  PrivateFormat.PKCS8,
                                  BestAvailableEncryption(pwd1))
    return (p_key1)



seed=bytes.fromhex("b6a82cc095258d5006661371191c59173545ca9b1da0c1815706cecc92da33e4")

app = FastAPI()


@app.get("/")
def read_root():
    return {"Status": "Ok"}


@app.get("/req")
def read_item(sel: str, id: str, val: str,):

    if len(check_TOTP(seed, val.encode())) > 1:
        pem_key = open_p_key_file('/home/mariano/Scrivania/MIEnc.pk8')
        enc_key = p_key_refactor(pem_key, b'1234', b'45678')
        return {"crypt_pld": enc_key}
    else:
        return {"crypt_pld": "ERRORE"}



