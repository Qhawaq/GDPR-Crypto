import os
import time

from typing import List
from GDPRUtils.src.GDPRUtils.Keymaster.models import User
from .keyvault import stream_keyfile
from fastapi import FastAPI

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key,  Encoding # noqa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption  # noqa
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat # noqa
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

from base64 import urlsafe_b64decode, urlsafe_b64encode


db: List[User] = []

# Creo la coppia chiave privata/pubblica per il DH
dh_private_key = ec.generate_private_key(ec.SECP384R1())
dh_public_key = dh_private_key.public_key()
dh_p = dh_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)  # type: ignore # noqa


def activate_session_for(id, sh_key):
    for user in db:
        if user.id == id:
            db.remove(user)
    newUser = User()  # type: ignore
    newUser.id = id
    newUser.shk = sh_key
    db.append(newUser)


def get_hkdf_key(master_key):

    salt = os.urandom(16)
    info = b"SecCheck_01"  # noqa TODO: NON CRITICO.

    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=info,
    )

    key = hkdf.derive(master_key)

    return (salt, key)


def check_TOTP(key, value):

    totp = TOTP(key, 8, SHA256(), 30)
    time_value = time.time()
    try:
        totp.verify(value, int(time_value))
        return (True)
    except InvalidToken:
        pass

    return (False)


def select_key_from_vault(idkey):
    pass


app = FastAPI()


@app.get("/")
async def read_root():
    return {"Status": "Ok"}


@app.get("/req")
async def read_item(sel: str, id: str, val: str,):

    seed = bytes.fromhex("b6a82cc095258d5006661371191c59173545ca9b1da0c1815706cecc92da33e4") # noqa
    if check_TOTP(seed, val.encode()):
        enc_key = stream_keyfile(sel, 'pwd')
        return {"crypt_pld": enc_key}
    else:
        return {"crypt_pld": "ERRORE"}


@app.get("/k_excg")
async def xchg_key(id: str, otp: str, key: str,):
    seed = ""
    # seed = bytes.fromhex("b6a82cc095258d5006661371191c59173545ca9b1da0c1815706cecc92da33e4") # noqa
    if check_TOTP(seed, otp.encode()):
        key_bytes = load_pem_public_key(urlsafe_b64decode(key))
        shared_key = dh_private_key.exchange(ec.ECDH(), key_bytes)
        server_key = dh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) # noqa
        activate_session_for(id, shared_key)
        return {"server_key": urlsafe_b64encode(server_key)}

    return {"server_key": ""}
