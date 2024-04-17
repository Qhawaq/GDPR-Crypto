# import os
import time

# from typing import List
# from GDPRUtils.src.GDPRUtils.Keymaster.models import User
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


def get_hkdf_key(master_key: bytes,
                 lngh: int = 32,
                 salt: bytes = b'0', info: bytes = b'SecCheck01') -> bytes:
    """ Derive a key from master_key using HKDF

    Args:
        master_key (bytes): Master Key
        lngh (int, optional): length of derived key in bytes. Defaults to 32.
        salt (bytes, optional): salt to use in key derive. Defaults to b'0'.
        info (bytes, optional): additional info to use in key derive.
                                Defaults to b'SecCheck01'.

    Returns:
        bytes: Derived key        
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=lngh,
        salt=salt,
        info=info,
    )
    key = hkdf.derive(master_key)
    return key


def check_TOTP(seed: bytes, otp: bytes, w_time: int = 30) -> bool:
    """Check if TOTP value is valid againt the seed

    Args:
        seed (bytes): Seed value used in TOTP calculation
        otp (bytes): TOTP value to check
        w_time (int): TOTP windows time in seconds.

    Returns:
        bool: True if OTP is valid for the seed, False otherwise
    """
    totp = TOTP(seed, 8, SHA256(), w_time)
    time_value = time.time()
    try:
        totp.verify(otp, int(time_value))
        return (True)
    except InvalidToken:
        pass

    return (False)

print("Prima")
app = FastAPI()


@app.get("/")
async def get_index():
    return {"Status": "Ok"}


@app.get("/getmykey")
async def get_my_key(id: str, sel: str, otp: str, key: str,):

    seed = bytes.fromhex("b6a82cc095258d5006661371191c59173545ca9b1da0c1815706cecc92da33e4") # noqa

    if check_TOTP(seed, otp.encode()):
        # Creo la coppia chiave privata/pubblica per il DH
        dh_private_key = ec.generate_private_key(ec.SECP384R1())
        dh_public_key = dh_private_key.public_key()

        server_key = dh_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) # noqa

        # carica la chiave pubblica inviata dal client
        key_bytes = load_pem_public_key(urlsafe_b64decode(key))
        # effettua lo scambio ECDH con la chiave inviata dal client
        shared_key = dh_private_key.exchange(ec.ECDH(), key_bytes)
        # deriva una chiave HKDF
        stream_key = get_hkdf_key(shared_key)
        print("STREAM Key: ", stream_key)
        
        enc_key = stream_keyfile(sel, stream_key)
        if enc_key is not None:
            return {"server_key": urlsafe_b64encode(server_key),
                    "keyfile": urlsafe_b64encode(enc_key)} # noqa

    return {"server_key": "", "keyfile": ""}
