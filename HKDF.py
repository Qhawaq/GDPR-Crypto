import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


for i in range(10):

    salt = os.urandom(16)
    info = b"test"

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )

    key = hkdf.derive(b"input key")
    print(key)


# hkdf = HKDF(
#    algorithm=hashes.SHA256(),
#    length=32,
#    salt=salt,
#    info=info,
# )


# hkdf.verify(b"input key", key)
