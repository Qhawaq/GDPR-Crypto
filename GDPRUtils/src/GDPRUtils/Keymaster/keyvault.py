import os
import sys
import yaml

from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding # noqa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption  # noqa
from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption  # noqa
from cryptography.hazmat.primitives import hashes


def get_config_file(cfgfile):
    try:
        with open(cfgfile, "r") as fconf:
            try:
                conf_var = yaml.safe_load(fconf)
            except yaml.scanner.ScannerError:  # type: ignore
                print("Keyvault config file error: Scanner Error")
                sys.exit(-1)
    except (OSError, IOError) as e:
        print("Keyvault config file error: " + e.strerror)
        sys.exit(-1)

    return conf_var


def create_key_hash(name: str) -> str:
    """Create an hash (SHA256) using the param as base value

    Args:
        name (string): string to be hashed

    Returns:
        string : Hexadecimal string representing the hash
    """
    k_hash = hashes.Hash(hashes.SHA256())
    k_hash.update(name.encode())
    key = k_hash.finalize()
    return key.hex()


def select_keyfile(keyfile: str) -> bool:
    """Search if a file exists in protected directory
    specified in the config file as 'keyfolder'.

    Args:
        keyfile (string): File name to search

    Returns:
        bool: True if file is found, False if not
    """
    (_, i_file) = os.path.split(keyfile)
    cryptkeyfile = kv_conf_book["keyfolder"] + "/" + i_file  # type: ignore
    p = Path(cryptkeyfile)
    if p.exists() and p.is_file():
        return True
    return False


def store_keyfile(keyfile: str, newkeyfile: str | None = None) -> bool:
    """Store an X.509 private key file in a proteceted directory
    specified in the config file as 'keyfolder'.
    The private key file will be saved in PKCS8 encrypted format
    the password will be the file name hashed by create_key_hash.
    If a second parameter will be specified it will be used as
    file name for the prinvate key in the protected folder.

    Args:
        keyfile (string): X.509 original private key file name
                         ( with or without path )
        newkeyfile (string, optional): X.509 new private key file name.
                                       Defaults to None.

    Returns:
        bool: True if operation succeeded, False if not
    """

    (_, i_file) = os.path.split(keyfile)

    if newkeyfile is None:
        cryptkeyfile = kv_conf_book["keyfolder"] + "/" + i_file  # type: ignore
        pwd = create_key_hash(i_file)
    else:
        cryptkeyfile = kv_conf_book["keyfolder"] + "/" + newkeyfile
        pwd = create_key_hash(newkeyfile)

    try:
        with open(keyfile, "r") as f:
            key = f.read().encode("utf-8")
        p_key0 = load_pem_private_key(key, password=None)
    except ValueError:
        return False

    p_key1 = p_key0.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8,
        BestAvailableEncryption(pwd.encode())
    )

    with open(cryptkeyfile, "w") as f:
        f.write(p_key1.decode())

    return True


def recover_keyfile(keyfile: str) -> bytes | None:
    """Recover X.509 private bytes from a protected file stored
    into protected folder.

    Args:
        keyfile (string): Private key file name to recover

    Returns:
        bytes: private key bytes in OpenSSL format, if file was recovered
        or None on error.
    """
    if select_keyfile(keyfile):
        (_, i_file) = os.path.split(keyfile)
        pwd = create_key_hash(i_file)
        cryptkeyfile = kv_conf_book["keyfolder"] + "/" + i_file  # type: ignore

        try:
            with open(cryptkeyfile, "r") as f:
                key = f.read().encode("utf-8")
            p_key0 = load_pem_private_key(key, password=pwd.encode())
        except ValueError:
            return None

        return p_key0.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
    return None


def stream_keyfile(keyfile: str, pwd: bytes) -> bytes | None:
    """Recover X.509 private key from the vault folder
    reencrypt the private key with a new password and
    pack key in PKCS8 format and return it for stream
    to client.

    Args:
        keyfile (string): Private key file name to stream
        pwd (string): New password for encryption

    Returns:
        bytes: Private key in PKCS8 format, None if error
    """
    if select_keyfile(keyfile):
        # Try to open private key file from vault directory
        # using create_key_hash for password if fail return None
        (_, i_file) = os.path.split(keyfile)
        pwd0 = create_key_hash(i_file).encode()
        cryptkeyfile = kv_conf_book["keyfolder"] + "/" + i_file  # type: ignore

        try:
            with open(cryptkeyfile, "r") as f:
                key = f.read().encode("utf-8")
            p_key0 = load_pem_private_key(key, password=pwd0)
        except ValueError:
            return None

        return p_key0.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(pwd) # noqa
        )

    return None


kv_conf_book = get_config_file("/home/mariano/Documenti/RepoSoftware/GDPR-Crypto/server-config.yml") # noqa

# if __name__ == "__main__":
#    store_keyfile('/home/mariano/Scrivania/GDPRUtils-Data/GDPR_TEST_CERT.pem', 'GDPR_TEST_CERT') # noqa
