import os
import ssl
import json
import time
import yaml
import requests

from base64 import urlsafe_b64decode, urlsafe_b64encode

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat, NoEncryption  # noqa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding # noqa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DNS = 0
CRT = 1

OP_CRYPT = 0
OP_DECRYPT = 1

CRYPT_GCM_SESSION_KEY_SIZE = 32
CRYPT_KEY_LOCATOR_SIZE = 50
CRYPT_ENC_GCM_SIZE = 256
CRYPT_GCM_NONCE_SIZE = 16
CRYPT_GCM_TAG_SIZE = 16

CRYPT_HEADER_SIZE = (
    CRYPT_KEY_LOCATOR_SIZE
    + CRYPT_ENC_GCM_SIZE
    + CRYPT_GCM_NONCE_SIZE
    + CRYPT_GCM_TAG_SIZE
)

CRYPT_TAG_POINTER = CRYPT_KEY_LOCATOR_SIZE + CRYPT_ENC_GCM_SIZE + CRYPT_GCM_NONCE_SIZE  # noqa


BUFFER_SIZE = 1024 * 1024
TOTP_VALID_TIME = 30
TOTP_DIGITS = 8

conf_book = []


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


def priv_key_request_for_file(i_file):
    """
    La funzione analizza la testata del file cifrato per sapere dove
    cercare la chiave privata relativa.
    """
    # Creo la coppia chiave privata/pubblica per il DH
    dh_private_key = ec.generate_private_key(ec.SECP384R1())
    dh_public_key = dh_private_key.public_key()
    dh_p = dh_public_key.public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo
    )  # noqa

    # TODO: controllo errore di accesso
    with open(i_file, "rb") as file_in:
        cert_name = file_in.read(50).decode().strip()
    cert = cert_name.split('=')

    if True:   #  cert_name[0] == "0":
        # Il certificato è un DNS  quindi la chiave deve essere cercata
        # nel server di chiavi
        myid = "id=" + conf_book["rest"]["id"]  # type: ignore
        mysel = "&sel=" + cert[1]
        myotp = "&otp=" + get_totp_code().decode()
        mykey = "&key=" + urlsafe_b64encode(dh_p).decode()
        url = (
            conf_book["rest"]["url"]  # type: ignore
            + ":"
            + str(conf_book["rest"]["port"])  # type: ignore
            + "/getmykey?"
            + myid
            + mysel
            + myotp
            + mykey
        )  # type: ignore

        try:
            r = requests.get(url)        
            x = json.loads(r.text)  # type: ignore

            server_key_bytes = load_pem_public_key(urlsafe_b64decode(x['server_key']))  # noqa
            shared_key = dh_private_key.exchange(ec.ECDH(), server_key_bytes)
            stream_key = get_hkdf_key(shared_key)  # chiave di decodifica

            pkb = load_pem_private_key(urlsafe_b64decode(x['keyfile']), stream_key)
            return pkb.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption() # noqa
            )
        except requests.exceptions.RequestException as e:
            msg = 'FATAL Error: ' + conf_book["rest"]["url"] + ':' + str(conf_book["rest"]["port"]) + ' has some troubles with us.\nSee what it said:\n\n'  # type: ignore
            for m in e.args:
                msg += str(m)+'\n'
            raise SystemExit(msg)

    else:
        # TODO: Il certificato è un CRT locale quindi la chiave deve essere
        # cercata nel vault locale
        pass


def get_config():
    with open("GCM-config.yml", "r") as fconf:
        conf_var = yaml.safe_load(fconf)
    return conf_var


def get_totp_code():
    seed = conf_book["otp_id"]["seed"]  # type: ignore
    key = bytes.fromhex(seed)
    totp = TOTP(key, TOTP_DIGITS, SHA256(), TOTP_VALID_TIME)
    time_value = time.time()
    t_value = totp.generate(int(time_value))
    return t_value


def get_rsa_public_key(certdata, tip: int):
    """Get an RSA Public Key form an X.509 certificate

    Args:
        certdata (str): X.509 Certificate Domain Name ( Internet )
                        or Certificate file path (Local file )
        tip (int): Flag DNS/CRT
                   If DNS function requests certificate on Internet using its domain name
                   IF CRT function search for local certificate file specified by path 

    Returns:
        (bytes,bytes): RSA Public Key extracted, Certificate 'CN' attribute
    """

    if tip == DNS:
        cert = ssl.get_server_certificate((certdata, 443))

    if tip == CRT:
        cert = open(certdata).read()

    cert_obj = x509.load_pem_x509_certificate(cert.encode())
    pub_key_rsa = cert_obj.public_key()
    cert_nm = x509.Name(cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME))  # noqa
    cert_name = f"{tip},{cert_nm.rfc4514_string():{' '}{'<'}{CRYPT_KEY_LOCATOR_SIZE -2}}".encode()  # noqa
    return (pub_key_rsa, cert_name)


def get_rsa_private_key(keyfile, pwd: bytes | None = None, mem: bool = False):
    """Read a PEM formatted RSA private key from a file or from memory variable

    Args:
        keyfile (any): PEM File name where to read key, or PEM memory 
        pwd (bytes, optional): Password to . Defaults to None.
        mem (bool, optional): True if PEM key is passed as variable, False if it is in file

    Returns:
        bytes: PEM private key in byte format
    """
    if mem:
        priv_key = load_pem_private_key(
            keyfile,
            password=pwd,
        )
    else:
        with open(keyfile, "rb") as key_file:
            priv_key = load_pem_private_key(
                key_file.read(),
                password=pwd,
            )

    return priv_key


def session_key_data(rsa_key, data: bytes, operation: int) -> bytes:
    """Encrypt/Decrypt session key data in AES-256-OAEP using
       the rsa_key param as key.

    Args:
        rsa_key (RSAPublicKey): A public RSA Key use to Encrypt/Decrypt data,
        data (bytes): Data to Encrypt / Decrypt
        operation (int): Operation flag

    Returns:
        bytes: Encryption -> 256 bytes block cyphered session data
               Decryption -> decrypted session data
    """

    if operation == OP_CRYPT:
        x_data = rsa_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None,
            ),
        )

    if operation == OP_DECRYPT:
        x_data = rsa_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None,
            ),
        )

    return x_data


def encode_file(i_file, crt_or_domain, tip):
    o_file = i_file + ".crypt"

    # Crea una chiave di sessione da 32 bytes ed un nonce da 16 bytes

    gcm_session_key = os.urandom(CRYPT_GCM_SESSION_KEY_SIZE)
    gcm_nonce = os.urandom(CRYPT_GCM_TAG_SIZE)

    # Crea la copia cifrata della chiave di sessione utilizzando
    # come chiave la chaive pubblica RSA del certificato
    rsa_pub_key, cert_name = get_rsa_public_key(crt_or_domain, tip)
    rsa_enc_gcm_key = session_key_data(rsa_pub_key, gcm_session_key, OP_CRYPT)

    # Prepara la cifratura GCM utilizzando la chiave di sessione
    encryptor = Cipher(
        algorithms.AES(gcm_session_key),
        modes.GCM(gcm_nonce),  # type: ignore
    ).encryptor()  # type: ignore

    # Nel file criptato i primi tre blocchi sono la chiave di sessione
    # criptata (256 bytes), il valore nonce (16 bytes) e il valore del tag
    # (16 bytes) creati dal cifratore GCM.
    # Il tag viene creato alla fine della cifratura del file
    # pertanto all'inizio dell'operazione nel file viene memorizzato
    # un placeholder che, alla fine, sarà sostituito dal vero valore del tag.

    file_out = open(o_file, "wb")

    file_out.write(cert_name)  # 50 bytes
    file_out.write(rsa_enc_gcm_key)  # 256 bytes
    file_out.write(gcm_nonce)  # 16 bytes
    file_out.write(b"****************")

    # Il file da cifrare viene letto a blocchi ogni singolo blocco
    # viene cifrato e salvato nel file di uscita
    file_in = open(i_file, "rb")

    data = file_in.read(BUFFER_SIZE)
    while len(data) != 0:
        enc_data = encryptor.update(data)
        file_out.write(enc_data)
        data = file_in.read(BUFFER_SIZE)

    encryptor.finalize()

    tg = encryptor.tag  # type: ignore
    file_out.seek(CRYPT_TAG_POINTER, 0)
    file_out.write(tg)  # 16 bytes

    file_in.close()
    file_out.close()


def decode_file(i_file, pk_file, memop=False):
    o_file = i_file + ".copy"
    i_file = i_file + ".crypt"

    # Apre il file crittografato e legge la chiave di sessione crittografata
    # il nonce e il tag

    file_in = open(i_file, "rb")

    _ = file_in.read(CRYPT_KEY_LOCATOR_SIZE)
    rsa_enc_gcm_key = file_in.read(CRYPT_ENC_GCM_SIZE)
    nonce = file_in.read(CRYPT_GCM_NONCE_SIZE)
    tag = file_in.read(CRYPT_GCM_TAG_SIZE)

    # Utilizzando il file di chiave privata del certificato usato per cifrare
    # recupera e decifra la chiave di sessione GCM

    priv_rsa_key = get_rsa_private_key(pk_file, mem=memop)
    rsa_dec_gcm_key = session_key_data(priv_rsa_key, rsa_enc_gcm_key, OP_DECRYPT)

    # Prepara la decifratura GCM utilizzando la chiave di sessione
    # decifrata
    decryptor = Cipher(
        algorithms.AES(rsa_dec_gcm_key),
        modes.GCM(nonce, tag),  # type: ignore
    ).decryptor()  # type: ignore

    # Calcola la dimensione del file crittografato per controllare
    # da quanti blocchi interi è costituita la zona dati crittografata
    # al netto della deimsione del CRYPT_HEADER

    f_sz = os.path.getsize(i_file)
    enc_blk_size = f_sz - CRYPT_HEADER_SIZE
    enc_blk_nums = int(enc_blk_size / BUFFER_SIZE)
    enc_blk_xtra = int(enc_blk_size % BUFFER_SIZE)

    # Legge il file di ingresso blocco per blocco, lo decodifica
    # e lo scrive sul nuovo file decodificato
    file_out = open(o_file, "wb")

    for _ in range(enc_blk_nums):
        data = file_in.read(BUFFER_SIZE)
        decrypted_data = decryptor.update(data)
        file_out.write(decrypted_data)

    data = file_in.read(enc_blk_xtra)
    decrypted_data = decryptor.update(data)
    file_out.write(decrypted_data)

    # Chiede la verifica del tag al cifratore se il file
    # è correttamente decifrato la verifica sarà ok.
    # altrimenti distrugge il file decodificato in maniera errata
    try:
        decryptor.finalize()
    except ValueError:
        file_in.close()
        file_out.close()
        os.remove(o_file)
        pass

    file_in.close()
    file_out.close()


conf_book = get_config()


# encode_file("/home/mariano/Scrivania/Testfile.pdf", "www.magaldinnova.it", DNS) # noqa
# decode_file("/home/mariano/Scrivania/Testfile.pdf", "/home/mariano/Scrivania/MI.key") # noqa

#encode_file("/home/mariano/Scrivania/GDPRUtils-Data/Testfile.pdf", "/home/mariano/Scrivania/GDPRUtils-Data/GDPR_TEST_CERT.crt", CRT) # noqa
#kk = priv_key_request_for_file('/home/mariano/Scrivania/GDPRUtils-Data/Testfile.pdf.crypt') # noqa
#decode_file('/home/mariano/Scrivania/GDPRUtils-Data/Testfile.pdf', kk, True)

# pub_rsa_key = get_rsa_public_key('www.magaldinnova.it', DNS)
# enc_pub_rsa_key = get_enc_session_key(pub_rsa_key, b'1233456789')

# priv_rsa_key = get_rsa_private_key('/home/mariano/Scrivania/MI.key')
# dec_pub_rsa_key = get_dec_session_key(priv_rsa_key, enc_pub_rsa_key)
