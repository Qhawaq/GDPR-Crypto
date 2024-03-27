import os
import ssl
import time
import yaml
import requests

from cryptography import x509
# from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.twofactor.totp import TOTP
# from cryptography.hazmat.primitives.keywrap import aes_key_unwrap


DNS = 0
CRT = 1
BUFFER_SIZE = 1024 * 1024

conf_book = []


def make_request():
    mysel= 'sel=AAA'
    myid = '&id='+conf_book['rest']['id']
    myval = '&val='+get_totp_code().decode()
    url = conf_book['rest']['url'] + ':' + str(conf_book['rest']['port'])+'/req?'+mysel+myid+myval
    print(url)
    r = requests.get(url)
    print(r.text)


def get_config():

    with open('GCM-config.yml', 'r') as fconf:
        conf_var = yaml.safe_load(fconf)
    return (conf_var)


def get_totp_code():

    seed = conf_book['otp_id']['seed']
    key = bytes.fromhex(seed)
    totp = TOTP(key, 8, hashes.SHA256(), 30)
    time_value = time.time()
    t_value = totp.generate(int(time_value))
    return (t_value)


def get_rsa_public_key(cert_or_domain_name, tip):

    if tip == DNS:
        cert = ssl.get_server_certificate((cert_or_domain_name, 443))

    if tip == CRT:
        cert = open(cert_or_domain_name).read()

    cert = bytes(ssl.get_server_certificate(
                (cert_or_domain_name, 443)), 'utf-8')
    cert_obj = x509.load_pem_x509_certificate(cert)
    pub_key_rsa = cert_obj.public_key()

    return (pub_key_rsa)


def get_rsa_private_key(keyfile):

    with open(keyfile, "rb") as key_file:
        priv_key = serialization.load_pem_private_key(
                    key_file.read(), password=None, )

    return (priv_key)


def get_enc_session_key(rsa_key, data):

    enc_data = rsa_key.encrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return (enc_data)


def get_dec_session_key(rsa_key, data):

    dec_data = rsa_key.decrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return (dec_data)


def encode_file(i_file, crt_or_domain, tip):

    o_file = i_file+'.crypt'

    # Crea una chiave di sessione da 32 bytes ed un nonce da 16 bytes

    gcm_session_key = os.urandom(32)
    gcm_nonce = os.urandom(16)

    # Crea la copia cifrata della chiave di sessione utilizzando
    # come chiave la chaive pubblica RSA del certificato
    rsa_pub_key = get_rsa_public_key(crt_or_domain, tip)
    rsa_enc_gcm_key = get_enc_session_key(rsa_pub_key, gcm_session_key)

    # Prepara la cifratura GCM utilizzando la chiave di sessione
    encryptor = Cipher(algorithms.AES(gcm_session_key),
                       modes.GCM(gcm_nonce),).encryptor()  # type: ignore

    # Nel file criptato i primi tre blocchi sono la chiave di sessione
    # criptata (256 bytes), il valore nonce (16 bytes) e il valore del tag
    # (16 bytes) creati dal cifratore GCM.
    # Il tag viene creato alla fine della cifratura del file
    # pertanto all'inizio dell'operazione nel file viene memorizzato
    # un placeholder che, alla fine, sarà sostituito dal vero valore del tag.

    file_out = open(o_file, 'wb')

    file_out.write(rsa_enc_gcm_key)  # 256 bytes
    file_out.write(gcm_nonce) 	 # 16 bytes
    file_out.write(b'****************')

    # Il file da cifrare viene letto a blocchi ogni singolo blocco
    # viene cifrato e salvato nel file di uscita
    file_in = open(i_file, 'rb')

    data = file_in.read(BUFFER_SIZE)
    while len(data) != 0:
        enc_data = encryptor.update(data)
        file_out.write(enc_data)
        data = file_in.read(BUFFER_SIZE)

    # Viene aggiunto il valore del tag (16 bytes) emesso dal cifratore GCM
    # al file cifrato
    encryptor.finalize()

    tg = encryptor.tag  # type: ignore
    file_out.seek(272, 0)
    file_out.write(tg)	 # 16 bytes

    file_in.close()
    file_out.close()


def decode_file(i_file, pk_file):

    o_file = i_file + '.copy'
    i_file = i_file + '.crypt'

    # Apre il file crittografato e legge la chiave di sessione crittografata
    # il nonce e il tag

    file_in = open(i_file, 'rb')

    rsa_enc_gcm_key = file_in.read(256)
    nonce = file_in.read(16)
    tag = file_in.read(16)

    # Utilizzando il file di chiave privata del certtificato usato per cifrare
    # recupera e decifra la chiave di sessione GCM

    priv_rsa_key = get_rsa_private_key(pk_file)
    rsa_dec_gcm_key = get_dec_session_key(priv_rsa_key, rsa_enc_gcm_key)

    # Prepara la decifratura GCM utilizzando la chiave di sessione
    # decifrata
    decryptor = Cipher(algorithms.AES(rsa_dec_gcm_key),
                       modes.GCM(nonce, tag), ).decryptor()  # type: ignore

    # Calcola la dimensione del file crittografato per controllare
    # da quanti blocchi interi è costituita la zona dati crittografata
    # al netto della chiave del nonce e del tag

    file_in_size = os.path.getsize(i_file)
    encrypted_data_size = file_in_size - 256 - 16 - 16

    # Legge il file di ingresso blocco per blocco, lo decodifica
    # e lo scrive sul nuovo file decodificato
    file_out = open(o_file, 'wb')

    for _ in range(int(encrypted_data_size / BUFFER_SIZE)):
        data = file_in.read(BUFFER_SIZE)
        decrypted_data = decryptor.update(data)
        file_out.write(decrypted_data)

    # Legge il "Fuori blocco" contenente il tag
    #
    data = file_in.read(int(encrypted_data_size % BUFFER_SIZE))
    decrypted_data = decryptor.update(data)
    file_out.write(decrypted_data)

    # Chiede la verifica del tag al cifratore se il file
    # è correttamente decifrato la verifica sarà ok.
    # altrimenti distrugge il file decodificato in maniera errata
    try:
        decryptor.finalize()
    except ValueError as e:
        file_in.close()
        file_out.close()
        os.remove(o_file)
        raise e

    file_in.close()
    file_out.close()


# encode_file('/home/mariano/Scrivania/Testfile.pdf',
#            'www.magaldinnova.it', DNS)

# decode_file('/home/mariano/Scrivania/Testfile.pdf',
#            '/home/mariano/Scrivania/MI.key')

conf_book = get_config()
print(get_totp_code())
make_request()
# pub_rsa_key = get_rsa_public_key('www.magaldinnova.it', DNS)
# enc_pub_rsa_key = get_enc_session_key(pub_rsa_key, b'1233456789')

# priv_rsa_key = get_rsa_private_key('/home/mariano/Scrivania/MI.key')
# dec_pub_rsa_key = get_dec_session_key(priv_rsa_key, enc_pub_rsa_key)
