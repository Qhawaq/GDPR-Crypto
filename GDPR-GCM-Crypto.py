import os
import ssl
import sys
import OpenSSL

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

DNS = 0
CRT = 1
BUFFER_SIZE = 1024 * 1024


# Estrae la chiave pubblica da un certificato on line
# o da un file .crt (PEM) locale, restituisce la chiave pubblica in
# formato RSA.

def get_rsa_public_key( cert_or_domain_name, tip ):
    if tip == DNS:
		cert = ssl.get_server_certificate((cert_or_domain_name, 443))
	if tip == CRT:
		cert = open(cert_or_domani_name).read()
	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
	pub_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM,x509.get_pubkey())
	rsa_key = RSA.import_key(pub_key)
	return ( rsa_key )
	

# Estrae la chiave privata da un file .key (PEM)
# restituisce la chiave privata in formato RSA

def get_rsa_private_key ( p_key_file ):
	rsa_key = RSA.import_key(open(p_key_file).read())
	return (rsa_key)
	

# Cifra un blocco di max 190 bytes utilizzando una chiave pubblica in formato RSA
# tramite PKCS1 OAEP, ritorna un blocco fisso di 256 bytes

def get_enc_session_key ( rsa_key, data ):
	cph_rsa = PKCS1_OAEP.new(rsa_key) 
	data_enc = cph_rsa.encrypt(data) 
	return ( data_enc )


# Decifra un blocco PKCS1 OAEP utilizzando una chiave privata in formato RSA
# del certificato.

def get_dec_session_key ( rsa_key, data):
	cph_rsa = PKCS1_OAEP.new(rsa_key)
	data_dec = cph_rsa.decrypt(data)
	return ( data_dec )
	

	
def encode_file ( i_file, crt_or_domain, tip ):

	o_file = i_file+'.crypt'
	
	# Crea una chiave casuale di sessione da 32 bytes
	gcm_session_key = get_random_bytes(32) 	
	
	# Crea la copia cifrata della chiave di sessione utilizzando 
	# come chiave la chaive pubblica RSA del certificato
	rsa_pub_key = get_rsa_public_key ( crt_or_domain, tip )
	rsa_enc_gcm_key = get_enc_session_key( rsa_pub_key, gcm_session_key )
	
	# Prepara la cifratura GCM utilizzando la chiave di sessione
	cipher = AES.new( gcm_session_key, AES.MODE_GCM) 

	# Nel file criptato i primi due blocchi sono la chiave di sessione
	# criptata (256 bytes) e il valore nonce (16 bytes) del creato dal 
	# cifratore GCM.
	
	file_out = open(o_file, 'wb')

	file_out.write(rsa_enc_gcm_key) # 256 bytes
	file_out.write(cipher.nonce) 	# 16 bytes

	# Il file da cifrare viene letto a blocchi ogni singolo blocco
	# viene cifrato e salvato nel file cifrato
	file_in = open(i_file, 'rb') 

	data = file_in.read(BUFFER_SIZE) 
    while len(data) != 0: 
        enc_data = cipher.encrypt(data) 
        file_out.write(enc_data)  
        data = file_in.read(BUFFER_SIZE) 

	# Viene aggiunto il valore del tag (16 bytes) emesso dal cifratore GCM
	# al file cifrato 
	
    tag=cipher.digest()
    file_out.write(tag)	# 16 bytes

    file_in.close()
    file_out.close()



def decode_file ( i_file, pk_file ): 

	o_file = i_file +'.copy'
	i_file = i_file +'.crypt'

	# Apre il file crittografato e legge la chiave di sessione crittografata
	# e il nonce 
	file_in = open(i_file, 'rb')

	rsa_enc_gcm_key = file_in.read(256) 
	nonce = file_in.read(16) 

	# Utilizzando il file di chiave privata del certtificato usato per cifrare 
	# recupera e decifra la chiave di sessione GCM
	private_key = RSA.import_key(open(pk_file).read())
	cph_rsa = PKCS1_OAEP.new(private_key)
	rsa_dec_gcm_key = cph_rsa.decrypt(rsa_enc_gcm_key)

	# Prepara la decifratura GCM utilizzando la chiave di sessione 
	# decifrata 
	cipher = AES.new(rsa_dec_gcm_key, AES.MODE_GCM, nonce=nonce)

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
	    decrypted_data = cipher.decrypt(data) 
	    file_out.write(decrypted_data) 

	# Legge il "Fuori blocco" contenente il tag
	#
	data = file_in.read(int(encrypted_data_size % BUFFER_SIZE)) 
	decrypted_data = cipher.decrypt(data) 
	file_out.write(decrypted_data) 

	tag = file_in.read(16)
	
	# Chiede la verifica del tag al cifratore se il file 
	# è correttamente decifrato la verifica sarà ok.
	# altrimenti distrugge il file decodificato in maniera errata
	try:
    		cipher.verify(tag)
	except ValueError as e:
    		file_in.close()
    		file_out.close()
    		os.remove(output_filename)
    		raise e

	file_in.close()
	file_out.close()


#encode_file ( 'Testfile.pdf','www.magaldinnova.it', DNS )
decode_file('Testfile.pdf','MI.key')
