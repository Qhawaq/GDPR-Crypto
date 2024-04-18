import sys
sys.path.append('/home/mariano/Documenti/RepoSoftware/GDPR-Crypto/GDPRUtils/src/') # noqa

from GDPRUtils.Keymaster.keyvault import store_keyfile
from GDPRUtils.Peer.filecrypto import encode_file, decode_file
from GDPRUtils.Peer.filecrypto import priv_key_request_for_file

DNS = 0
CRT = 1

#store_keyfile('/home/mariano/Scrivania/GDPRUtils-Data/GDPR_TEST_CERT.pem', 'GDPR_TEST_CERT') # noqa

#encode_file("/home/mariano/Scrivania/GDPRUtils-Data/Testfile.pdf", "/home/mariano/Scrivania/GDPRUtils-Data/GDPR_TEST_CERT.crt", CRT) # noqa
kk = priv_key_request_for_file('/home/mariano/Scrivania/GDPRUtils-Data/Testfile.pdf.crypt') # noqa
decode_file('/home/mariano/Scrivania/GDPRUtils-Data/Testfile.pdf', kk, True)
