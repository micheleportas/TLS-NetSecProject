import socket
from tlslite.api import TLSConnection, X509, X509CertChain, HandshakeSettings
from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

HOST = "127.0.0.1"
PORT = 4443
EXPECTED_CN = "server-lab"

# Versione TLS da proporre al server
# 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2
TLS_VERSION = 0x0302  # TLS 1.1

# Carica certificato trusted (self-signed server.crt)
with open("server.crt") as f:
    certPEM = f.read()

x509 = X509()
x509.parse(certPEM)
trustedCertChain = X509CertChain([x509])

# Connessione TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# Wrappa con TLS
conn = TLSConnection(sock)

# Configura handshake settings per proporre TLS 1.1
conn._handshakeSettings = HandshakeSettings()
# Nota: tlslite-ng ignora la forzatura se il server supporta versioni superiori
conn._handshakeSettings.minVersion = (3,2)  # TLS 1.1
conn._handshakeSettings.maxVersion = (3,2)  # TLS 1.1

# Handshake client
conn.handshakeClientCert()
print(f"✔ Handshake completata con TLS 1.1 (proposta)")

# Recupera certificato server
server_cert_chain = conn.session.serverCertChain
server_cert = server_cert_chain.x509List[0]

# Verifica certificato trusted
if server_cert.bytes != x509.bytes:
    raise Exception("Errore di verifica: certificato server non corrisponde al trusted!")

# Parsing con cryptography per leggere CN
cert = crypto_x509.load_der_x509_certificate(bytes(server_cert.bytes), default_backend())
server_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

if server_cn != EXPECTED_CN:
    raise Exception(f"Errore di verifica CN: atteso '{EXPECTED_CN}', ricevuto '{server_cn}'")

print(f"✔ Connessione sicura con server CN={server_cn}")

# Invia messaggio
conn.send(b"Ciao dal client TLS 1.1 verificato!\n")

# Riceve risposta
data = conn.recv(1024)
print("Risposta dal server:", data.decode(errors="ignore"))

# Controlla la versione TLS effettivamente negoziata
try:
    version_bytes = conn.session.versionBytes  # bytearray b'\x03\x02'
    negotiated_version = (version_bytes[0], version_bytes[1])
    print(f"TLS version negoziata (internal tlslite-ng): {negotiated_version}")
except AttributeError:
    print("Non è possibile leggere la versione TLS negoziata con tlslite-ng. "
          "Usa Wireshark per verificare ServerHello.")

conn.close()
