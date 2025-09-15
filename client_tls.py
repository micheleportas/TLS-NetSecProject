import socket
from tlslite.api import TLSConnection, X509, X509CertChain
from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

HOST = "127.0.0.1"
PORT = 4443
EXPECTED_CN = "server-lab"

# Carica certificato trusted (self-signed server.crt)
with open("server.crt", "r") as f:
    certPEM = f.read()

x509 = X509()
x509.parse(certPEM)
trustedCertChain = X509CertChain([x509])

# Connessione TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# Wrappa con TLS
conn = TLSConnection(sock)

# Handshake client
conn.handshakeClientCert()

# Recupera certificato server (oggetto tlslite.X509)
server_cert_chain = conn.session.serverCertChain
server_cert = server_cert_chain.x509List[0]

# Confronto con certificato trusted (byte a byte)
if server_cert.bytes != x509.bytes:
    raise Exception("Errore di verifica: certificato server non corrisponde al trusted!")

# Parsing con cryptography per leggere il CN
cert = crypto_x509.load_der_x509_certificate(bytes(server_cert.bytes), default_backend())
subject = cert.subject
server_cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

if server_cn != EXPECTED_CN:
    raise Exception(f"Errore di verifica CN: atteso '{EXPECTED_CN}', ricevuto '{server_cn}'")

print(f"✔ Connessione sicura con server CN={server_cn}")

# Invia messaggio
conn.send(b"Ciao dal client TLS verificato con CN!\n")

# Riceve risposta
data = conn.recv(1024)
print("Risposta dal server:", data.decode(errors="ignore"))

conn.close()
