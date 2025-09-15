import socket
from tlslite.api import TLSConnection, X509, X509CertChain, parsePEMKey

# Carica certificato e chiave
with open("server.crt", "r") as f:
    certPEM = f.read()
with open("server.key", "r") as f:
    keyPEM = f.read()

x509 = X509()
x509.parse(certPEM)
certChain = X509CertChain([x509])
privateKey = parsePEMKey(keyPEM, private=True)

# Crea socket TCP
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(("0.0.0.0", 4443))
server_sock.listen(5)

print("Server TLS in ascolto su porta 4443...")

while True:
    sock, addr = server_sock.accept()
    print(f"Connessione da {addr}")

    # Wrappa la socket con TLS
    conn = TLSConnection(sock)
    conn.handshakeServer(certChain=certChain, privateKey=privateKey)

    # Riceve e manda messaggi
    data = conn.recv(1024)
    print(f"Ricevuto: {data.decode(errors='ignore')}")
    conn.send(b"Ciao dal server TLS!\n")

    conn.close()
