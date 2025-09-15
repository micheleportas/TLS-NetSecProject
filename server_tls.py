# server_tls.py
# Esempio didattico: server TLS minimal con tlslite-ng (solo per laboratorio)
from tlslite.api import TLSConnection, parsePEMKey, X509CertChain
import socket

HOST = "0.0.0.0"
PORT = 4443

# Carica certificato e chiave (PEM)
# Genera self-signed con openssl se non li hai ancora
CERT_PEM = "server.crt"   # file PEM con certificato
KEY_PEM = "server.key"    # file PEM con chiave privata

def load_cert_chain(cert_pem):
    with open(cert_pem, "rb") as f:
        return X509CertChain.fromPEMBytes(f.read())

def load_private_key(key_pem):
    with open(key_pem, "rb") as f:
        return parsePEMKey(f.read(), private=True)

def handle_client(conn_sock, cert_chain, priv_key):
    tls_conn = TLSConnection(conn_sock)
    # Server-side handshake: accetta connessioni TLS 1.0/1.1/1.2 a scopo didattico
    try:
        tls_conn.connectionServer(certChain=cert_chain, privateKey=priv_key, reqCert=False)
        print("[*] Handshake completato")
        # Leggi un messaggio semplice (non HTTP, per semplicità)
        data = tls_conn.read()
        print("[*] Ricevuto (decrypted):", data)
        tls_conn.write(b"OK dal server TLS\n")
    except Exception as e:
        print("Errore handshake/connessione:", e)
    finally:
        tls_conn.close()

def main():
    cert_chain = load_cert_chain(CERT_PEM)
    priv_key = load_private_key(KEY_PEM)

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[+] Server TLS in ascolto su {HOST}:{PORT}")
    while True:
        cli, addr = s.accept()
        print("[*] Connessione da", addr)
        handle_client(cli, cert_chain, priv_key)

if __name__ == "__main__":
    main()
