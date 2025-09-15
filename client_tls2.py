# READ THIS: client_tls2.py, è come client_tls.py, semplicemente scritto in modo diverso, non so quale sia meglio. In teoria client_tls.py fa più verifiche, quindi usiamo quello, questo lo teniamo se ci sono problemi.
import socket
from tlslite.api import TLSConnection

SERVER_ADDR = "localhost"   # es. 192.168.56.101
SERVER_PORT = 4443

def main():
    s = socket.socket()
    s.connect((SERVER_ADDR, SERVER_PORT))
    tls_conn = TLSConnection(s)
    try:
        # handshake client: versione di default (TLS1.2 con tlslite-ng)
        tls_conn.handshakeClientCert()  # semplice handshake client
        print("[*] Handshake client completato")
        tls_conn.write(b"Ciao server, messaggio TLS cifrato\n")
        resp = tls_conn.read()
        print("[>] Risposta server (decrypted):", resp.decode(errors="ignore"))
    except Exception as e:
        print("[!] Errore client TLS:", e)
    finally:
        tls_conn.close()

if __name__ == "__main__":
    main()
