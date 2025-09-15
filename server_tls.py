from tlslite.api import TLSConnection, X509, X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
import socket
import sys

HOST = "0.0.0.0"
PORT = 4443

# Percorsi dei file PEM
CERT_PEM = "server.crt"
KEY_PEM = "server.key"

def load_cert_chain(cert_pem):
    """Carica il certificato X.509 da un file PEM e lo converte in una catena."""
    try:
        # Apri il file in modalità binaria ('rb')
        with open(cert_pem, "rb") as f:
            cert_data = f.read()
        cert = X509()
        cert.parse(cert_data)
        return X509CertChain([cert])
    except Exception as e:
        print(f"Errore nel caricamento del certificato: {e}")
        sys.exit(1)

def load_private_key(key_pem):
    """Carica la chiave privata da un file PEM."""
    try:
        with open(key_pem, "rb") as f:
            return parsePEMKey(f.read(), private=True)
    except Exception as e:
        print(f"Errore nel caricamento della chiave privata: {e}")
        sys.exit(1)

def main():
    """Avvia il server TLS e gestisce le connessioni dei client."""
    try:
        # Carica il certificato e la chiave privata
        cert_chain = load_cert_chain(CERT_PEM)
        priv_key = load_private_key(KEY_PEM)

        # Crea un socket standard
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[+] Server TLS in ascolto su {HOST}:{PORT}")

        while True:
            # Accetta una connessione TCP standard
            conn_sock, addr = s.accept()
            print(f"[*] Connessione da {addr}")
            
            # Esegui l'handshake TLS
            tls_conn = TLSConnection(conn_sock)
            try:
                tls_conn.handshakeServer(certChain=cert_chain, privateKey=priv_key)
                print("[*] Handshake TLS completato")
                
                # Ricevi i dati in byte e li decodifica in una stringa
                data = tls_conn.read()
                print("[*] Ricevuto (decrypted):", data.decode())
                
                # Rispondi al client con un messaggio in byte
                tls_conn.write(b"OK dal server TLS\n")
            
            except Exception as e:
                print(f"Errore handshake/connessione: {e}")
            
            finally:
                # Chiudi la connessione TLS
                tls_conn.close()

    except Exception as e:
        print(f"Errore fatale del server: {e}")
    finally:
        if 's' in locals():
            s.close()

if __name__ == "__main__":
    main()