import subprocess

SERVER = "192.168.91.135:8080" # insert the attacker IP address (leave the port 8080)

def try_openssl(version_flag, fallback_protection=None):
    cmd = ["/usr/local/ssl-1.0.1j/bin/openssl", "s_client", "-connect", SERVER, version_flag] 
    if fallback_protection:
        cmd.append(fallback_protection)

    result = subprocess.run( # executes: /usr/local/ssl-1.0.1j/bin/openssl s_client -connect <server_ip> [-fallback_scsv]
        cmd,
        input=b"",
        capture_output=True,
    )
    output = result.stdout.decode()
    if "Cipher is (NONE)" in output:
        print(f"Connection {version_flag} failed")
        return False, output
    else:
        print(f"Connection {version_flag} succeded")
        return True, output


print("Menu:")
print("1) NO FALLBACK_SCSV")
print("2) FALLBACK_SCSV")

choice = input("\nChoose a mode: ")

if choice not in ['1','2']:
    print("Choice not valid, using mode 1 by default.")
    choice = '1'

print(f"Sending TLS 1.2 request...")

if choice == '1': # Without FALLBACK_SCSV
    ok, out = try_openssl("-tls1_2")
    if not ok:
        print(f"Something went wrong: downgrading TLS version to 1.1")
        ok, out = try_openssl("-tls1_1")

elif choice == '2': # WIth FALLBACK_SCSV
    ok, out = try_openssl("-tls1_2", "-fallback_scsv")
    if not ok:
        print(f"Something went wrong: downgrading TLS version to 1.1 (FALLBACK_SCSV)")
        ok, out = try_openssl("-tls1_1", "-fallback_scsv")

else:
    print("Choice not valid")
    exit(1)

print(out)
