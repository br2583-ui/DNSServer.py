# DNSServer.py
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
from dns.rdtypes.ANY.TXT import TXT
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Fernet encrypt/decrypt helpers
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # returns bytes
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    """
    Accept either:
     - bytes (raw token) OR
     - str (token text returned by DNS TXT)
    Convert to bytes and decrypt.
    """
   
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Assignment parameters
salt = b"Tandon"                    # must be bytes
password = "br2583@nyu.edu"         # per guidelines
input_string = "AlwaysWatching"

# Create encrypted token (bytes). Store the bytes value in dns_records for nyu.edu.
encrypted_value = encrypt_with_aes(input_string, password, salt)  # bytes

# Sanity check locally (won't affect grader)
try:
    assert decrypt_with_aes(encrypted_value, password, salt) == input_string
except InvalidToken:
    # If this prints locally, the key derivation is wrong — but it should not be for correct password/salt.
    print("Local sanity check failed: decrypt error")

# For future use
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# DNS records
# NOTE: For nyu.edu TXT we store the token as bytes in a one-element list.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,  # refresh
            1800,  # retry
            604800,  # expire
            86400,  # minimum
        ),
    },
    'safebank.com.': {dns.rdatatype.A: '192.168.1.102'},
    'google.com.': {dns.rdatatype.A: '192.168.1.103'},
    'legitsite.com.': {dns.rdatatype.A: '192.168.1.104'},
    'yahoo.com.': {dns.rdatatype.A: '192.168.1.105'},
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        # IMPORTANT: store the encrypted token as bytes (in a list) to preserve exact token
        dns.rdatatype.TXT: [encrypted_value],
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

def run_dns_server():
    # UDP socket, bind to loopback port 53 (autograder expects port 53)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            if not request.question:
                server_socket.sendto(response.to_wire(), addr)
                continue

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))

                elif qtype == dns.rdatatype.SOA:
                    # SOA tuple format: (mname, rname, serial, refresh, retry, expire, minimum)
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA,
                                mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)

                elif qtype == dns.rdatatype.TXT:
                    # answer_data might contain bytes or str items
                    for item in answer_data:
                        if isinstance(item, bytes):
                            # decode bytes->str for the TXT constructor but do NOT alter bytes content
                            txt_str = item.decode('utf-8')
                        else:
                            txt_str = item
                        # TXT constructor takes a list of strings (each chunk)
                        rdata_list.append(TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [txt_str]))

                else:
                    # A, AAAA, NS, CNAME, etc.
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data)
                                      for data in answer_data]

                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            # Set AA flag (Authoritative Answer)
            response.flags |= 1 << 10

            # Print out the request handling
            print("Responding to request:", qname, "from", addr)

            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            # Print error but keep running
            print("Error handling request:", repr(e))

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()

