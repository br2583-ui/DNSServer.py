# DNSServer.py
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
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

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    # Accept either bytes or str; ensure bytes for Fernet.decrypt
    if isinstance(encrypted_data, str):
        encrypted_bytes = encrypted_data.encode('utf-8')
    else:
        encrypted_bytes = encrypted_data
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_bytes)
    return decrypted_data.decode('utf-8')

# Assignment parameters
salt = b"Tandon"
password = "br2583@nyu.edu"
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt)  # bytes
# decode once for storing in TXT (plain string token)
encrypted_token_str = encrypted_value.decode()  # e.g. "gAAAAA...."
# optional sanity check (not used by grader)
try:
    _ = decrypt_with_aes(encrypted_value, password, salt)
except InvalidToken:
    print("Local decrypt sanity check failed (this shouldn't happen)")

# For future use
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# DNS records required by assignment
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
        # crucial: store the token string (decoded once)
        dns.rdatatype.TXT: (encrypted_token_str,),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # bind to loopback and standard DNS port (53). Use elevated privileges if required.
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            if not request.question:
                # no question; ignore
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
                    # (mname, rname, serial, refresh, retry, expire, minimum)
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname,
                                serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)

                else:
                    # Special-case TXT: explicitly quote the text so DNS wire format contains exact token
                    if qtype == dns.rdatatype.TXT:
                        # answer_data is an iterable of strings; build rdata items with explicit quotes
                        for data_str in answer_data:
                            # wrap in quotes for dns.rdata.from_text so it's preserved exactly
                            quoted = '"' + data_str + '"'
                            rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, qtype, quoted))
                    else:
                        # general case: A, AAAA, NS, etc.
                        if isinstance(answer_data, str):
                            rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                        else:
                            rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data)
                                          for data in answer_data]

                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            # Set AA flag (authoritative)
            response.flags |= 1 << 10

            print("Responding to request:", qname, "from", addr)
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            # print and continue so autograder can keep testing
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

    input_thread = threading.Thread()
