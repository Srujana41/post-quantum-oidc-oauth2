import csv
import itertools
import json
import os
import subprocess
import sys

# calculate the token size in op in function idp_pqc_token before return
"""
with open('tokens.csv', mode='a', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    access_token_size = len(base64.b64decode(access_token.split(".")[2]))
    refresh_token_size = len(base64.b64decode(refresh_token.split(".")[2]))
    id_token_size = len(base64.b64decode(id_token.split(".")[2]))
    csv_writer.writerow([sign_alg, str(access_token_size), str(refresh_token_size), str(id_token_size)])
    
with open('pk_size.csv', mode='a', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    if KEY_TYPE == "PQC":
        jwk_size = len(base64.b64decode(str(KEYJAR.dump_issuer_keys("")[0].get('key'))))
    else:
        jwk_size = len(base64.b64decode(str(KEYJAR.dump_issuer_keys("")[0].get('key')).split("-\n")[1].split("\n-")[0]))
    csv_writer.writerow([JWT_SIGN, str(jwk_size)])
    
""" 
    
session_state = ""
class Packet:

    def __init__(self, packet):
        self._packet = packet
        self._tcp = packet["_source"]["layers"]["tcp"]
        self._tls = packet["_source"]["layers"].get("tls")
        self._frame = packet["_source"]["layers"]["frame"]

    @property
    def srcport(self):
        return self._tcp["tcp.srcport"]

    @property
    def dstport(self):
        return self._tcp["tcp.dstport"]

    @property
    def is_tls(self):
        return self._tls is not None
    
    @property
    def time(self):
        return self._frame["frame.time_epoch"]
    
    @property
    def tls_records(self):
        if not self.is_tls:
            raise ValueError
        if isinstance(self._tls, list):
            all_records = []
            for tls_item in self._tls:
                records = tls_item['tls.record']
                if isinstance(records, list):
                    all_records.extend(records)
                else:
                    all_records.append(records)
            return all_records
        # just a singular tls record
        records = self._tls['tls.record']
        if isinstance(records, list):
            return records
        else:
            return [records]

    def is_css(self):
        return any(record.get('tls.change_cipher_spec', False) == "" for record in self.tls_records)

    @property
    def is_client_hello(self):
        hs = self.tls_records[0].get('tls.handshake')
        if not hs:
            return False
        return hs['tls.handshake.type'] == "1"

    @property
    def is_server_hello(self):
        hs = self.tls_records[0].get('tls.handshake')
        if not hs:
            return False
        return hs['tls.handshake.type'] == "2"

    @property
    def tcp_payload_size(self):
        return int(self._tcp['tcp.len'])

def length(record):
    return 5 + int(record['tls.record.length'])

def calculate_tls_size_for_file(filepath, algorithm):
    command = "tshark -r {} -R tls -2 -Tjson --no-duplicate-keys > {}.json".format(filepath, pcap_directory+algorithm)
    return_code = subprocess.call(command, shell=True)
    with open(pcap_directory+algorithm + '.json') as f:
        data = json.load(f)

    client_port = None
    server_port = None

    handshakes = []
    for packet in [Packet(p) for p in data]:
        if not packet.is_tls:
            continue
        print(f"Packet: {packet.srcport} -> {packet.dstport}: {packet.tcp_payload_size} bytes")
        if packet.is_client_hello:
            client_port = packet.srcport
            server_port = packet.dstport
            handshakes.append([])
        handshakes[-1].append(packet)

    for handshake in handshakes:
        size = 0
        # Client Hello
        
        start_time = float(handshake[0].time)
        end_time = float(handshake[len(handshake)-1].time)
        
        clmsgs = list(filter(lambda p: p.dstport == server_port, handshake))
        cmsgiter = itertools.chain.from_iterable(msg.tls_records for msg in clmsgs)

        assert clmsgs[0].is_client_hello
        size += (msgsize := length(next(cmsgiter)))
        client_hello_size = msgsize
        print(f"Client hello size: {msgsize}")

        # Server Hello, CSS, EE, Cert, CertV, SFIN
        # chain all next server->client messages
        servmsgs = list(filter(lambda p: p.srcport == server_port, handshake))
        smsgiter = itertools.chain.from_iterable(msg.tls_records for msg in servmsgs)
        assert servmsgs[0].is_server_hello

        size += (msgsize := length(next(smsgiter)))
        server_hello_size = msgsize
        print(f"Server hello size: {msgsize}")

        size += (msgsize := length(next(smsgiter)))
        assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
        change_cipher_spec_size = msgsize
        print(f"ChangeCipherSpec size: {msgsize}")

        size += (msgsize := length(next(smsgiter)))
        encrypted_extensions_size = msgsize
        print(f"EncryptedExtensions size: {msgsize}")

        try:
            cert_size = (msgsize := length(next(smsgiter)))
        except Exception as e:
            continue
        while msgsize == 16406:  # magic constant for large msgs that got fragmented by TLS
            cert_size += (msgsize := length(next(smsgiter)))
        size += cert_size
        certificate_size = cert_size
        print(f"Certificate size: {cert_size}")
        size += (msgsize := length(next(smsgiter)))
        certificate_verify_size = msgsize
        print(f"CertificateVerify size: {msgsize}")
        size += (msgsize := length(next(smsgiter)))
        server_finished_size = msgsize
        print(f"ServerFinished size: {msgsize}")
        # assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"

        # CSS, ClientFinished
        size += (msgsize := length(next(cmsgiter)))
        # assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
        change_cipher_spec_client_finished_size = msgsize
        print(f"ChangeCipherSpec size: {msgsize}")

        size += (msgsize := length(next(cmsgiter)))
        client_finished_size = msgsize
        print(f"ClientFinished size: {msgsize}")
        # assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"
        total_size = size
        print(f"Total size: {size}")
        total_handshake = len(handshakes)
        tls_time = ((end_time - start_time) / 1000) * total_handshake
        return client_hello_size, server_hello_size, change_cipher_spec_size, encrypted_extensions_size, certificate_size, certificate_verify_size, server_finished_size, change_cipher_spec_client_finished_size, client_finished_size, total_size, total_handshake, tls_time


pcap_directory = 'results/172.27.96.243-172.27.96.250/all-1-2023-10-06-06-01-27/'

tcp_dump_directory = pcap_directory + "tcpdump"
ssl_keylog_directory = "tls_debug"
output_csv_file =  pcap_directory + 'tls_sizes.csv'
csv_data = []

# Iterate through each PCAP file in the directory.
for pcap_file in os.listdir(tcp_dump_directory):
    if pcap_file.endswith('.pcap'):
        file_path = os.path.join(tcp_dump_directory, pcap_file)
        algorithm = pcap_file.split(".")[0]
        ssl_key_file = os.path.join(ssl_keylog_directory, "TLS=" + pcap_file.split(".")[0] + ".tls_debug")

        # Calculate times for TLS and HTTPS for the current file.
        client_hello_size, server_hello_size, change_cipher_spec_size, encrypted_extensions_size, certificate_size, certificate_verify_size, server_finished_size, change_cipher_spec_client_finished_size, client_finished_size, total_size, total_handshake, tls_time = calculate_tls_size_for_file(file_path, algorithm)

        # Append data for CSV export: [File Name, TLS Time, HTTPS Time, Ratio]
        csv_data.append([algorithm, client_hello_size, server_hello_size, change_cipher_spec_size, encrypted_extensions_size, certificate_size, certificate_verify_size, server_finished_size, change_cipher_spec_client_finished_size, client_finished_size, total_size, total_handshake, tls_time])

with open(output_csv_file, mode='w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)

    # Write header row.
    csv_writer.writerow(['algorithm', 'client_hello_size', 'server_hello_size', 'change_cipher_spec_size',
                         'encrypted_extensions_size',
                         'certificate_size', 'certificate_verify_size', 'server_finished_size',
                         'change_cipher_spec_client_finished_size',
                         'client_finished_size', 'total_size', 'total_handshake', 'tls_time'
                         ])

    # Write the data rows.
    csv_writer.writerows(csv_data)

print(f'Data exported to {output_csv_file}')
