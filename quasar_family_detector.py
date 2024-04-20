#! /usr/bin/env python3

import os
import socket
import ssl
import time
import OpenSSL
import gzip
import msgpack
import select
import hashlib
import json
import collections.abc
import subprocess
import argparse
from tabulate import tabulate
from datetime import datetime

from scapy.all import *
from scapy.sendrecv import AsyncSniffer
from jarm.scanner.scanner import Scanner as JarmScanner
from pwn import p32
from dataclasses import dataclass
from contextlib import contextmanager

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 


def generate_c2_packet(rat_name, message_type):
    packet_key_string = "Packet" if rat_name == "AsyncRAT" else "Pac_ket"
    payload = gzip.compress(msgpack.packb({packet_key_string.encode("utf-8"): message_type.encode("utf-8")}))
    payload_header = p32(len(payload))
    payload = payload_header + payload
    return p32(len(payload)) + payload


@dataclass
class QuasarRatIndicators:
    default_port = 4782
    tls_version = "TLSv1.2"
    jarm_hashes = ["2ad2ad16d2ad2ad0002ad2ad2ad2add3b67dd3674d9af9dd91c1955a35d0e9",
                   "22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9",
                   "26d26d16d26d26d00026d26d26d26dd3b67dd3674d9af9dd91c1955a35d0e9"]
    ja3s_hashes = ["364ff14b04ef93c3b4cfa429d729c0d9",
                   "8529fd8de0d7f73186ef5ea8b4531a76",
                   "ae4edc6faf64d08308082ad26be60767",
                   "649d6810e8392f63dc311eecb6b7098b"]
    ja4s = "t120200_c030_5333cdffa7d9"
    ja4x = "7022c563de38_7022c563de38_0147df7a0c11"
    subject_cn = "Quasar Server CA"
    issuer_cn = "Quasar Server CA"
    cert_validity_not_after = "99991231235959Z"
    serial_number_length = 15
    cert_algorithm = "sha512WithRSAEncryption"
    #tcp_keep_alive_interval = 25 #seconds


@dataclass
class AsyncRatIndicators:
    default_ports = [6606, 7707, 8808]
    tls_version = "TLSv1"
    jarm_hashes = ["22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9",
                   "1dd40d40d00040d1dc1dd40d1dd40d3df2d6a0c2caaa0dc59908f0d3602943"]
    ja3s_hash = "b74704234e6128f33bff9865696e31b3"
    ja4s = "t100200_c014_5333cdffa7d9"
    ja4x = "7022c563de38_7022c563de38_0147df7a0c11"
    subject_cn = "AsyncRAT Server"
    issuer_cn = "AsyncRAT Server"
    cert_validity_not_after = "99991231235959Z"
    serial_number_length = 15
    cert_algorithm = "sha512WithRSAEncryption"
    #tcp_keep_alive_interval = 10 #seconds
    ping_packet = generate_c2_packet("AsyncRAT", "Ping")


@dataclass
class DcRatIndicators:
    default_port = 8848
    tls_version = "TLSv1"
    jarm_hashes = ["22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9",
                   "22b22b09b22b22b22b22b22b22b22bfd9c9d14e4f4f67f94f0359f8b28f532"]
    ja3s_hashes = "b74704234e6128f33bff9865696e31b3"
    ja4s = "t100200_c014_5333cdffa7d9"
    ja4x = "c9ed8d15cf91_7022c563de38_0147df7a0c11"
    subject_cn = "DcRat"
    issuer_dict = {"CN": "DcRat Server", "OU": "qwqdanchun", "O": "DcRat By qwqdanchun", "L": "SH", "C": "CN"}
    cert_validity_period = 3935 #days
    serial_number_length = 20
    cert_algorithm = "sha512WithRSAEncryption"
    #tcp_keep_alive_interval = 10 #seconds
    ping_packet = generate_c2_packet("DcRAT", "Ping")


@dataclass
class VenomRatIndicators:
    tls_version = "TLSv1"
    jarm_hashes = ["22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9"]
    ja3s_hashes = "b74704234e6128f33bff9865696e31b3"
    ja4s = "t100200_c014_5333cdffa7d9"
    ja4x = "c9ed8d15cf91_7022c563de38_0147df7a0c11"
    subject_cn = "VenomRAT"
    issuer_dict = {"CN": "VenomRAT Server", "OU": "qwqdanchun", "O": "VenomRAT By qwqdanchun", "L": "SH", "C": "CN"}
    cert_validity_period = 3935 #days
    serial_number_length = 20
    cert_algorithm = "sha512WithRSAEncryption"
    ping_packet = generate_c2_packet("VenomRAT", "Ping")


@dataclass
class CollectedIndicators:
    port: int
    tls_version: str
    jarm: str
    ja3s: str
    ja4s: str
    ja4x: str
    cert_infos: dict
    guess_from_custom_scan: str
    #tcp_keep_alive_interval: int


@contextmanager
def tls_connection(interface, ip, port, tls_version):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(interface.encode("utf-8")))
    sock.settimeout(10) # in seconds
    context = ssl.SSLContext(tls_version)
    context.set_ciphers('DEFAULT:@SECLEVEL=0')
    context.verify_mode = ssl.CERT_NONE
    wrapped_socket = context.wrap_socket(sock)
    wrapped_socket.connect((ip, port))
    try:
        yield wrapped_socket
    finally:
        wrapped_socket.close()


def get_response_to_packet(ssock, packet):
    ssock.send(packet)
    raw_response = b""
    now = time.time()
    while True:
        if time.time() - now > 10:
            return raw_response
        ready = select.select([ssock], [], [], 2)
        if ready[0]:
            raw_response += ssock.recv(4096)
        else:
            return raw_response


def decode_packed_packet(input):
    payload_size = int.from_bytes(input[:4], "little")
    if (payload_size != len(input) - 4):
        return dict()
    return msgpack.unpackb(gzip.decompress(input[8:]))


def concat(data):
    result = []
    for d in data:
        if isinstance(d, collections.abc.Iterable):
            result.append("-".join(map(str, d)))
        else:
            result.append(str(d))
    return ",".join(result)


def get_attr(obj, attr, default=""):
    value = getattr(obj, attr, default)
    if value is None:
        value = default
    return value


def calculate_ja3s(msg):
    try:
        tls_version = msg.version
    except AttributeError:
        return
    cipher = get_attr(msg, "cipher")
    exts = get_attr(msg, "ext")
    if exts:
        extensions_type = list(map(lambda c: c.type, exts))
    else:
        extensions_type = []
    value = [tls_version, cipher, extensions_type]
    return hashlib.md5(concat(value).encode("utf8")).hexdigest()


def collect_indicators(interface, ip, port, keep_pcap):
    # determine jarm hash
    jarm = JarmScanner.scan(dest_host=ip, dest_port=port, timeout=10)[0]
    if jarm == "00000000000000000000000000000000000000000000000000000000000000":
        print(f"\nERROR: failed to connect to {ip}:{port}")
        exit(2)

    # start packet capturing for calculating JA hashes later on
    pcap_filename = "quasarscan_" + time.strftime("%Y%m%d_%H%M%S") + ".pcap"
    async_sniffer = AsyncSniffer(iface=interface, filter=f"tcp and host {ip} and port {port}",
                                 prn=lambda pkt: wrpcap(pcap_filename, pkt, append=True))
    async_sniffer.start()
    time.sleep(1)

    der_cert = bytes()
    guess_from_custom_scan, tls_version = "", ""

    # --------------------------------------------------------
    # send custom crafted C2 packets:
    try:
        # try QuasarRAT indicator
        with tls_connection(interface, ip, port, ssl.PROTOCOL_TLSv1_2) as conn:
            der_cert = conn.getpeercert(True)
            tls_version = conn.version()
            conn.send(b"\x00\x00\x00")
            try:
                conn.recv(4096)
            except TimeoutError:
                # connection still established
                conn.send(b"\x00")
                try:
                    response = conn.recv(4096)
                    if response == b"":
                        # disconnect
                        guess_from_custom_scan = "QuasarRAT"
                except TimeoutError:
                    pass
    except ssl.SSLError as ssl_err:
        if ssl_err.reason != "WRONG_SSL_VERSION":
            print(ssl_err)
            exit(3)

    if guess_from_custom_scan == "":
        _ = async_sniffer.stop()
        async_sniffer.start()
        time.sleep(1)
        try:
            # try to send valid AsyncRAT and DcRAT packets
            with tls_connection(interface, ip, port, ssl.PROTOCOL_TLSv1) as conn:
                tls_version = conn.version()
                if der_cert == b"":
                    der_cert = conn.getpeercert(True)
                try:
                    raw_ping_response = get_response_to_packet(conn, AsyncRatIndicators.ping_packet)
                    if raw_ping_response != b"":
                        decoded_response = decode_packed_packet(raw_ping_response)
                        if decoded_response == {b'Packet': b'pong'}:
                            guess_from_custom_scan = "AsyncRAT"
                    else:
                        raw_ping_response = get_response_to_packet(conn, DcRatIndicators.ping_packet)
                        if raw_ping_response != b"":
                            decoded_response = decode_packed_packet(raw_ping_response)
                            if decoded_response == {b'Pac_ket': b'Po_ng'}:
                                guess_from_custom_scan = "DcRAT/VenomRAT"
                except Exception:
                    pass
        except ssl.SSLError as ssl_err:
            pass
    # --------------------------------------------------------------------
    
    results = async_sniffer.stop()
    ja3s, ja4s, ja4x = "", "", ""

    for pkt in results:
        if pkt.haslayer("TLSServerHello"):
                ja3s = calculate_ja3s(pkt.getlayer("TLSServerHello"))
        elif pkt.haslayer("Raw"):
            # scapy doesn't identify TLS layers as such by itself, we need to help
            tls_packet = TLS(pkt.getlayer("Raw").load)
            if tls_packet.haslayer("TLSServerHello"):
                ja3s = calculate_ja3s(tls_packet.getlayer("TLSServerHello"))

    # extract certificate infos
    cert_infos = dict()
    if der_cert != b"":
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
        cert_infos = {
            "subject": dict(x509.get_subject().get_components()),
            "issuer": dict(x509.get_issuer().get_components()),
            "serialNumber": hex(x509.get_serial_number()),
            "notBefore": x509.get_notBefore().decode("utf-8"),
            "notAfter": x509.get_notAfter().decode("utf-8"),
            "signature_alogrithm": x509.get_signature_algorithm().decode("utf-8")
        }
    
    # calculate ja4s and ja4x, we need the pcap of our captures trafic for that
    raw_ja4_result = subprocess.Popen(f"python3 ja4+/ja4.py --ja4s --ja4x {pcap_filename}",
                                      shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.read().decode("utf-8")
    if raw_ja4_result.endswith("}\n"):
        try:
            ja4_dict = json.loads(raw_ja4_result.split("\n")[-2].replace("'", "\""))
            ja4s = ja4_dict["JA4S"]
            ja4x = ja4_dict["JA4X.1"]
        except Exception as e:
            print("Failed to calculate JA4S/JA4X:")
            print(e)

    if not keep_pcap:
        os.remove(pcap_filename)

    return CollectedIndicators(port, tls_version, jarm, ja3s, ja4s, ja4x, cert_infos, guess_from_custom_scan)


def evaluate_collected_indicators(collected_indicators: CollectedIndicators):
    rows = []

    row = ["Port", collected_indicators.port]
    if collected_indicators.port == QuasarRatIndicators.default_port:
        row += ["QuasarRAT", "LOW"]
    elif collected_indicators.port in AsyncRatIndicators.default_ports:
        row += ["AsyncRAT", "LOW"]
    elif collected_indicators.port == DcRatIndicators.default_port:
        row += ["DcRAT", "LOW"]
    else:
        row += ["-", "-"]
    rows.append(row)
    
    if collected_indicators.tls_version != "":
        row = ["TLS Version", collected_indicators.tls_version]
        if collected_indicators.tls_version == QuasarRatIndicators.tls_version:
            row += ["QuasarRAT", "VERY LOW"]
        elif collected_indicators.tls_version == "TLSv1":
            row += ["AsyncRAT/DcRAT/VenomRAT", "VERY LOW"]
        else:
            row += ["-", "-"]
        rows.append(row)
    
    if collected_indicators.jarm != "":
        row = ["JARM", collected_indicators.jarm]
        jarm_inference = ""
        if collected_indicators.jarm in QuasarRatIndicators.jarm_hashes:
            jarm_inference = "QuasarRAT"
        if collected_indicators.jarm in AsyncRatIndicators.jarm_hashes:
            if jarm_inference != "":
                jarm_inference += "/"
            jarm_inference += "AsyncRAT"
        if collected_indicators.jarm in DcRatIndicators.jarm_hashes:
            if jarm_inference != "":
                jarm_inference += "/"
            jarm_inference += "DcRAT"
        if collected_indicators.jarm in VenomRatIndicators.jarm_hashes:
            if jarm_inference != "":
                jarm_inference += "/"
            jarm_inference += "VenomRAT"
        if jarm_inference != "":
            row += [jarm_inference, "MEDIUM"]
        else:
            row += ["-", "-"]
        rows.append(row)
    
    if collected_indicators.ja3s != "":
        if collected_indicators.ja3s == AsyncRatIndicators.ja3s_hash:
            # same also for DcRAT, VenomRAT, QuasarRAT
            rows.append(["JA3S", collected_indicators.ja3s, "QuasarRAT/AsyncRAT/DcRAT/VenomRAT" , "MEDIUM"])
        elif collected_indicators.ja3s in QuasarRatIndicators.ja3s_hashes:
            rows.append(["JA3S", collected_indicators.ja3s, "QuasarRAT" , "MEDIUM"])
        else:
            rows.append(["JA3S", collected_indicators.ja3s, "-" , "-"])
    
    if collected_indicators.ja4s != "":
        if collected_indicators.ja4s == AsyncRatIndicators.ja4s:
            # same also for DcRAT, VenomRAT, QuasarRAT
            rows.append(["JA4S", collected_indicators.ja4s, "AsyncRAT/DcRAT/VenomRAT" , "MEDIUM"])
        elif collected_indicators.ja4s == QuasarRatIndicators.ja4s:
            rows.append(["JA4S", collected_indicators.ja4s, "QuasarRAT" , "MEDIUM"])
        else:
            rows.append(["JA4S", collected_indicators.ja4s, "-" , "-"])

    if collected_indicators.ja4x != "":
        if collected_indicators.ja4x == QuasarRatIndicators.ja4x == AsyncRatIndicators.ja4x:
            rows.append(["JA4X", collected_indicators.ja4x, "QuasarRAT/AsyncRAT", "MEDIUM"])
        elif collected_indicators.ja4x == DcRatIndicators.ja4x == VenomRatIndicators.ja4x:
            rows.append(["JA4X", collected_indicators.ja4x, "DcRAT/VenomRAT", "MEDIUM"])
        else:
            rows.append(["JA4X", collected_indicators.ja4x, "-" , "-"])
    
    if collected_indicators.cert_infos:
        if collected_indicators.cert_infos["subject"] and collected_indicators.cert_infos["issuer"]:
            subject_cn = collected_indicators.cert_infos["subject"][b"CN"].decode("utf-8")
            issuer_cn = collected_indicators.cert_infos["issuer"][b"CN"].decode("utf-8")
            if subject_cn == QuasarRatIndicators.subject_cn and issuer_cn == QuasarRatIndicators.issuer_cn:
                rows.append(["Subject CN", subject_cn, "QuasarRAT", "VERY HIGH"])
                rows.append(["Issuer CN", issuer_cn, "QuasarRAT", "VERY HIGH"])
            elif subject_cn == AsyncRatIndicators.subject_cn and issuer_cn == AsyncRatIndicators.issuer_cn:
                rows.append(["Subject CN", subject_cn, "AsyncRAT", "VERY HIGH"])
                rows.append(["Issuer CN", issuer_cn, "AsyncRAT", "VERY HIGH"])
            elif subject_cn == DcRatIndicators.subject_cn:
                rows.append(["Subject CN", subject_cn, "DcRAT", "VERY HIGH"])
                decoded_issuer_dict = {k.decode("utf-8"): v.decode("utf-8") for k,v in collected_indicators.cert_infos["issuer"].items()}
                if decoded_issuer_dict == DcRatIndicators.issuer_dict:
                    rows.append(["Issuer", f"{decoded_issuer_dict}", "DcRAT", "VERY HIGH"])
            elif subject_cn == VenomRatIndicators.subject_cn:
                rows.append(["Subject CN", subject_cn, "VenomRAT", "VERY HIGH"])
                decoded_issuer_dict = {k.decode("utf-8"): v.decode("utf-8") for k,v in collected_indicators.cert_infos["issuer"].items()}
                if decoded_issuer_dict == VenomRatIndicators.issuer_dict:
                    rows.append(["Issuer", f"{decoded_issuer_dict}", "VenomRAT", "VERY HIGH"])
            elif subject_cn == issuer_cn:
                rows.append(["Issuer CN == Subject CN", issuer_cn, "QuasarRAT/AsyncRAT", "LOW"])
            else:
                rows.append(["Subject CN", subject_cn, "-", "-"])
                rows.append(["Issuer CN", issuer_cn, "-", "-"])

        if collected_indicators.cert_infos["serialNumber"]:
            serial_number_length = len(collected_indicators.cert_infos["serialNumber"][2:])//2
            row = ["Serial Number Length", serial_number_length]
            if serial_number_length == 15:
                row += ["QuasarRAT/AsyncRAT", "LOW"]
            elif serial_number_length == 20:
                row +=["DcRAT/VenomRAT", "LOW"]
            else:
                row += ["-", "-"]
            rows.append(row)

        if collected_indicators.cert_infos["notAfter"] and collected_indicators.cert_infos["notBefore"]:
            not_after = collected_indicators.cert_infos["notAfter"]
            if not_after == QuasarRatIndicators.cert_validity_not_after == AsyncRatIndicators.cert_validity_not_after:
                rows.append(["Not After", not_after, "QuasarRAT/AsyncRAT", "MEDIUM"])
            else:
                not_before = collected_indicators.cert_infos["notBefore"]
                if not_after[8:] == not_before[8:]:
                    not_after_time = datetime.strptime(not_after[:8], "%Y%m%d")
                    not_before_time = datetime.strptime(not_before[:8], "%Y%m%d")
                    validity_period = (not_after_time - not_before_time).days
                    if validity_period == DcRatIndicators.cert_validity_period == VenomRatIndicators.cert_validity_period:
                        rows.append(["Certificate Validity Period", f"{validity_period} days", "DcRAT/VenomRAT", "MEDIUM"])
                    else:
                        rows.append(["Not Before", not_before, "-", "-"])
                        rows.append(["Not After", not_after, "-", "-"])
                else:
                    rows.append(["Not Before", not_before, "-", "-"])
                    rows.append(["Not After", not_after, "-", "-"])

        if collected_indicators.cert_infos["signature_alogrithm"]:
            if collected_indicators.cert_infos["signature_alogrithm"] == "sha512WithRSAEncryption":
                rows.append(["Signature Algorithm", "sha512WithRSAEncryption", "QuasarRAT/AsyncRAT/DcRAT/VenomRAT", "VERY LOW"])
            else:
                rows.append(["Signature Algorithm", collected_indicators.cert_infos["signature_alogrithm"], "-", "-"])
    
    if collected_indicators.guess_from_custom_scan != "":
        if collected_indicators.guess_from_custom_scan != "QuasarRAT":     
            rows.append(["Result from Custom Scan", "Server responded to crafted C2 Ping Message with Pong",
                         collected_indicators.guess_from_custom_scan, "VERY HIGH"])
        else:
            rows.append(["Result from Custom Scan", "Server reset connection when sending exactly four bytes",
                         collected_indicators.guess_from_custom_scan, "HIGH"])
    else:
        rows.append(["Result from Custom Scan", "-", "-", "-"])
    
    # only set inference for TLS version when we also got some other inferences 
    for r in rows[2:]:
        if r[2] != "-":
            print(tabulate(rows, headers=["Indicator", "Value", "Inference", "Confidence"], tablefmt="grid"))
            return
    
    rows[1][2:] = ["-", "-"]
    print(tabulate(rows, headers=["Indicator", "Value", "Inference", "Confidence"], tablefmt="grid"))



def main():
    if os.geteuid() != 0:
        print("This script needs to be run as root.")
        exit(1)
    load_layer("tls")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--keep-pcap",
        default=False,
        action="store_true",
        help="keep the created pcap file",
        required=False
    )
    parser.add_argument("interface", 
        help="network interface to use (eth0/tun0/...)"
    )
    parser.add_argument("ip",
        help="IP address or domain to connect to"
    )
    parser.add_argument("port",
        type=int,
        help="port to connect to"
    )
    args = parser.parse_args()

    collected_indicators = collect_indicators(args.interface, args.ip, args.port, args.keep_pcap)
    evaluate_collected_indicators(collected_indicators)



if __name__ == "__main__":
    main()