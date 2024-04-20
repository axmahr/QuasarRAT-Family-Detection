# QuasarRAT Family Detector

QuasarRAT Family Detector scans a given `IP address:port`, collects indicators which infer, if the server endpoint belongs to the QuasarRAT family and, if so, which RAT (QuasarRAT/AsyncRAT/DcRAT/VenomRAT) it is likely to be. At the end, it shows all computed indicators with corresponding inferences.

The collected indicators are:
- Server Port
- Negotiated TLS version
- JARM, JA3S, JA4S, JA4X fingerprint
- TLS Certificate:
    * Subject and Issuer CN
    * "Not After" time (for QuasarRAT/AsyncRAT)
    * Validity time period (for DcRAT/VenomRAT)
    * Serial Number length
    * Signing Algorithm
- **Result from sending custom crafted C2 packets (see the [corresponding section below](#detection-capabilities-through-sending-custom-c2-packets))**

## Requirements
QuasarRAT Family Detector needs to be run on a Linux machine with Python 3.7+.
Make sure to install all necessary requirements **as root** (because the tool needs to be run as root):
```
sudo pip install -r requirements.txt
sudo apt install tshark
```

## Usage
Usage together with VPN is strongly recommended.

```
sudo python3 quasar_family_detector.py [-h] [--keep-pcap] interface ip port

positional arguments:
  interface    network interface to use (eth0/tun0/...)
  ip           IP address or domain to connect to
  port         port to connect to

options:
  -h, --help   show this help message and exit
  --keep-pcap  keep the created pcap file
```

## Example
Let's grab an IP and port from an exposed QuasarRAT server using [Censys](https://search.censys.io) by searching for `services.software.product:"Quasar"`.
I got exemplarily `159.100.13[.]218:1606`.
```
sudo ./quasar_family_detector.py tun0 159.100.13.218 1606
[sudo] password for axel: 
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| Indicator               | Value                                                          | Inference                         | Confidence   |
+=========================+================================================================+===================================+==============+
| Port                    | 1606                                                           | -                                 | -            |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| TLS Version             | TLSv1.2                                                        | QuasarRAT                         | VERY LOW     |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| JARM                    | 2ad2ad16d2ad2ad0002ad2ad2ad2add3b67dd3674d9af9dd91c1955a35d0e9 | QuasarRAT                         | MEDIUM       |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| JA3S                    | ae4edc6faf64d08308082ad26be60767                               | QuasarRAT                         | MEDIUM       |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| JA4S                    | t120200_c030_5333cdffa7d9                                      | QuasarRAT                         | MEDIUM       |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| JA4X                    | 7022c563de38_7022c563de38_0147df7a0c11                         | QuasarRAT/AsyncRAT                | MEDIUM       |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| Subject CN              | Quasar Server CA                                               | QuasarRAT                         | VERY HIGH    |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| Issuer CN               | Quasar Server CA                                               | QuasarRAT                         | VERY HIGH    |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| Serial Number Length    | 15                                                             | QuasarRAT/AsyncRAT                | LOW          |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| Not After               | 99991231235959Z                                                | QuasarRAT/AsyncRAT                | MEDIUM       |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| Signature Algorithm     | sha512WithRSAEncryption                                        | QuasarRAT/AsyncRAT/DcRAT/VenomRAT | VERY LOW     |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
| Result from Custom Scan | Server reset connection when sending exactly four bytes        | QuasarRAT                         | HIGH         |
+-------------------------+----------------------------------------------------------------+-----------------------------------+--------------+
```


## Detection Capabilities through sending custom C2 packets
In order to detect AsyncRAT/DcRAT/VenomRAT, it is possible to send valid C2 packets to the server as an unauthenticated client, provoking a certain response from the server. The response reliably indicates us, which RAT we are facing. This approach is particularly robust since it also works when a custom TLS ceritifcate is used. Also, this is not prone to false positives like JARM/JA3S.

Exemplarily, with the follwing code, we can get easily detect AsyncRAT:
```python
import socket
import ssl
import gzip
import msgpack
from pwn import p32

# init socket for connecting to AsyncRAT server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
context.set_ciphers('DEFAULT:@SECLEVEL=0')
context.verify_mode = ssl.CERT_NONE

# connect
wrapped_socket = context.wrap_socket(sock)
wrapped_socket.connect((IP, PORT))

# craft valid C2 packet of message type "Ping"
# (for detecting DcRAT/VenomRAT, just change b"Packet" to b"Pac_ket")
payload = gzip.compress(msgpack.packb({b"Packet": b"Ping"}))
payload_header = p32(len(payload))
payload = payload_header + payload
ping_packet = p32(len(payload)) + payload

# send our crafted packet
wrapped_socket.send(ping_packet)

# get and decode response
response = b""
response += wrapped_socket.recv(1280)
response += wrapped_socket.recv(1280)
response += wrapped_socket.recv(1280)
response += wrapped_socket.recv(1280)
print("raw response:", response)
payload_size = int.from_bytes(response[:4], "little")
print("payload size:", payload_size)
cropped_payload = response[8:]
print("cropped payload (compressed):", cropped_payload)
payload_uncompressed = gzip.decompress(cropped_payload)
print("cropped payload (decompressed):", payload_uncompressed)
print("\n... and unpacked with msgpack:", msgpack.unpackb(payload_uncompressed))
```

This is the response we then get from an AsyncRAT server:
```
raw response: b'%\x00\x00\x00\r\x00\x00\x00\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\x00k\\\x16\x90\x98\x9c\x9dZ\xb2\xa4 ?/\x1d\x00\x9e\x931\x87\r\x00\x00\x00'
payload size: 37
cropped payload (compressed): b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\x00k\\\x16\x90\x98\x9c\x9dZ\xb2\xa4 ?/\x1d\x00\x9e\x931\x87\r\x00\x00\x00'
cropped payload (decompressed): b'\x81\xa6Packet\xa4pong'

... and unpacked with msgpack: {b'Packet': b'pong'}
```
We see, the server responds with a "Pong"-Packet and doesn't care whether the initial "Ping" message came from an actual client beacon of an infected system or just some other random client. The same works for DcRAT/VenomRAT when we change `{b"Packet": b"Ping"}` to `{b"Pac_ket": b"Ping"}` in the code above.
Also, by sending such a ping message, we remain completely unnoticed on the server-side since nothing w.r.t the ping message is logged there.

By the way, the ability of sending valid C2 packets which are then regardlessly processed by the server, is not limited to just ping messages. Indeed, we can send **arbitrary** messages, as long as they are message types which are actually handled by the server. That means, depending on the available message types, we can cause some wild things happening on the server-side. And all that as a random client from outside.

### Detecting QuasarRAT
Sending valid C2 packets that are blindly processed by the server is only possible for AsyncRAT/DcRAT/VenomRAT. QuasarRAT on the other side requires that the client is actually a valid client beacon. Nevertheless there is also another possibility to identify QuasarRAT:

A QuasarRAT server doesn't begin processing a packet sent by a client until 4 or more bytes are received since a QuasarRAT packet (inside TLS) always begins with 4 bytes indicating the size of the following payload. And when these 4 bytes don't match the actual payload size, the server disconnects. Thus, a possible indicator for identifying a QuasarRAT server is to send 3 bytes of data to the server. When the connection keeps established and is closed by the server once a fourth byte is sent, the server might be QuasarRAT.