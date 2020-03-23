#!/usr/bin/env python
"""Generate JA3 fingerprints from PCAPs using Python."""

import argparse
import dpkt
import json
import socket
import struct
from hashlib import md5
import sys

GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 4443
TLS_HANDSHAKE = 22


LOOPBACK = False

def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results


def process_ssl(pkt, any_port=False):
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    tls_handshake = pkt

    if tls_handshake[0] != TLS_HANDSHAKE:
        return

    records = list()

    try:
        # records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        records, bytes_used = dpkt.ssl.tls_multi_factory(tls_handshake)
    except dpkt.ssl.SSL3Exception:
        return
    except dpkt.dpkt.NeedData:
        return

    if len(records) <= 0:
        return

    for record in records:
        if record.type != TLS_HANDSHAKE:
            return
        if len(record.data) == 0:
            return
        client_hello = bytearray(record.data)
        if client_hello[0] != 1:
            # We only want client HELLO
            return
        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except dpkt.dpkt.NeedData:
            # Looking for a handshake here
            return
        if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
            # Still not the HELLO
            return

        client_handshake = handshake.data
        buf, ptr = parse_variable_array(client_handshake.data, 1)
        buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
        ja3 = [str(client_handshake.version)]

        # Cipher Suites (16 bit values)
        ja3.append(convert_to_ja3_segment(buf, 2))
        ja3 += process_extensions(client_handshake)
        ja3 = ",".join(ja3)

        ja3_digest = md5(ja3.encode()).hexdigest()
        # src_ip = convert_ip(ip.src)
        src_ip = None
        # sport = tcp.sport
        sport = None
        record = {
                  "ja3": ja3,
                  "ja3_digest": ja3_digest}

        return record


def main():
    """Intake arguments from the user and print out JA3 output."""
    desc = "A python script for extracting JA3 fingerprints from PCAP files"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("pcap", help="The pcap file to process")
    help_text = "Look for client hellos on any port instead of just 443"
    parser.add_argument("-a", "--any_port", required=False,
                        action="store_true", default=False,
                        help=help_text)
    help_text = "Print out as JSON records for downstream parsing"
    parser.add_argument("-j", "--json", required=False, action="store_true",
                        default=True, help=help_text)
    parser.add_argument("--loopback", action="store_true",
                        default=False, help="loopback capture") 
    args = parser.parse_args()

    global LOOPBACK
    LOOPBACK = args.loopback

    # Use an iterator to process each line of the file
    output = None
    with open(args.pcap, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as e:
            raise Exception("File doesn't appear to be a PCAP: %s" % e)
        output = process_pcap(capture, any_port=args.any_port)

    if args.json:
        output = json.dumps(output, indent=4, sort_keys=True)
        print(output)
    else:
        for record in output:
            tmp = '[{dest}:{port}] JA3: {segment} --> {digest}'
            tmp = tmp.format(dest=record['destination_ip'],
                             port=record['destination_port'],
                             segment=record['ja3'],
                             digest=record['ja3_digest'])
            print(tmp)


if __name__ == "__main__":
    main()
