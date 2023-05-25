#!/usr/bin/env python

import argparse
import csv
import struct
import sys

# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util import Counter


class UnifyingCrypto:
    def __init__(self, key):
        self.key = key

    @staticmethod
    def counter(initial_value):
        prefix = bytearray([0x04, 0x14, 0x1D, 0x1F, 0x27, 0x28, 0x0D])
        suffix = bytearray([0x0A, 0x0D, 0x13, 0x26, 0x0E])
        return Counter.new(32, prefix=prefix, suffix=suffix, initial_value=initial_value)

    def cipher(self, counter):
        return AES.new(self.key, AES.MODE_CTR, counter=self.counter(counter))

    def decrypt(self, packet):
        if packet[1] != 0xD3:
            raise Exception('wrong packet type')

        ciphertext = packet[2:10]
        counter = struct.unpack('>I', packet[10:14])[0]

        cipher = self.cipher(counter)
        plaintext = cipher.decrypt(ciphertext)

        return packet[:2] + plaintext + packet[10:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('device_csv',
        help='device csv file produced by "extract-devices.py"')
    parser.add_argument('capture', nargs='?', default=sys.stdin, type=open,
        help='packet capture from "nrf-scanner.py" or "nrf-sniffer.py".')
    args = parser.parse_args()

    with open(args.device_csv) as csvfile:
        reader = csv.DictReader(csvfile)
        devices = list(reader)

    crypto = {}

    for device in devices:
        address = device['address']
        key = bytearray.fromhex(device['key'])

        if not address or not key:
            continue

        crypto[address] = UnifyingCrypto(key)

    for line in iter(args.capture.readline, ''):
        line = line.rstrip()
        try:
            timestamp, channel, length, address, packet = line.split('  ')

            if address in crypto:
                packet_bytes = bytearray.fromhex(packet.replace(':', ''))
                decrypted = crypto[address].decrypt(packet_bytes)
                packet = ':'.join('{:02X}'.format(x) for x in decrypted)

            print('{}  {}  {}  {}  {}'.format(
                timestamp, channel, length, address, packet))
        except Exception as e:
            print(line)


if __name__ == '__main__':
    main()
