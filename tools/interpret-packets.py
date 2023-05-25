#!/usr/bin/env python

import argparse
import sys

class PacketParser:
    L_SHIFT = 0b00000010
    R_SHIFT = 0b00100000
    SCANCODES = {
        0x04: ['a', 'A'],
        0x05: ['b', 'B'],
        0x06: ['c', 'C'],
        0x07: ['d', 'D'],
        0x08: ['e', 'E'],
        0x09: ['f', 'F'],
        0x0a: ['g', 'G'],
        0x0b: ['h', 'H'],
        0x0c: ['i', 'I'],
        0x0d: ['j', 'J'],
        0x0e: ['k', 'K'],
        0x0f: ['l', 'L'],
        0x10: ['m', 'M'],
        0x11: ['n', 'N'],
        0x12: ['o', 'O'],
        0x13: ['p', 'P'],
        0x14: ['q', 'Q'],
        0x15: ['r', 'R'],
        0x16: ['s', 'S'],
        0x17: ['t', 'T'],
        0x18: ['u', 'U'],
        0x19: ['v', 'V'],
        0x1a: ['w', 'W'],
        0x1b: ['x', 'X'],
        0x1c: ['y', 'Y'],
        0x1d: ['z', 'Z'],
        0x1e: ['1', '!'],
        0x1f: ['2', '@'],
        0x20: ['3', '#'],
        0x21: ['4', '$'],
        0x22: ['5', '%'],
        0x23: ['6', '^'],
        0x24: ['7', '&'],
        0x25: ['8', '*'],
        0x26: ['9', '('],
        0x27: ['0', ')'],
        0x28: ['\n', '\n'],
        0x2b: ['\t', '\t'],
        0x2c: [' ', ' '],
        0x2d: ['-', '_'],
        0x2e: ['=', '+'],
        0x2f: ['[', '{'],
        0x30: [']', '}'],
        0x31: ['\\', '|'],
        0x32: ['#', '~'],
        0x33: [';', ':'],
        0x34: ["'", '"'],
        0x35: ['`', '~'],
        0x36: [',', '<'],
        0x37: ['.', '>'],
        0x38: ['/', '?'],
        0x54: ['/', '/'],
        0x55: ['*', '*'],
        0x56: ['-', '-'],
        0x57: ['+', '+'],
        0x58: ['\n', '\n'],
        0x59: ['1', '1'],
        0x5a: ['2', '2'],
        0x5b: ['3', '3'],
        0x5c: ['4', '4'],
        0x5d: ['5', '5'],
        0x5e: ['6', '6'],
        0x5f: ['7', '7'],
        0x60: ['8', '8'],
        0x61: ['9', '9'],
        0x62: ['0', '0'],
        0x63: ['.', '.'],
        0x64: ['\\', '|'],
        0x67: ['=', '=']
    }

    def __init__(self):
        self.keys = [0x00] * 6

    def parse(self, packet):
        if packet[1] != 0xD3:
            # not an encrypted keystroke packet
            return

        if packet[9] != 0xC9:
            # keystroke packet has not been decrypted
            return

        mods = packet[2]
        keys = packet[3:9][::-1]

        for key in keys:
            if key == 0x00:
                continue
            elif key not in self.keys and key in self.SCANCODES:
                symbols = self.SCANCODES[key]
                if mods & (self.L_SHIFT | self.R_SHIFT):
                    sys.stdout.write(symbols[1])
                else:
                    sys.stdout.write(symbols[0])

                sys.stdout.flush()

        self.keys = keys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('address',
        help='address of a device to parse packets for')
    parser.add_argument('capture', nargs='?', default=sys.stdin, type=open,
        help='decrypted packet capture from "decrypt-packets.py".')
    args = parser.parse_args()

    packet_parser = PacketParser()

    for line in iter(args.capture.readline, ''):
        line = line.rstrip()
        try:
            timestamp, channel, length, address, packet = line.split('  ')
            if args.address != address:
                continue

            packet_parser.parse(bytearray.fromhex(packet.replace(':', '')))
        except Exception as e:
            pass


if __name__ == '__main__':
    main()
