#!/usr/bin/env python

import argparse
import array
import binascii
import csv

PAGE_SIZE = 0x200
DEVICE_COUNT = 6


def xnor(lhs, rhs):
    return ~(lhs ^ rhs) & 0xFF


def decipher_proto_encryption_keys(proto_keys):
    keys = [bytearray()] * len(proto_keys)
    order = [0x07, 0x01, 0x00, 0x03, 0x0A, 0x02, 0x09, 0x0E,
           0x08, 0x06, 0x0C, 0x05, 0x0D, 0x0F, 0x04, 0x0B]
    mask = [0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xFF,
          0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xAA, 0xFF, 0xFF]

    # Convert proto-encryption keys into encryption keys.
    for i, proto in enumerate(proto_keys):
        if not proto:
            continue

        keys[i] = bytearray(xnor(proto[order[j]], mask[j]) for j in range(16))

    return keys


def parse_crypto_page(crypto_page):
    record_len = 32
    data = crypto_page[:record_len * DEVICE_COUNT]
    records = [data[i:i+record_len] for i in range(0, len(data), record_len)]
    proto_keys = [bytearray()] * DEVICE_COUNT

    # Collect proto-encryption keys
    for record in records:
        proto_key = record[1:1+16]

        if all(byte == 0xFF for byte in proto_key):
            continue

        index = record[0]
        proto_keys[index] = proto_key

    return decipher_proto_encryption_keys(proto_keys)


def parse_device_page(page):
    # Ignore the first 48 bytes of receiver data.
    data = page[48:]
    record_len = 16
    records = [data[i:i+record_len] for i in range(0, len(data), record_len)]

    # Isolate relevant device data
    addresses = [x[1:6] for x in records if x[0] == 0x03]
    names = [x[2:2+x[1]] for x in records if x[0] & 0xF0 == 0x40]
    indexes = [x[0] & 0x0F for x in records if x[0] & 0xF0 == 0x40]

    print(names)

    ordered_names = [bytearray()] * DEVICE_COUNT
    ordered_addresses = [bytearray()] * DEVICE_COUNT

    # Order device data.
    for i, j in enumerate(indexes):
        ordered_names[j] = names[i]
        ordered_addresses[j] = addresses[i]

    return ordered_names, ordered_addresses


def get_active_page(data):
    for page_start in range(0, len(data), PAGE_SIZE):
        page = data[page_start:page_start + PAGE_SIZE]

        if all(byte == 0xFF for byte in page):
            continue

        return page
    else:
        raise Exception('no active page found')


def get_data_pages(flash_dump_path):
    with open(flash_dump_path, 'rb') as f:
        flash_dump = bytearray(f.read())

    flash_dump_len = len(flash_dump)
    if flash_dump_len != 0x8000:
        raise Exception('flash dump contains {} bytes, expected {}'.format(
            flash_dump_len, 0x8000))

    device_pages = flash_dump[0x6C00:0x7000]
    crypto_pages = flash_dump[0x7000:0x7400]

    return device_pages, crypto_pages


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('flash_dump',
        help='flash dump to extract device data from')
    parser.add_argument('device_csv', nargs='?',
        help='CSV file to save device data to')
    args = parser.parse_args()

    device_pages, crypto_pages = get_data_pages(args.flash_dump)

    device_page = get_active_page(device_pages)
    crypto_page = get_active_page(crypto_pages)

    names, addresses = parse_device_page(device_page)
    keys = parse_crypto_page(crypto_page)

    names = [name.decode() for name in names]
    addresses = [':'.join('{:02X}'.format(x) for x in addr) for addr in addresses]
    keys = [binascii.hexlify(key).decode() for key in keys]

    print('name\taddress\tkey')
    for name, addr, key in zip(names, addresses, keys):
        if name or addr or key:
            print('{}\t{}\t{}'.format(name, addr, key))

    if args.device_csv:
        with open(args.device_csv, 'w') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow((['name', 'address', 'key']))
            writer.writerows(zip(names, addresses, keys))

if __name__ == '__main__':
    main()
