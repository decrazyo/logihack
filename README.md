
# Logitech Unifying Hacking Tools

This project is a collection of tools/information for hacking the Logitech Unifying protocol.

## Dependencies
- python
- pycryptodome

## Extract Devices

Extract device information, including encryption keys, from a flash dump of a unifying receiver.
A flash dump can obtained with the "nrf-research-firmware" and "nrf24-flash-dumper.py"

```
python tools/extract-devices.py flash_dump.bin devices.csv
```

## Decrypt Packets

Use device information, obtained from "extract-devices.py", to decrypt captured keystroke packets.
Packets can be captured with the "nrf-research-firmware" and "nrf24-scanner.py" or "nrf24-sniffer.py".

```
python tools/decrypt-packets.py devices.csv packet_capture.txt > decrypted_packets.txt
```

## Interpret Packets

Interpret decrypted keystroke packets, from a specific address, to generate an approximation of what was typed.

```
python tools/interpret-packets.py 1A:2B:3C:4D:5E decrypted_packets.txt
```
