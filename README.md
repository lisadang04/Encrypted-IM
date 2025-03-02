# Encrypted Instant Messenger

A encrypted instant messenger program that allows two instances of the program to communicate securely over a network. The program reads messages from standard input, encrypts them using AES-256 in CBC mode, and sends them to another instance of the program running on a different machine. Received messages are decrypted and printed to standard output. The program uses TCP/IP for communication and ensures message integrity and authenticity using HMAC with SHA-256.

---

## Features

- **Secure Communication**: AES-256 encryption for confidentiality.
- **Message Integrity**: HMAC-SHA256 ensures message authenticity.
- **Encrypt-then-MAC**: Combines encryption and authentication securely.
- **Cross-Platform**: Works on any system with Python 3 and `pycryptodome`.

---

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/encrypted-instant-messenger.git
   cd encrypted-instant-messenger
   ```
2. Install dependencies:
   ```
   pip install pycryptodome
   ```

## Usage
1. Start the server:

```
python3 encryptedim.py --s --confkey 'your_conf_key' --authkey 'your_auth_key'
```
2. Start the client and connect to the server:

```
python3 encryptedim.py --c 127.0.0.1 --confkey 'your_conf_key' --authkey 'your_auth_key'
```
3. Type messages in either terminal. Press CTRL-C or CTRL-D to exit.

### Example:
Terminal 1 (Server):
```
python3 encryptedim.py --s --confkey 'foo' --authkey 'bar'
```

Terminal 2 (Client):
```
python3 encryptedim.py --c 127.0.0.1 --confkey 'foo' --authkey 'bar'
```

## Testing
Capture traffic with tcpdump to verify encryption:
```
tcpdump -i lo -w output.pcap
```
Inspect output.pcap in Wireshark.

## Acknowledgments
Uses the pycryptodome library for cryptographic functions.
