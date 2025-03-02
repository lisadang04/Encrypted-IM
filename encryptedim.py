import argparse
import socket
import select
import sys
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

PORT = 9999
BLOCK_SIZE = AES.block_size  # 16 bytes

# Derive a 256-bit key from a string using SHA-256.
def derive_key(key_str):
    return SHA256.new(data=key_str.encode('utf-8')).digest()

# Encrypts a message using an encrypt-then-MAC scheme with two separate IVs.
def encrypt_packet(message, conf_key, auth_key):
    # Generate separate IVs
    iv_len = get_random_bytes(BLOCK_SIZE)
    iv_msg = get_random_bytes(BLOCK_SIZE)
    
    # Encrypt the length field.
    len_field = struct.pack("!I", len(message))
    padded_len_field = pad(len_field, BLOCK_SIZE)
    cipher_len = AES.new(conf_key, AES.MODE_CBC, iv_len)
    encrypted_len = cipher_len.encrypt(padded_len_field)
    
    header = iv_len + encrypted_len
    hmac_header = HMAC.new(auth_key, digestmod=SHA256)
    hmac_header.update(header)
    header_mac = hmac_header.digest()
    
    # Encrypt the message.
    padded_message = pad(message, BLOCK_SIZE)
    cipher_msg = AES.new(conf_key, AES.MODE_CBC, iv_msg)
    encrypted_msg = cipher_msg.encrypt(padded_message)
    hmac_msg = HMAC.new(auth_key, digestmod=SHA256)
    # It is a good practice to include the IV used for this encryption in the MAC.
    hmac_msg.update(iv_msg + encrypted_msg)
    msg_mac = hmac_msg.digest()
    
    # Packet: header + header_mac + iv_msg + encrypted_msg + msg_mac
    return header + header_mac + iv_msg + encrypted_msg + msg_mac

# Attempts to extract one complete packet from buffer.
def try_decrypt_packet(buffer, conf_key, auth_key):
    # We need at least iv_len + encrypted_len + header_mac + iv_msg + msg_mac (without the encrypted_msg)
    min_header = BLOCK_SIZE + BLOCK_SIZE + 32 + BLOCK_SIZE + 32
    if len(buffer) < min_header:
        return None, buffer

    # Extract the first part.
    iv_len = buffer[0:BLOCK_SIZE]
    encrypted_len = buffer[BLOCK_SIZE:BLOCK_SIZE*2]
    header = buffer[0:BLOCK_SIZE*2]
    header_mac = buffer[BLOCK_SIZE*2:BLOCK_SIZE*2+32]
    
    # Verify header HMAC.
    try:
        h = HMAC.new(auth_key, digestmod=SHA256)
        h.update(header)
        h.verify(header_mac)
    except Exception:
        print("ERROR: HMAC verification failed")
        sys.stdout.flush()
        sys.exit(1)
    
    # Decrypt the length field.
    cipher_len = AES.new(conf_key, AES.MODE_CBC, iv_len)
    decrypted_padded = cipher_len.decrypt(encrypted_len)
    try:
        len_field = unpad(decrypted_padded, BLOCK_SIZE)
    except Exception:
        print("ERROR: Decryption padding error in length field")
        sys.stdout.flush()
        sys.exit(1)
    
    if len(len_field) != 4:
        print("ERROR: Invalid length field size")
        sys.stdout.flush()
        sys.exit(1)
    
    (plain_len,) = struct.unpack("!I", len_field)
    # Determine the size of the encrypted message block.
    padded_msg_len = ((plain_len // BLOCK_SIZE) + 1) * BLOCK_SIZE
    
    # Total packet length:
    # header (iv_len+encrypted_len) + header_mac + iv_msg + encrypted_msg + msg_mac.
    total_needed = (BLOCK_SIZE*2 + 32) + BLOCK_SIZE + padded_msg_len + 32
    if len(buffer) < total_needed:
        return None, buffer  # Wait for more data.
    
    # Extract iv_msg.
    offset = BLOCK_SIZE*2 + 32
    iv_msg = buffer[offset:offset+BLOCK_SIZE]
    offset += BLOCK_SIZE
    encrypted_msg = buffer[offset:offset+padded_msg_len]
    offset += padded_msg_len
    msg_mac = buffer[offset:offset+32]
    
    # Verify message HMAC.
    try:
        h = HMAC.new(auth_key, digestmod=SHA256)
        h.update(iv_msg + encrypted_msg)
        h.verify(msg_mac)
    except Exception:
        print("ERROR: HMAC verification failed")
        sys.stdout.flush()
        sys.exit(1)
    
    # Decrypt the message.
    cipher_msg = AES.new(conf_key, AES.MODE_CBC, iv_msg)
    decrypted_padded_msg = cipher_msg.decrypt(encrypted_msg)
    try:
        message = unpad(decrypted_padded_msg, BLOCK_SIZE)
    except Exception:
        print("ERROR: Decryption padding error in message")
        sys.stdout.flush()
        sys.exit(1)
    
    new_buffer = buffer[total_needed:]
    return message, new_buffer

def run_server(conf_key, auth_key):
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(('', PORT))
    listen_socket.listen()
    
    client_sockets = []
    recv_buffers = {}
    stdin_active = True

    while True:
        read_list = [listen_socket] + client_sockets
        if stdin_active:
            read_list.append(sys.stdin)
        
        readable, _, _ = select.select(read_list, [], [])
        
        for sock in readable:
            if sock is listen_socket:
                new_conn, addr = sock.accept()
                client_sockets.append(new_conn)
                recv_buffers[new_conn] = b""
            elif sock is sys.stdin:
                user_input = sys.stdin.readline()
                if not user_input:
                    stdin_active = False
                    continue
                packet = encrypt_packet(user_input.encode('utf-8'), conf_key, auth_key)
                for c in client_sockets[:]:
                    try:
                        c.sendall(packet)
                    except Exception:
                        client_sockets.remove(c)
                        if c in recv_buffers:
                            del recv_buffers[c]
            else:
                try:
                    data = sock.recv(4096)
                except Exception:
                    data = b""
                if data:
                    recv_buffers[sock] += data
                    while True:
                        message, new_buffer = try_decrypt_packet(recv_buffers[sock], conf_key, auth_key)
                        if message is None:
                            break
                        sys.stdout.write(message.decode('utf-8'))
                        sys.stdout.flush()
                        recv_buffers[sock] = new_buffer
                else:
                    if sock in client_sockets:
                        client_sockets.remove(sock)
                    if sock in recv_buffers:
                        del recv_buffers[sock]
                    sock.close()

def run_client(hostname, conf_key, auth_key):
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((hostname, PORT))
    recv_buffer = b""
    stdin_active = True

    while True:
        read_list = [conn_sock]
        if stdin_active:
            read_list.append(sys.stdin)
        try:
            readable, _, _ = select.select(read_list, [], [])
        except ValueError:
            break

        for sock in readable:
            if sock is conn_sock:
                try:
                    data = conn_sock.recv(4096)
                except Exception:
                    data = b""
                if data:
                    recv_buffer += data
                    while True:
                        message, new_buffer = try_decrypt_packet(recv_buffer, conf_key, auth_key)
                        if message is None:
                            break
                        sys.stdout.write(message.decode('utf-8'))
                        sys.stdout.flush()
                        recv_buffer = new_buffer
                else:
                    conn_sock.close()
                    return
            elif sock is sys.stdin:
                user_input = sys.stdin.readline()
                if not user_input:
                    stdin_active = False
                    continue
                packet = encrypt_packet(user_input.encode('utf-8'), conf_key, auth_key)
                try:
                    conn_sock.sendall(packet)
                except Exception:
                    conn_sock.close()

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server', '--s', action='store_true')
    group.add_argument('--client', '--c', help="Hostname to connect to")
    
    parser.add_argument('--confkey', required=True, help="Confidentiality key (K1)")
    parser.add_argument('--authkey', required=True, help="Authenticity key (K2)")
    
    args = parser.parse_args()
    
    conf_key = derive_key(args.confkey)
    auth_key = derive_key(args.authkey)
    
    if args.server:
        run_server(conf_key, auth_key)
    elif args.client:
        if args.client == "":
            raise Exception("--c flag requires a hostname argument")
        run_client(args.client, conf_key, auth_key)

if __name__ == '__main__':
    main()
