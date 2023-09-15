import socket
import struct
import time
import hashlib

MAGIC_BYTES = bytes.fromhex('f9beb4d9')
VERSION = 70015

def get_bitcoin_peers_from_dns(dns_seed, port=8333):
    print(f"Fetching IP addresses from DNS seed {dns_seed}...")
    try:
        ip_addresses = socket.getaddrinfo(dns_seed, port, socket.AF_INET)
        return [ip[4][0] for ip in ip_addresses]
    except Exception as e:
        print(f"Error fetching IP addresses from DNS seed {dns_seed}: {e}")
        return []

def create_version_payload():
    version = struct.pack('i', VERSION)
    services = struct.pack('Q', 0)
    timestamp = struct.pack('q', int(time.time()))

    addr_recv = struct.pack('Q', 0) + b'\x00'*10 + b'\xFF'*2 + socket.inet_pton(socket.AF_INET, '0.0.0.0') + struct.pack('>H', 8333)
    addr_from = struct.pack('Q', 0) + b'\x00'*10 + b'\xFF'*2 + socket.inet_pton(socket.AF_INET, '0.0.0.0') + struct.pack('>H', 8333)
    
    nonce = struct.pack('Q', 0)
    user_agent_bytes = struct.pack('B', 0)
    start_height = struct.pack('i', 0)
    relay = struct.pack('?', 0)
    
    payload = version + services + timestamp + addr_recv + addr_from + nonce + user_agent_bytes + start_height + relay
    return payload

def create_message(command, payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC_BYTES + struct.pack('12s', command) + struct.pack('I', len(payload)) + checksum + payload

def create_getblocks_payload():
    version = struct.pack('i', VERSION)
    hash_count = struct.pack('B', 1)  
    block_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')  
    stop_hash = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')  
    return version + hash_count + block_hash + stop_hash

def parse_inv_payload(payload):
    offset = 0
    count, = struct.unpack_from('<B', payload, offset)
    offset += 1
    if count >= 0xfd:
        count, = struct.unpack_from('<H', payload, offset)
        offset += 2

    items = []
    for _ in range(count):
        item_type, = struct.unpack_from('<I', payload, offset)
        offset += 4
        item_hash = payload[offset:offset+32]
        offset += 32
        items.append((item_type, item_hash))

    return items

def recv_n_bytes(sock, n):
    """Utility function to receive exactly n bytes from a socket."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data

def handshake_with_node(peer_ip):
    s = socket.create_connection((peer_ip, 8333), timeout=10)
    
    # Version handshake
    version_payload = create_version_payload()
    version_msg = create_message(b'version', version_payload)
    s.send(version_msg)
    
    # Get the 'version' response
    response = s.recv(1024)
    if not response.startswith(MAGIC_BYTES):
        print(f"Unexpected response from {peer_ip}")
        return False

    if response[4:16].startswith(b'version'):
        # Send verack message
        verack_msg = create_message(b'verack', b'')
        s.send(verack_msg)
        
        # Now we send the getblocks message
        getblocks_payload = create_getblocks_payload()
        getblocks_msg = create_message(b'getblocks', getblocks_payload)
        s.send(getblocks_msg)
        
        retries = 5  # Number of times we'll retry reading messages
        while retries > 0:
            header = recv_n_bytes(s, 24)  # Read the header first
            if len(header) < 24:
                print("Incomplete header received.")
                return False

            _, command, payload_length, _ = struct.unpack('<4s12sI4s', header)
            payload = recv_n_bytes(s, payload_length)  # Now, read the payload
        
            if command.startswith(b'inv'):
                inventory_items = parse_inv_payload(payload)
                for item_type, item_hash in inventory_items:
                    if item_type == 2:  # Block
                        print(f"Received block hash: {item_hash.hex()}")
                return True
            elif command.startswith(b'verack'):
                print("Received verack, waiting for inv...")
                retries -= 1
            else:
                print(f"Unexpected message: {command}")
                retries -= 1
                continue
        
        return False
    else:
        return False

# Use one of the Bitcoin DNS seeds
dns_seed = "seed.bitcoin.sipa.be"
peers = get_bitcoin_peers_from_dns(dns_seed)

if not peers:
    print("Couldn't find any Bitcoin peers.")
else:
    connected = False
    for peer_ip in peers:
        if handshake_with_node(peer_ip):
            connected = True
            break

    if not connected:
        print("Failed to handshake with any Bitcoin peer.")
