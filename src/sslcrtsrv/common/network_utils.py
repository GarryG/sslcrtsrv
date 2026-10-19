import socket
import json
import time
import random
import zlib
from datetime import datetime
from typing import Optional, Dict, Any
from .constants import (
    DEFAULT_TIMEOUT, MAX_RETRY_ATTEMPTS, BASE_RETRY_DELAY, MAX_RETRY_DELAY,
    MAX_MESSAGE_SIZE, MAX_SIGNATURE_SIZE, MAX_DECOMPRESSED_MESSAGE_SIZE
)
from .crypto_utils import sign_message, verify_signature, encrypt_data, decrypt_data


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def send_secure_message(sock: socket.socket, data: Dict[str, Any], 
                       private_key=None, public_key=None) -> bool:
    """Send a secure message with optional signing and encryption"""
    try:
        # Serialize the "data" content as a JSON string
        message_json = json.dumps(data, cls=DateTimeEncoder)
        # print(f"Original message: {message_json}")
        # print(f"Original message length: {len(message_json)} bytes")
        
        # Compress the JSON string
        compressed_data = zlib.compress(message_json.encode('utf-8'))
        # print(f"Compressed message sent: {compressed_data.hex()}")
        compressed_len = len(compressed_data)
        # print(f"Compressed message length: {compressed_len} bytes")
        # print(f"Compressed data (HEX): {compressed_data.hex()}")
        
        # If we have a public key, encrypt the compressed data
        encrypted_data = None
        encrypted_len = 0
        signature_data = None
        
        if public_key is not None:
            # Encrypt the compressed binary data
            # print(f"public key: {public_key}")
            encrypted_data = encrypt_data(compressed_data, public_key)
            if encrypted_data is None:
                return False
            encrypted_len = len(encrypted_data)
        else:
            # Use the compressed data directly
            encrypted_data = compressed_data
            encrypted_len = compressed_len
            
        # If we have a private key, create a signature over the compressed binary data
        if private_key is not None:
            signature = sign_message(compressed_data, private_key)
            if signature:
                signature_data = signature
                signature_len = len(signature_data)
            else:
                # If signing fails, we might want to return False or continue
                signature_data = None
        
        # Prepare the data to send according to the specified format:
        # - length of the data (encrypted length if encrypted, otherwise unencrypted length)
        # - followed by the data (encrypted or unencrypted)
        # - the length of the signature (0 if no signature, 4 bytes otherwise)
        # - the signature (if exists)

        # Send flag to show whether the data is encrypted (1 byte, 0 for unencrypted, 1 for encrypted)
        encryption_flag = b'\x01' if public_key is not None else b'\x00'
        sock.send(encryption_flag)

        # Send the length of the data (encrypted length if encrypted, otherwise compressed length)
        data_length_bytes = encrypted_len.to_bytes(4, byteorder='big')
        sock.send(data_length_bytes)
        
        # Send the data itself
        sock.send(encrypted_data)
        # print(f"Encrypted message sent: {encrypted_data.hex()}")
        
        # Send the length of signature data (0 if no signature, 4 bytes otherwise)
        if signature_data is not None:
            signature_length_bytes = signature_len.to_bytes(4, byteorder='big')
            sock.send(signature_length_bytes)
            # Send the signature data
            sock.send(signature_data)
        else:
            # Send 4 zero bytes to indicate no signature
            sock.send(b'\x00\x00\x00\x00')
        
        return True
    except Exception as e:
        print(f"Error sending secure message: {e}")
        return False


def _decompress_bounded(data: bytes, max_size: int, what: str = "message") -> Optional[bytes]:
    """zlib-decompress data, refusing to produce more than max_size bytes of
    output. Without this, a small, highly compressible payload can force an
    arbitrarily large memory allocation (a "decompression bomb") regardless
    of how little data was actually received over the wire - capping only
    the wire length (see MAX_MESSAGE_SIZE) does not prevent this, since
    zlib's compression ratio can exceed 1000:1."""
    decompressor = zlib.decompressobj()
    try:
        result = decompressor.decompress(data, max_size)
    except Exception as e:
        print(f"Error decompressing {what}: {e}")
        return None
    if decompressor.unconsumed_tail:
        print(f"Error: decompressed {what} exceeds the {max_size}-byte limit - "
              f"rejecting (possible decompression bomb)")
        return None
    return result


def receive_secure_message(sock: socket.socket,
                          private_key=None, public_key=None, is_from_client=False) -> Optional[Dict[str, Any]]:
    """Receive and verify a secure message with optional signature verification"""
    try:
        # Receive the encryption flag (1 byte)
        encryption_flag = sock.recv(1)

        # Receive the message length (4 bytes)
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None

        # Convert length bytes to integer
        message_length = int.from_bytes(length_bytes, byteorder='big')

        # Reject outright rather than buffering whatever a peer claims -
        # real messages here are small JSON control/status payloads (see
        # MAX_MESSAGE_SIZE's definition), so a peer declaring anything past
        # this is either broken or hostile.
        if message_length > MAX_MESSAGE_SIZE:
            print(f"Error: peer declared a message length of {message_length} bytes, "
                  f"exceeding the {MAX_MESSAGE_SIZE}-byte limit - refusing")
            return None

        # Receive the actual message data
        message_data = b""
        while len(message_data) < message_length:
            chunk = sock.recv(message_length - len(message_data))
            if not chunk:
                return None
            message_data += chunk

        if not message_data:
            return None

        # Receive signature length (4 bytes)
        signature_length_bytes = sock.recv(4)


        signature_length = int.from_bytes(signature_length_bytes, byteorder='big')

        if signature_length > MAX_SIGNATURE_SIZE:
            print(f"Error: peer declared a signature length of {signature_length} bytes, "
                  f"exceeding the {MAX_SIGNATURE_SIZE}-byte limit - refusing")
            return None

        # Receive signature data if present
        signature_data = None
        if signature_length > 0:
            signature_data = b""
            while len(signature_data) < signature_length:
                chunk = sock.recv(signature_length - len(signature_data))
                if not chunk:
                    return None
                signature_data += chunk
        
        # Determine if we need to decrypt based on the encryption flag
        is_encrypted = encryption_flag == b'\x01'
        
        # If we have a private key, decrypt the message data if needed
        if private_key is not None and is_encrypted:
            try:
                # Decrypt the message using private key
                # print(f"Message data: {message_data.hex()}")
                decrypted_data = decrypt_data(message_data, private_key)
                # print(f"Decrypted message data: {decrypted_data.hex()}")
                compressed_data = decrypted_data
                if decrypted_data is None:
                    print("Error decrypting message")
                    return None
                # The decrypted_data is binary data that was compressed before encryption
                # We need to decompress it
                decompressed_data = _decompress_bounded(decrypted_data, MAX_DECOMPRESSED_MESSAGE_SIZE)
                if decompressed_data is None:
                    return None
                response_str = decompressed_data.decode('utf-8')
            except Exception as e:
                print(f"Error decrypting and decompressing message: {e}")
                return None
        elif private_key is None or not is_encrypted:
            # No decryption needed, just decompress
            try:
                # Debug output for received data
                # print(f"Received message data (HEX): {message_data.hex()}")
                compressed_data = message_data
                decompressed_data = _decompress_bounded(message_data, MAX_DECOMPRESSED_MESSAGE_SIZE)
                if decompressed_data is None:
                    return None
                response_str = decompressed_data.decode('utf-8')
            except Exception as e:
                print(f"Error decompressing message: {e}")
                return None
        
        # Parse JSON
        response_data = json.loads(response_str)
        # print(f"Received message data: {response_data} {is_from_client}")
        # Set once we've resolved a known client below, so the verification
        # outcome can be recorded against that client's connection-health
        # columns (see database.py's update_client_connection_success/failure) -
        # left None for messages not from a known client (e.g. registration,
        # or is_from_client callers receiving a server response), which have
        # nothing to record against.
        verified_client_id = None
        if is_from_client==1:
            if (response_data['type']!="register"):             # Don't try to find a client for a register message, since it won't have a client_id yet
                from .database import get_client
                # Make sure we have the client_id in the data
                client_id = response_data['data']['client_id']
                if client_id:
                    client = get_client(client_id)
                    if not client:
                        print(f"Error: No client found with client_id {client_id}")
                        return None             # Don't allow processing of messages from clients that aren't registered, since we won't be able to verify their signature without their public key
                    # print(f"Got client data: {client}")
                    public_key_str = client.public_key
                    # print(f"Got public key string for client {client_id}: {public_key_str}")
                    from .crypto_utils import load_public_key_from_string
                    public_key = load_public_key_from_string(public_key_str)
                    # print(f"Public key for client {client_id}: {public_key} ")
                    response_data['client_public_key'] = public_key
                    verified_client_id = client_id
                else:
                    print(f"Error: No client_id found in response data for type {response_data['type']}")
                    return None             # Don't allow processing of messages that don't have a client_id, since we won't be able to verify their signature without it

        # If we have keys for verification and there's a signature, verify it
        if public_key is not None:
            if signature_data is not None:
                # Check if signature is valid
                if not verify_signature(compressed_data, signature_data, public_key):
                    print("Warning: Message signature verification failed")
                    if verified_client_id:
                        from .database import update_client_connection_failure
                        update_client_connection_failure(verified_client_id)
                    return None
            else:
                print("Error: No signature available for verification")
                if verified_client_id:
                    from .database import update_client_connection_failure
                    update_client_connection_failure(verified_client_id)
                return None

        if verified_client_id:
            from .database import update_client_connection_success, update_client_last_ip, update_client_version
            update_client_connection_success(verified_client_id)
            try:
                update_client_last_ip(verified_client_id, sock.getpeername()[0])
            except OSError:
                pass  # socket already gone - connection-success tracking above still happened
            client_version = response_data.get('client_version')
            if client_version:
                update_client_version(verified_client_id, client_version)

        return response_data
    except Exception as e:
        print(f"Error receiving secure message: {e}")
        return None


def retry_with_backoff(func, *args, **kwargs):
    """Execute a function with exponential backoff retry logic"""
    for attempt in range(MAX_RETRY_ATTEMPTS):
        try:
            result = func(*args, **kwargs)
            if result is not None:
                return result
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            
        # Exponential backoff with jitter
        if attempt < MAX_RETRY_ATTEMPTS - 1:
            delay = min(BASE_RETRY_DELAY * (2 ** attempt), MAX_RETRY_DELAY)
            jitter = random.uniform(0, 1)
            time.sleep(delay + jitter)
    
    return None


def handle_congestion_response(sock: socket.socket, 
                              congestion_info: Dict[str, Any]) -> bool:
    """Handle server congestion response by waiting and retrying"""
    try:
        # Get the congestion delay
        delay = congestion_info.get('delay', BASE_RETRY_DELAY)
        
        print(f"Server is congested. Waiting {delay} seconds before retry...")
        time.sleep(delay)
        
        return True
    except Exception as e:
        print(f"Error handling congestion: {e}")
        return False
