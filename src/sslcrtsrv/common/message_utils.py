# Message utilities for the SSL Key Repository application

import json
import secrets
import time
from typing import Dict, Any, Optional
from .. import __version__
from .constants import (
    MSG_REGISTER, MSG_STATUS, MSG_LISTCERTS, MSG_REQUEST, MSG_RESPONSE,
    MSG_CONGESTION, REQUEST_NONCE_BYTES
)


def create_register_message(client_id: str, public_key: str = None,
                              nonce: str = None, timestamp: str = None,
                              registration_proof: str = None) -> Dict[str, Any]:
    """Create a registration message"""
    message = {
        "type": MSG_REGISTER,
        "client_id": client_id,
        # Advertised to the server so it can record it against this client
        # (see common/server_utils.py's handle_registration()) - not a
        # negotiated protocol version, just informational.
        "client_version": __version__
    }

    # Include the actual public key if provided
    if public_key is not None:
        message["public_key"] = public_key

    # Proof of knowledge of the shared registration secret, bound to a nonce
    # and timestamp so a captured registration message can't be replayed
    if nonce is not None:
        message["nonce"] = nonce
    if timestamp is not None:
        message["timestamp"] = timestamp
    if registration_proof is not None:
        message["registration_proof"] = registration_proof

    return message


def create_status_message(status: str, server_state: str = None) -> Dict[str, Any]:
    """Create a status message"""
    message = {
        "type": MSG_STATUS,
        "status": status
    }
    
    if server_state:
        message["server_state"] = server_state
        
    return message


def create_listcerts_message() -> Dict[str, Any]:
    """Create a list certificates message"""
    return {
        "type": MSG_LISTCERTS
    }


def create_request_message(request_type: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Create a request message"""
    message = {
        "type": MSG_REQUEST,
        "request_type": request_type,
        # See create_register_message()'s client_version - refreshed on
        # every request, not just at registration, so the server's record
        # stays current across a client upgrade.
        "client_version": __version__,
        # Anti-replay, mirroring create_register_message()'s nonce/timestamp -
        # checked (and the nonce consumed) by common/server_utils.py's
        # handle_request() before any request_type-specific handler runs, so
        # a captured-and-replayed request can't be processed a second time.
        "nonce": secrets.token_hex(REQUEST_NONCE_BYTES),
        "timestamp": str(int(time.time()))
    }

    if data:
        message["data"] = data

    return message


def create_response_message(response_type: str, success: bool,
                           data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Create a response message"""
    message = {
        "type": MSG_RESPONSE,
        "response_type": response_type,
        "success": success,
        # Advertised symmetrically to client_version above, so a client can
        # compare it against its own (see client.py's checkversion command).
        "server_version": __version__
    }

    if data:
        message["data"] = data

    return message


def create_congestion_message(delay: int = 5) -> Dict[str, Any]:
    """Create a congestion message"""
    return {
        "type": MSG_CONGESTION,
        "delay": delay
    }


def is_valid_message(message: Dict[str, Any]) -> bool:
    """Validate if a message has the required structure"""
    if not isinstance(message, dict):
        return False
        
    if "type" not in message:
        return False
        
    # Check for required fields based on message type
    msg_type = message.get("type")
    
    if msg_type == MSG_REGISTER:
        # Registration only requires client_id and optionally public_key
        required_fields = ["client_id"]
        if "public_key" in message:
            # If we have a public key, the message is valid
            return True
        else:
            # If no public key, then at least client_id is required
            return all(key in message for key in required_fields)
    elif msg_type == MSG_REQUEST:
        return "request_type" in message
    elif msg_type == MSG_RESPONSE:
        return all(key in message for key in ["response_type", "success"])
    elif msg_type == MSG_CONGESTION:
        return "delay" in message
        
    # For other message types, just validate basic structure
    return True


def parse_message(message_str: str) -> Optional[Dict[str, Any]]:
    """Parse a JSON string into a message dictionary"""
    try:
        return json.loads(message_str)
    except json.JSONDecodeError:
        return None


def serialize_message(message: Dict[str, Any]) -> str:
    """Serialize a message dictionary to JSON string"""
    try:
        return json.dumps(message)
    except Exception as e:
        print(f"Error serializing message: {e}")
        return ""
