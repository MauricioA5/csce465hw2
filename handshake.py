import os
import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"

GATEWAY_ROLE = b"gateway"
NODE_ROLE = b"node"

DH_WIDTH = 384
NONCE_SIZE = 16
TRANSCRIPT_FIELD_COUNT = 8


def load_dh_parameters(filename="ffdhe3072.pem"):
    with open(filename, "rb") as f:
        return serialization.load_pem_parameters(f.read())


def generate_ephemeral_dh(parameters):
    return parameters.generate_private_key()


def dh_public_bytes(public_key):
    """Encode ffdhe3072 public value as 384 bytes."""
    y = public_key.public_numbers().y
    return y.to_bytes(DH_WIDTH, byteorder="big")

def generate_rsa_key():
    """Generate a 3072-bit RSA key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )


def encode_field(field):
    """Encode one field as 4-byte big-endian length || field."""
    return len(field).to_bytes(4, byteorder="big") + field


def build_transcript(gateway_id, node_id, gateway_dh_public,
                     node_dh_public,gateway_nonce,node_nonce):
    """ Build handshake in order."""

    if len(gateway_dh_public) != DH_WIDTH:
        raise ValueError("Invalid gateway DH public value length")

    if len(node_dh_public) != DH_WIDTH:
        raise ValueError("Invalid node DH public value length")

    if len(gateway_nonce) != NONCE_SIZE:
        raise ValueError("Invalid gateway nonce length")

    if len(node_nonce) != NONCE_SIZE:
        raise ValueError("Invalid node nonce length")

    fields = [PROTOCOL_LABEL,GROUP_ID,
        gateway_id,node_id,
        gateway_dh_public,node_dh_public,
        gateway_nonce,node_nonce,]

    return b"".join(encode_field(field) for field in fields)


def parse_transcript(transcript):
    """Parse and validate all transcript fields."""
    fields = []
    offset = 0

    for _ in range(TRANSCRIPT_FIELD_COUNT):

        # There must be enough bytes for the 4-byte length.
        if offset + 4 > len(transcript):
            raise ValueError("Malformed transcript: missing field length")

        field_length = int.from_bytes(
            transcript[offset:offset + 4],
            byteorder="big"
        )

        offset += 4

        # Field length must fit inside the transcript.
        if offset + field_length > len(transcript):
            raise ValueError("Malformed transcript: incorrect field length")

        field = transcript[offset:offset + field_length]
        fields.append(field)

        offset += field_length

    # Check for no extra bytes
    if offset != len(transcript):
        raise ValueError("Malformed transcript: unexpected trailing data")

    (protocol_label,
     group_id, gateway_id, node_id,
     gateway_dh_public, node_dh_public,
    gateway_nonce, node_nonce,
    ) = fields

    # Validate fixed  fields.
    if protocol_label != PROTOCOL_LABEL:
        raise ValueError("Unexpected protocol label")

    if group_id != GROUP_ID:
        raise ValueError("Unexpected DH group")

    if len(gateway_dh_public) != DH_WIDTH:
        raise ValueError("Invalid gateway DH public value length")

    if len(node_dh_public) != DH_WIDTH:
        raise ValueError("Invalid node DH public value length")

    if len(gateway_nonce) != NONCE_SIZE:
        raise ValueError("Invalid gateway nonce length")

    if len(node_nonce) != NONCE_SIZE:
        raise ValueError("Invalid node nonce length")

    return {
        "protocol_label": protocol_label,
        "group_id": group_id,
        "gateway_id": gateway_id,
        "node_id": node_id,
        "gateway_dh_public": gateway_dh_public,
        "node_dh_public": node_dh_public,
        "gateway_nonce": gateway_nonce,
        "node_nonce": node_nonce,
    }


def transcript_hash(transcript):
    """ Validate transcript before hashing it. """
    parse_transcript(transcript)
    return hashlib.sha256(transcript).digest()


# Authentication

def sign_transcript(private_key, role, transcript):
    th = transcript_hash(transcript)
    # Required signed message: role || SHA-256(transcript)
    message = role + th

    return private_key.sign(
        message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(public_key, role, transcript, signature):
    th = transcript_hash(transcript)
    message = role + th

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise ValueError("Invalid handshake signature")


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def derive_keys(shared_secret, transcript):
    th = transcript_hash(transcript)

    k_master = hashlib.sha256(
        b"CSCE465-KDF-v1" + shared_secret + th
    ).digest()

    k_g2n_enc = hmac_sha256(
        k_master,
        b"gateway-to-node encryption" + th
    )

    k_g2n_mac = hmac_sha256(
        k_master,
        b"gateway-to-node MAC" + th
    )

    k_n2g_enc = hmac_sha256(
        k_master,
        b"node-to-gateway encryption" + th
    )

    k_n2g_mac = hmac_sha256(
        k_master,
        b"node-to-gateway MAC" + th
    )

    session_id = hmac_sha256(
        k_master,
        b"session identifier" + th
    )[:8]

    return {
        "k_master": k_master,
        "k_g2n_enc": k_g2n_enc,
        "k_g2n_mac": k_g2n_mac,
        "k_n2g_enc": k_n2g_enc,
        "k_n2g_mac": k_n2g_mac,
        "session_id": session_id,
    }



def perform_handshake():
    print("Authenticated Diffie-Hellman Handshake")

    parameters = load_dh_parameters()

    # Long-term RSA identity/signing keys
    gateway_rsa = generate_rsa_key()
    node_rsa = generate_rsa_key()

    # Fresh ephemeral DH private keys
    gateway_dh = generate_ephemeral_dh(parameters)
    node_dh = generate_ephemeral_dh(parameters)

    # Fresh 16-byte nonces
    gateway_nonce = os.urandom(NONCE_SIZE)
    node_nonce = os.urandom(NONCE_SIZE)

    # Fixed-width DH public values
    gateway_dh_bytes = dh_public_bytes(gateway_dh.public_key())
    node_dh_bytes = dh_public_bytes(node_dh.public_key())

    # Build canonical transcript
    transcript = build_transcript(
        GATEWAY_ID, NODE_ID,
        gateway_dh_bytes, node_dh_bytes,
        gateway_nonce, node_nonce
    )

    # Validate before hashing
    parsed = parse_transcript(transcript)

    # Explicit identity checks
    if parsed["gateway_id"] != GATEWAY_ID:
        raise ValueError("Unexpected gateway identity")

    if parsed["node_id"] != NODE_ID:
        raise ValueError("Unexpected node identity")

    th = transcript_hash(transcript)

    print("Gateway identity :", parsed["gateway_id"].decode())
    print("Node identity    :", parsed["node_id"].decode())
    print("Gateway nonce    :", gateway_nonce.hex())
    print("Node nonce       :", node_nonce.hex())
    print("Transcript hash  :", th.hex())

    # Sign role and hash
    gateway_signature = sign_transcript(gateway_rsa, GATEWAY_ROLE, transcript)

    node_signature = sign_transcript(node_rsa, NODE_ROLE,transcript)

    # Verify node
    verify_signature(node_rsa.public_key(), NODE_ROLE, transcript,node_signature)

    print("Gateway verified node signature.")

    # Verify gateway
    verify_signature(gateway_rsa.public_key(), GATEWAY_ROLE, transcript, gateway_signature)

    print("Node verified gateway signature.")

    # Each side independently calculates Z.
    gateway_secret = gateway_dh.exchange(node_dh.public_key())

    node_secret = node_dh.exchange(gateway_dh.public_key())

    # Represent as 384 bytes.
    gateway_secret = int.from_bytes(gateway_secret, byteorder="big").to_bytes(DH_WIDTH, byteorder="big")

    node_secret = int.from_bytes(node_secret,byteorder="big").to_bytes(DH_WIDTH, byteorder="big")

    if gateway_secret != node_secret:
        raise ValueError("Diffie-Hellman shared secrets do not match")

    print("DH shared secrets match.")

    # Independently derive session keys
    gateway_keys = derive_keys(gateway_secret,transcript)

    node_keys = derive_keys(node_secret,transcript)

    if gateway_keys != node_keys:
        raise ValueError("Derived session keys do not match")

    print("Derived session keys match.")
    print("Session ID       :", gateway_keys["session_id"].hex())

    print("\nHandshake successful.")

    return gateway_keys

# MAIN
if __name__ == "__main__":
    perform_handshake()
