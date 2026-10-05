import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


VERSION = 1

DIRECTION_G2N = 1
DIRECTION_N2G = 2

HEADER_SIZE = 15
TAG_SIZE = 32
IV_SIZE = 16


def aes_ctr_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

    encryptor = cipher.encryptor()

    return (encryptor.update(plaintext)+ encryptor.finalize())


def aes_ctr_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

    decryptor = cipher.decryptor()

    return (decryptor.update(ciphertext) + decryptor.finalize())


def build_header(direction, sequence, message_type, ciphertext_length):
    if direction not in (DIRECTION_G2N, DIRECTION_N2G):
        raise ValueError("Invalid direction")

    if not 0 <= sequence < 2**64:
        raise ValueError("Invalid sequence number")

    if not 0 <= message_type <= 255:
        raise ValueError("Invalid message type")

    if not 0 <= ciphertext_length < 2**32:
        raise ValueError("Invalid ciphertext length")

    return (
        VERSION.to_bytes(1, "big")
        + direction.to_bytes(1, "big")
        + sequence.to_bytes(8, "big")
        + message_type.to_bytes(1, "big")
        + ciphertext_length.to_bytes(4, "big")
    )


def parse_header(header):
    if len(header) != HEADER_SIZE:
        raise ValueError("Invalid header length")

    version = header[0]
    direction = header[1]

    sequence = int.from_bytes(
        header[2:10],
        "big"
    )

    message_type = header[10]

    ciphertext_length = int.from_bytes(
        header[11:15],
        "big"
    )

    if version != VERSION:
        raise ValueError("Unsupported version")

    if direction not in (DIRECTION_G2N, DIRECTION_N2G):
        raise ValueError("Invalid direction")

    return {
        "version": version,
        "direction": direction,
        "sequence": sequence,
        "message_type": message_type,
        "ciphertext_length": ciphertext_length,
    }


def build_iv(session_id, sequence):
    if len(session_id) != 8:
        raise ValueError("Session ID must be 8 bytes")

    if not 0 <= sequence < 2**64:
        raise ValueError("Invalid sequence number")

    return (
        session_id
        + sequence.to_bytes(8, "big")
    )


def seal(
    k_enc,
    k_mac,
    session_id,
    direction,
    sequence,
    message_type,
    plaintext
):
    """
    Encrypt and authenticate one record.
    """

    iv = build_iv(session_id, sequence)

    ciphertext = aes_ctr_encrypt(
        k_enc,
        iv,
        plaintext
    )

    header = build_header(
        direction,
        sequence,
        message_type,
        len(ciphertext)
    )

    tag = hmac.new(
        k_mac,
        header + iv + ciphertext,
        hashlib.sha256
    ).digest()

    return header + ciphertext + tag


def open_record(
    k_enc,
    k_mac,
    session_id,
    expected_direction,
    expected_sequence,
    record
):
    """
    Authenticate and decrypt one record.

    Authentication is performed BEFORE plaintext is released.
    """

    # Must contain at least header + tag.
    if len(record) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("Record too short")

    header = record[:HEADER_SIZE]

    parsed = parse_header(header)

    # Check direction.
    if parsed["direction"] != expected_direction:
        raise ValueError("Wrong record direction")

    # Check exact expected sequence number.
    if parsed["sequence"] != expected_sequence:
        raise ValueError("Unexpected sequence number")

    ciphertext_length = parsed["ciphertext_length"]

    expected_record_length = (
        HEADER_SIZE
        + ciphertext_length
        + TAG_SIZE
    )

    if len(record) != expected_record_length:
        raise ValueError("Invalid record length")

    ciphertext_start = HEADER_SIZE
    ciphertext_end = HEADER_SIZE + ciphertext_length

    ciphertext = record[
        ciphertext_start:ciphertext_end
    ]

    received_tag = record[
        ciphertext_end:ciphertext_end + TAG_SIZE
    ]

    iv = build_iv(
        session_id,
        parsed["sequence"]
    )

    expected_tag = hmac.new(
        k_mac,
        header + iv + ciphertext,
        hashlib.sha256
    ).digest()

    # Constant-time MAC comparison.
    if not hmac.compare_digest(
        received_tag,
        expected_tag
    ):
        raise ValueError("Invalid authentication tag")

    # Only decrypt after successful authentication.
    plaintext = aes_ctr_decrypt(
        k_enc,
        iv,
        ciphertext
    )

    return plaintext, parsed["message_type"]


if __name__ == "__main__":
    import os

    k_enc = os.urandom(32)
    k_mac = os.urandom(32)
    session_id = os.urandom(8)

    plaintext = b'{"action":"READ","path":"notes.txt"}'

    record = seal(
        k_enc,
        k_mac,
        session_id,
        DIRECTION_G2N,
        0,
        1,
        plaintext
    )

    print("Original plaintext :", plaintext)
    print("Protected record   :", record.hex())

    recovered, message_type = open_record(
        k_enc,
        k_mac,
        session_id,
        DIRECTION_G2N,
        0,
        record
    )

    print("Recovered plaintext:", recovered)
    print("Message type       :", message_type)
