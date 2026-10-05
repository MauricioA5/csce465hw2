import os

import pytest

from hw2.handshake import (
    perform_handshake,
    generate_rsa_key,
    sign_transcript,
    verify_signature,
    build_transcript,
    load_dh_parameters,
    generate_ephemeral_dh,
    dh_public_bytes,
    GATEWAY_ID,
    NODE_ID,
    NODE_ROLE,
)

from hw2.secure_record import (
    seal,
    open_record,
    DIRECTION_G2N,
    DIRECTION_N2G,
)

# Helpers

def make_session():
    """
    Run the authenticated handshake and return its derived keys.
    """
    return perform_handshake()


def make_record_keys():
    """
    Generate standalone record-layer keys for tests that do not
    specifically need to exercise the handshake.
    """
    return {
        "k_g2n_enc": os.urandom(32),
        "k_g2n_mac": os.urandom(32),
        "k_n2g_enc": os.urandom(32),
        "k_n2g_mac": os.urandom(32),
        "session_id": os.urandom(8),
    }


# Valid handshake and bidirectional messages

def test_valid_handshake_and_bidirectional_messages():
    keys = make_session()

    # Gateway -> Node
    g2n_plaintext = b"hello from gateway"

    g2n_record = seal(
        keys["k_g2n_enc"],
        keys["k_g2n_mac"],
        keys["session_id"],
        DIRECTION_G2N,
        0,
        1,
        g2n_plaintext,
    )

    recovered, message_type = open_record(
        keys["k_g2n_enc"],
        keys["k_g2n_mac"],
        keys["session_id"],
        DIRECTION_G2N,
        0,
        g2n_record,
    )

    assert recovered == g2n_plaintext
    assert message_type == 1

    # Node -> Gateway
    n2g_plaintext = b"hello from node"

    n2g_record = seal(
        keys["k_n2g_enc"],
        keys["k_n2g_mac"],
        keys["session_id"],
        DIRECTION_N2G,
        0,
        1,
        n2g_plaintext,
    )

    recovered, message_type = open_record(
        keys["k_n2g_enc"],
        keys["k_n2g_mac"],
        keys["session_id"],
        DIRECTION_N2G,
        0,
        n2g_record,
    )

    assert recovered == n2g_plaintext
    assert message_type == 1


# 2. Modified cyphertext

def test_modified_ciphertext_rejected():
    keys = make_record_keys()

    record = seal(
        keys["k_g2n_enc"],
        keys["k_g2n_mac"],
        keys["session_id"],
        DIRECTION_G2N,
        0,
        1,
        b"secret message",
    )

    modified = bytearray(record)

    # Header is 15 bytes, so byte 15 is the first ciphertext byte.
    modified[15] ^= 0x01

    with pytest.raises(
        ValueError,
        match="Invalid authentication tag"
    ):
        open_record(
            keys["k_g2n_enc"],
            keys["k_g2n_mac"],
            keys["session_id"],
            DIRECTION_G2N,
            0,
            bytes(modified),
        )


# 3. Modified authenticated header

def test_modified_header_rejected():
    keys = make_record_keys()

    record = seal(
        keys["k_g2n_enc"],
        keys["k_g2n_mac"],
        keys["session_id"],
        DIRECTION_G2N,
        0,
        1,
        b"secret message",
    )

    modified = bytearray(record)

    # Byte 10 is message_type.
    # Changing it preserves a syntactically valid header but invalidates
    # the HMAC because the header is authenticated.
    modified[10] ^= 0x01

    with pytest.raises(
        ValueError,
        match="Invalid authentication tag"
    ):
        open_record(
            keys["k_g2n_enc"],
            keys["k_g2n_mac"],
            keys["session_id"],
            DIRECTION_G2N,
            0,
            bytes(modified),
        )


# 4. Replay

def test_replayed_record_rejected():
    keys = make_record_keys()

    record = seal(
        keys["k_g2n_enc"],
        keys["k_g2n_mac"],
        keys["session_id"],
        DIRECTION_G2N,
        0,
        1,
        b"perform action",
    )

    # First transmission is accepted.
    plaintext, _ = open_record(
        keys["k_g2n_enc"],
        keys["k_g2n_mac"],
        keys["session_id"],
        DIRECTION_G2N,
        0,
        record,
    )

    assert plaintext == b"perform action"

    # After accepting sequence 0, the receiver expects sequence 1.
    # Replaying record 0 must therefore fail.
    with pytest.raises(
        ValueError,
        match="Unexpected sequence number"
    ):
        open_record(
            keys["k_g2n_enc"],
            keys["k_g2n_mac"],
            keys["session_id"],
            DIRECTION_G2N,
            1,
            record,
        )


# 5. Reflection into opposite direction

def test_reflected_record_rejected():
    keys = make_record_keys()

    record = seal(
        keys["k_g2n_enc"],
        keys["k_g2n_mac"],
        keys["session_id"],
        DIRECTION_G2N,
        0,
        1,
        b"gateway command",
    )

    # Attempt to feed a gateway->node record to the
    # node->gateway receiver.
    with pytest.raises(
        ValueError,
        match="Wrong record direction"
    ):
        open_record(
            keys["k_n2g_enc"],
            keys["k_n2g_mac"],
            keys["session_id"],
            DIRECTION_N2G,
            0,
            record,
        )


# 6. Incorrect RSA public key / invalid signature

def test_incorrect_rsa_public_key_rejected():
    parameters = load_dh_parameters()

    gateway_dh = generate_ephemeral_dh(parameters)
    node_dh = generate_ephemeral_dh(parameters)

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    transcript = build_transcript(
        GATEWAY_ID,
        NODE_ID,
        dh_public_bytes(gateway_dh.public_key()),
        dh_public_bytes(node_dh.public_key()),
        gateway_nonce,
        node_nonce,
    )

    # Real node signing key
    node_private_key = generate_rsa_key()

    signature = sign_transcript(
        node_private_key,
        NODE_ROLE,
        transcript,
    )

    # Attacker/unrelated RSA key
    wrong_private_key = generate_rsa_key()
    wrong_public_key = wrong_private_key.public_key()

    # Verification with the wrong identity key must fail.
    with pytest.raises(
        ValueError,
        match="Invalid handshake signature"
    ):
        verify_signature(
            wrong_public_key,
            NODE_ROLE,
            transcript,
            signature,
        )
