import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COMMAND = b'{"action":"READ","path":"notes.txt"}'


def encrypt(key, iv, plaintext):
    """Encrypt using AES-256 in CTR mode."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(key, iv, ciphertext):
    """Decrypt using AES-256 in CTR mode."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def relay_modify(ciphertext, original, replacement):
    """
    Modifies AES-CTR ciphertext without knowing the key.

    CTR: C = P XOR stream

    Therefore: C' = C XOR P XOR P'

    Decrypted plaintext changes from from P to P'.
    """
    if len(original) != len(replacement):
        raise ValueError("Original and replacement must be of equal length")

    # Area to modify is found at th e beginning of the command
    offset = COMMAND.index(original)

    # XOR difference to transform original into replacement
    xor_delta = bytes( old ^ new for old, new in zip(original, replacement))

    print("\nRelay bit-flip attack")
    print("Original bytes    :", original.hex())
    print("Replacement bytes :", replacement.hex())
    print("XOR difference    :", xor_delta.hex())
    print("Target offset     :", offset)

    modified = bytearray(ciphertext)

    # Apply XOR difference directly to the ciphertext
    for i in range(len(xor_delta)):
        modified[offset + i] ^= xor_delta[i]

    return bytes(modified)


def receiver(key, iv, ciphertext):
    plaintext = decrypt(key, iv, ciphertext)
    print("Receiver processed:", plaintext)


def main():
    # AES-256 uses a 32-byte key.
    key = os.urandom(32)

    # AES has a 16-byte block size, so CTR uses a 16-byte initial counter/IV.
    iv = os.urandom(16)

    print("AES-CTR Baseline")

    ciphertext = encrypt(key, iv, COMMAND)

    print("Original plaintext :", COMMAND)
    print("Ciphertext (hex)    :", ciphertext.hex())

    recovered = decrypt(key, iv, ciphertext)
    print("Decrypted plaintext :", recovered)

    # Attack 1: Modify READ to SEND without knowing the AES key

    modified_ciphertext = relay_modify(ciphertext,b"READ", b"SEND")

    modified_plaintext = decrypt(key, iv, modified_ciphertext)

    print("Modified ciphertext:", modified_ciphertext.hex())
    print("Modified plaintext :", modified_plaintext)

    # Attack 2: Replay exactly the same ciphertext

    print("\nReplay attack")
    print("Sending the same ciphertext twice:")

    receiver(key, iv, ciphertext)
    receiver(key, iv, ciphertext)


if __name__ == "__main__":
    main()
