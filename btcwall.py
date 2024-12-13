import os
import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

def generate_private_key():
    """
    Generate a random 256-bit private key.
    """
    return os.urandom(32)

def private_key_to_public_key(private_key):
    """
    Generate the public key from the private key using the secp256k1 curve.
    The public key can be in compressed (33 bytes) or uncompressed (65 bytes) format.
    """
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    public_key = b'\x04' + sk.verifying_key.to_string()  # Uncompressed public key
    return public_key

def public_key_to_address(public_key):
    """
    Generate a Bitcoin address from the public key.
    Steps:
    1. Apply SHA-256 to the public key.
    2. Apply RIPEMD-160 to the SHA-256 hash.
    3. Add a network byte (0x00 for mainnet).
    4. Compute the checksum (first 4 bytes of double SHA-256).
    5. Append the checksum to the hash.
    6. Encode in Base58.
    """
    # Step 1: SHA-256
    sha256_public_key = hashlib.sha256(public_key).digest()

    # Step 2: RIPEMD-160
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_public_key)
    hash160 = ripemd160.digest()

    # Step 3: Add network byte
    network_byte = b'\x00'  # Mainnet
    hash160_with_network = network_byte + hash160

    # Step 4: Compute checksum
    checksum = hashlib.sha256(hashlib.sha256(hash160_with_network).digest()).digest()[:4]

    # Step 5: Append checksum and encode in Base58
    address = base58.b58encode(hash160_with_network + checksum)
    return address.decode()

def main():
    # Step 1: Generate a private key
    private_key = generate_private_key()
    print(f"Private Key (hex): {private_key.hex()}")

    # Step 2: Generate the public key from the private key
    public_key = private_key_to_public_key(private_key)
    print(f"Public Key (hex): {public_key.hex()}")

    # Step 3: Generate the Bitcoin address from the public key
    bitcoin_address = public_key_to_address(public_key)
    print(f"Bitcoin Address: {bitcoin_address}")

if __name__ == "__main__":
    main()
