#!/bin/python3

from secrets import randbits
from ecdsa import SigningKey, SECP256k1
from hashlib import new 
from base58check import b58encode


def hasher(bytestring, hashAlg):
    """Apply given hash alorithm to bytestring. Returns as bytes object.
    """
    hashObj = new(hashAlg)
    hashObj.update(bytestring)
    return hashObj.digest()
    

def pairEncode(hex_string):
    if len(hex_string) % 2:
        hex_string = '0' + hex_string
    return bytes.fromhex(hex_string)


# Generate cryptographically strong 256 bit private key.
private_key = randbits(256)

# Generate ECDSA signing (private) and verifying (public) keys from private key.
signing_key = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
verifying_key = signing_key.get_verifying_key()

# Concatenate (x, y) points to create public key.
x = verifying_key.pubkey.point.x()
x = pairEncode(f'{x:x}')
y = verifying_key.pubkey.point.y()
y = pairEncode(f'{y:x}')

full_public_key = b'\x00' + x + y

# Compress the public key.
prefix = b'\x03' if y[-1] % 2 else b'\x02'
public_key = prefix + x

# Calculate the address.
# Encrypt public key.
public_hash = hasher(public_key, 'sha256')
encrypted_public_key = hasher(public_hash, 'ripemd160')

# Add network byte (main: 0x00, test:0x6f)
encrypted_public_key = b'\x00' + encrypted_public_key

# Calculate the checksum.
checksum = hasher(encrypted_public_key, 'sha256')
checksum = hasher(checksum, 'sha256')
checksum = checksum[:4] # last 4 bytes

# Merge mainnet key and checksum and encode with base58check to make address.
address = b58encode(encrypted_public_key + checksum).decode('ascii')


print(f'Private Key: {private_key:x}')
print('Public Key:', public_key.hex())
print('Address:', address)
