# Random
import os
from typing import Tuple

# Hash
from cryptography.hazmat.primitives import hashes

# ECDH
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Serialization
from ureka_framework.resource.crypto.serialization_util import (
    byte_to_base64str,
    str_to_byte,
)

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_resource_func


######################################################
# Random Number Generation
#   pyca/cryptography recommends using operating system’s provided random number generator
######################################################
@measure_resource_func
def generate_random_byte(bytes_num: int) -> bytes:
    return os.urandom(bytes_num)


@measure_resource_func
def generate_random_str(bytes_num: int) -> str:
    return byte_to_base64str(os.urandom(bytes_num))


######################################################
# Hash Function
######################################################
@measure_resource_func
def generate_sha256_hash_bytes(message: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    generated_hash: bytes = digest.finalize()

    return generated_hash


@measure_resource_func
def generate_sha256_hash_str(message_str: str) -> str:
    message_bytes: bytes = str_to_byte(message_str)
    generated_hash_bytes: bytes = generate_sha256_hash_bytes(message_bytes)
    generated_hash_str: str = byte_to_base64str(generated_hash_bytes)

    return generated_hash_str


######################################################
# ECDH Key Factory
#   In a key agreement protocol deriving cryptographic keys from a Diffie-Hellman exchange
#       can derive a salt value from public nonces exchanged and authenticated between communicating parties
#       as part of the key agreement.
#       <Ref> https://datatracker.ietf.org/doc/html/rfc5869.html#section-3.1
#   Further recommand ECDHE (ECDH, ephemeral) if consider Forward Secrecy
#       -> But need exchange ephemeral public keys & bring more overhead.
#       -> A practical solution for ephemeral maybe periodically re-exchange a HKDF-derived session key.
#       -> How to set the period depends on the trade-off between security and overhead.
######################################################
@measure_resource_func
def generate_ecdh_key(
    server_private_key: ec.EllipticCurvePrivateKey,
    salt: bytes,
    info: bytes,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    # Perform ECDH
    shared_key = server_private_key.exchange(ec.ECDH(), peer_public_key)

    # Perform Key Derivation [HKDF, HMAC-based Extract-and-Expand KDF]
    # derived_key = HKDF(
    #     algorithm=hashes.SHA256(),
    #     length=32,  # The desired length of the derived key in bytes.
    #     salt=salt,  # Randomizes the KDF’s output.
    #     info=info,  # Optional: application specific context information.
    #     backend=default_backend(),
    # ).derive(shared_key)
    # print("爬蟲共享單車", shared_key.hex())
    return shared_key


######################################################
# ECDH AES Encryption (CBC Mode)
#   Need Padding:
#       https://cryptography.io/en/3.4.2/hazmat/primitives/padding.html
#   Need HMAC:
#       If ureka protocol applies Command UTicket/Data UTicket with signatures on them,
#           the AES-CBC can be used and the HMAC can be omitted.
#       However, AES+HMAC may provide better performance than Command UTicket/Data UTicket.
#                   (Because HMAC verfication may be cheaper than Signature verification.)
#           In this case, AES-GCM (Galois Counter Mode) is better,
#               which is a  AEAD (authenticated encryption with additional data) mode so that HMAC are not necessary.
######################################################
@measure_resource_func
def cbc_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    # Randomly generate IV (Initialization Vector)
    #   IV must be the same number of bytes as the block_size of the cipher.
    #   IV must be random bytes.
    #   IV do not need to be kept secret and they can be included in a transmitted message.
    #   For better security, each time something is encrypted a new IV should be generated.
    #   Do not reuse an IV with a given key, and particularly do not use a constant IV, i.e.:
    #       iv = b"1234567890abcdef"  # Dangerous.
    #       iv = generate_random_byte(16) # Recommanded, but need be transmited & perform authenticity check everytime.
    iv = generate_random_byte(16)

    # Initailize AES (CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding using PKCS7 (CBC mode needs padding)
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(plaintext) + padder.finalize()

    # Encrypt message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return (encrypted_message, iv)


######################################################
# ECDH AES Decryption (CBC Mode)
######################################################
@measure_resource_func
def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # Initailize AES (CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt message
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Padding using PKCS7 (CBC mode needs padding)
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_message


######################################################
# ECDH AES Encryption (GCM Mode)
#   Need NOT Padding & Need NOT HMAC:
#       But when decryption, it not only needs (ciphertext, key, iv), but also needs (associated_plaintext, authentication_tag)
#       <Ref> https://cryptography.io/en/3.4.2/hazmat/primitives/symmetric-encryption.html#cryptography.hazmat.primitives.ciphers.modes.GCM
#   Can add Associated Plaintext (authenticated but not encrypted) in message:
#       In ureka protocol, we assume all command & data are authenticated & encrypted,
#           so associated_plaintext can be set as None.
######################################################
@measure_resource_func
def gcm_gen_iv() -> bytes:
    # Generate a random 96-bit IV.
    iv = generate_random_byte(12)
    return iv

@measure_resource_func
def gcm_encrypt(
    plaintext: bytes, associated_plaintext: bytes, key: bytes, iv: bytes = None
) -> Tuple[bytes, bytes, bytes]:
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    # print("明文", plaintext.hex())  # 這是明文
    # print("相關明文", associated_plaintext.hex())
    # print("金鑰", key.hex())
    # print("len(金鑰)", len(key))
    # print("IV", iv.hex())
    # print("len(IV)", len(iv))
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()

    # associated_plaintext will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    # encryptor.authenticate_additional_data(associated_plaintext)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    ciphertextTest = ciphertext + encryptor.tag
    # print("密文", ciphertext.hex())
    return (ciphertext, encryptor.tag)


######################################################
# ECDH AES Decryption (GCM Mode)
######################################################
@measure_resource_func
def gcm_decrypt(
    ciphertext: bytes, associated_data: bytes, tag: bytes, key: bytes, iv: bytes
) -> bytes:
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    # print("明文", ciphertext.hex())  # 這是明文
    # print("tag", tag.hex()) 
    # print("相關明文", associated_data.hex())
    # print("金鑰", key.hex())
    # print("len(金鑰)", len(key))
    # print("IV", iv.hex())
    # print("len(IV)", len(iv))
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()
    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()
