# Data Model (RAM)
from typing import Tuple

# ECC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# ECDSA
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_resource_func


######################################################
# ECC Key Factory
######################################################
@measure_resource_func
def generate_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return (private_key, public_key)


######################################################
# Sign ECC Signature
######################################################
@measure_resource_func
def sign_signature(message_in: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.sign(message_in, ec.ECDSA(hashes.SHA256()))


######################################################
# Verify ECC Signature
######################################################
@measure_resource_func
def verify_signature(
    signatureIn: bytes, message_in: bytes, public_key: ec.EllipticCurvePublicKey
) -> bool:
    try:
        public_key.verify(signatureIn, message_in, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        # failure_msg = "FAILURE: INVALID SIGNATURE"
        # simple_log("error",failure_msg)
        return False
