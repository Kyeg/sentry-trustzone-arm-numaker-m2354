# Data Model (RAM)
from typing import Dict, Union
import json
import binascii
import base64

# ECC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
    PrivateFormat,
    PublicFormat,
    Encoding,
    NoEncryption,
)

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_resource_func


################################################################################
#           "Encode always success -o->, while Decode does not -x->"           #
################################################################################
################################################################################
#                  < Arbitrary_String (Printable Characters) >                 #
#                                       |                                      #
#                                       v                                      #
#                                   < Byte >                                   #
################################################################################
@measure_resource_func
def str_to_byte(string: str) -> bytes:
    return string.encode("UTF-8")


@measure_resource_func
def byte_backto_str(byte: bytes) -> str:
    try:
        return byte.decode("UTF-8")
    except UnicodeDecodeError:
        failure_msg = "NOT Any Byte can be decoded to UTF-8"
        # simple_log("error",failure_msg)
        raise RuntimeError(failure_msg)


################################################################################
#                                  < String >                                  #
#                                       ^                                      #
#                                       |                                      #
#                    < Arbitrary_Byte (Signature / Salt) >                     #
################################################################################
@measure_resource_func
def byte_to_base64str(byte: bytes) -> str:
    base64_byte = base64.standard_b64encode(byte)
    return base64_byte.decode("UTF-8")


@measure_resource_func
def base64str_backto_byte(string: str) -> bytes:
    try:
        base64_byte = string.encode("UTF-8")
        return base64.standard_b64decode(base64_byte)
    except binascii.Error:
        failure_msg = "NOT Any String is Base64 string which can be decoded to Byte"
        # simple_log("error",failure_msg)
        raise RuntimeError(failure_msg)


################################################################################
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
@measure_resource_func
def dict_to_jsonstr(dict_obj: Dict[str, str]) -> str:
    return json.dumps(dict_obj, sort_keys=True)


@measure_resource_func
def jsonstr_to_dict(json_str: str) -> Dict[str, str]:
    try:
        return json.loads(json_str, strict=False) 
    except json.JSONDecodeError:
        failure_msg = "NOT VALID JSON"
        # simple_log("error",failure_msg)
        raise RuntimeError(failure_msg)


################################################################################
#                                < ECC_Key_obj >                               #
#                                       | Python cryptography defined          #
#                                       v                                      #
#                                 < DER_byte >                                 #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
@measure_resource_func
def _key_to_byte(
    key_obj: Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey],
    key_type: str,
) -> bytes:
    if key_type == "ecc-public-key":
        return key_obj.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    elif key_type == "ecc-private-key":
        return key_obj.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    else:
        failure_msg = "Only support key_type = [ecc-public-key] or [ecc-private-key]"
        # simple_log("error",failure_msg)
        raise RuntimeError(failure_msg)


@measure_resource_func
def _byte_to_key(
    key_byte: bytes, key_type: str
) -> Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]:
    if key_type == "ecc-public-key":
        return load_der_public_key(key_byte, backend=default_backend())
    elif key_type == "ecc-private-key":
        return load_der_private_key(key_byte, password=None, backend=default_backend())
    else:
        failure_msg = "Only support key_type = [ecc-public-key] or [ecc-private-key]"
        # simple_log("error",failure_msg)
        raise RuntimeError(failure_msg)


@measure_resource_func
def key_to_str(
    key_obj: Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey],
    key_type: str = "ecc-public-key",
) -> bytes:
    # derive x, y from the public key with curve SPEC256K1, it was encoded by X.509
    if key_type == "ecc-public-key":
        public_numbers = key_obj.public_numbers()

        # Extract x and y coordinates
        x = public_numbers.x
        y = public_numbers.y
        # Encode x and y coordinates
        x_byte = base64.standard_b64encode(x.to_bytes(32, "big")).decode("UTF-8")
        y_byte = base64.standard_b64encode(y.to_bytes(32, "big")).decode("UTF-8")
        return x_byte + "-" + y_byte
    else:
        key_byte = _key_to_byte(key_obj, key_type=key_type)
        return byte_to_base64str(key_byte)


@measure_resource_func
def str_to_key(
    key_str: str, key_type: str = "ecc-public-key"
) -> ec.EllipticCurvePublicKey:
    x = key_str.split("-")
    if len(x) == 1:
        key_byte = base64str_backto_byte(key_str)
        return _byte_to_key(key_byte, key_type=key_type)
    if key_type == "ecc-public-key":
        # print(key_str)
        x = key_str.split("-")
        x_byte = base64str_backto_byte(x[0])
        y_byte = base64str_backto_byte(x[1])
        # reverse to the public key with curve SPEC256K1
        x = int.from_bytes(x_byte, "big")
        y = int.from_bytes(y_byte, "big")
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve=ec.SECP256K1())
        return public_numbers.public_key()
        
