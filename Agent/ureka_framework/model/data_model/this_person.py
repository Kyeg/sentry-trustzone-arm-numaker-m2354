# Data Model (RAM)
from dataclasses import dataclass
import json
from typing import Optional, Dict

# Resource (Crypto): Notice that cryptography types are not supported by pydantic, so we simply use dataclass instead
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto.serialization_util import (
    key_to_str,
    str_to_key,
    byte_to_base64str
)


######################################################
# Data Model (User Agent or Cloud Server only)
######################################################
@dataclass
class ThisPerson:
    # Generate Person Key after Intialization (UA or CS only)
    person_priv_key: Optional[ec.EllipticCurvePrivateKey] = None
    person_pub_key: Optional[ec.EllipticCurvePublicKey] = None

    @property
    def person_priv_key_str(self) -> Optional[str]:
        if self.person_priv_key is None:
            return None
        return key_to_str(self.person_priv_key, key_type="ecc-private-key")

    @property
    def person_pub_key_str(self) -> Optional[str]:
        if self.person_pub_key is None:
            return None
        public_numbers = self.person_pub_key.public_numbers()
        x = public_numbers.x
        y = public_numbers.y

        # x_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder='little')
        # y_bytes = y.to_bytes((y.bit_length() + 7) // 8, byteorder='little')
        x_bytes = x.to_bytes(32, byteorder='big')
        y_bytes = y.to_bytes(32, byteorder='big')

        # 將 x 和 y 坐標位元組編碼為 Base64
        x_base64 = byte_to_base64str(x_bytes)
        y_base64 = byte_to_base64str(y_bytes)
        print (x_base64)
        print (y_base64)
        #return key_to_str(self.person_pub_key, key_type="ecc-public-key")
        return x_base64 + '-' + y_base64


################################################################################
#                                < Person_obj >                                #
#                                       | self-defined serilaization           #
#                                       | (including ECC_Key_obj, bytes, etc.) #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def _this_person_to_dict(this_person_obj: ThisPerson) -> Dict[str, str]:
    # Prevent side effect on this_person_obj
    # However, cannot deepcopy key object, so we need to handle it separately
    this_person_dict = {}

    # Not JSON Serializable
    if this_person_obj.person_priv_key == None:
        this_person_dict["person_priv_key"] = None
    else:
        this_person_dict["person_priv_key"] = key_to_str(
            this_person_obj.person_priv_key, "ecc-private-key"
        )
    if this_person_obj.person_pub_key == None:
        this_person_dict["person_pub_key"] = None
    else:
        this_person_dict["person_pub_key"] = key_to_str(
            this_person_obj.person_pub_key, "ecc-public-key"
        )

    return this_person_dict


def _dict_to_this_person(this_person_dict: Dict[str, Optional[str]]) -> ThisPerson:
    this_person_obj = ThisPerson()

    # Not JSON Serializable
    if this_person_dict["person_priv_key"] != None:
        this_person_obj.person_priv_key = str_to_key(
            this_person_dict["person_priv_key"], "ecc-private-key"
        )
    if this_person_dict["person_pub_key"] != None:
        this_person_obj.person_pub_key = str_to_key(
            this_person_dict["person_pub_key"], "ecc-public-key"
        )

    return this_person_obj


def this_person_to_jsonstr(this_person_obj: ThisPerson) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    return json.dumps(
        this_person_obj, indent=4, default=_this_person_to_dict, sort_keys=True
    )


def jsonstr_to_this_person(json_str: str) -> ThisPerson:
    try:
        return json.loads(json_str, object_hook=_dict_to_this_person, strict=False) 
    except json.JSONDecodeError:
        failure_msg = "NOT VALID JSON or VALID SCHEMA"
        # simple_log("error",failure_msg)
        raise RuntimeError(failure_msg)
