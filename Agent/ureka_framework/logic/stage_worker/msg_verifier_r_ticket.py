# Data Model (RAM)
from typing import Optional
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.other_device import OtherDevice
from ureka_framework.model.data_model.current_session import CurrentSession

# Data Model (Message)
import copy
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import UTicket
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.message_model.r_ticket import (
    RTicket,
    jsonstr_to_r_ticket,
    r_ticket_to_jsonstr,
)
from cryptography.hazmat.backends import default_backend
from ureka_framework.resource.crypto.serialization_util import (
    str_to_key,
    base64str_backto_byte,
    byte_to_base64str,
    str_to_byte,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
# Resource (Crypto)
from cryptography.hazmat.primitives.asymmetric import ec
import ureka_framework.resource.crypto.ecc as ecc
from ureka_framework.resource.crypto import ecdh


# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func


class RTicketVerifier:
    def __init__(
        self,
        this_device: Optional[ThisDevice],
        device_table: Optional[dict[str, OtherDevice]],
        audit_start_ticket: Optional[UTicket],
        audit_end_ticket: Optional[UTicket],
        current_session: Optional[CurrentSession],
    ) -> None:
        self.this_device = this_device
        self.device_table = device_table
        self.audit_start_ticket = audit_start_ticket
        self.audit_end_ticket = audit_end_ticket
        self.current_session = current_session

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_json_schema(self, arbitrary_json: str) -> RTicket:
        success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"

        try:
            r_ticket_in: RTicket = jsonstr_to_r_ticket(arbitrary_json)
            simple_log("info", success_msg)
            return r_ticket_in
        except RuntimeError as error:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", f"{failure_msg}: {error}")
            raise RuntimeError(f"{failure_msg}: {error}")

    def verify_protocol_version(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = (
            f"-> SUCCESS: VERIFY_PROTOCOL_VERSION = {r_ticket_in.protocol_version}"
        )
        failure_msg = (
            f"-> FAILURE: VERIFY_PROTOCOL_VERSION = {r_ticket_in.protocol_version}"
        )

        if r_ticket_in.protocol_version == u_ticket.PROTOCOL_VERSION:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_r_ticket_id(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_RTICKET_ID"
        failure_msg = f"-> FAILURE: VERIFY_RTICKET_ID"

        # Verify UTicket Id (Hash-based)
        ticket_without_id_and_sig = copy.deepcopy(r_ticket_in)
        ticket_without_id_and_sig.r_ticket_id = None
        ticket_without_id_and_sig.device_signature = None
        generated_hash = ecdh.generate_sha256_hash_str(
            r_ticket_to_jsonstr(ticket_without_id_and_sig)
        )
        if generated_hash == r_ticket_in.r_ticket_id:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_r_ticket_type(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"

        if r_ticket_in.r_ticket_type in r_ticket.LEGAL_RTICKET_TYPES:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    # Because holder do not really know whether this device_id is correct before get RT
    def has_device_id(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: HAS_DEVICE_ID = {r_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: HAS_DEVICE_ID = {r_ticket_in.device_id}"

        if r_ticket_in.device_id != None:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    # However, device can verify whether this device_id is correct
    def verify_device_id(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"

        if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            # # Note that for TYPE_INITIALIZATION:
            # u_ticket_device_id = "no_id"
            # r_ticket_device_id = "newly-created device public key string"

            # NO Device ID
            simple_log("info", success_msg)
            return r_ticket_in
        elif (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # print("哭哭", self.audit_start_ticket.device_id, r_ticket_in.device_id)
            if r_ticket_in.device_id == self.audit_start_ticket.device_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type in r_ticket.LEGAL_CRKE_TYPES:
            if r_ticket_in.device_id == self.current_session.current_device_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_result(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_RESULT"
        failure_msg = f"-> FAILURE: VERIFY_RESULT"

        if "SUCCESS" in r_ticket_in.result:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_ticket_order(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_TICKET_ORDER"
        failure_msg = f"-> FAILURE: VERIFY_TICKET_ORDER"

        # If TX is finished, the ticket_order++
        # "holder"
        if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            if r_ticket_in.ticket_order == 1:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            if (
                r_ticket_in.ticket_order
                == self.device_table[r_ticket_in.device_id].ticket_order + 1
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        # If TX is not finished, the ticket_order should be the same
        # "holder"
        elif (
            r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
        ):
            if (
                r_ticket_in.ticket_order
                == self.device_table[r_ticket_in.device_id].ticket_order
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        # "device"
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if r_ticket_in.ticket_order == self.this_device.ticket_order:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_audit_start(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_START"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_START"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # print(r_ticket_in.audit_start, self.audit_start_ticket.u_ticket_id)
            if r_ticket_in.audit_start == self.audit_start_ticket.u_ticket_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type in r_ticket.LEGAL_CRKE_TYPES:
            if r_ticket_in.audit_start == self.current_session.current_u_ticket_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_audit_end(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_END"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_END"

        # Auditted by:
        #   Per-Use
        #   TXend UToken
        #   TODO: Revocation UTicket
        if r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
            if r_ticket_in.audit_end == "ACCESS_END":
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:
            simple_log("info", success_msg)
            return r_ticket_in

    def verify_cr_ke(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_CR_KE"
        failure_msg = f"-> FAILURE: VERIFY_CR_KE"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # NO CR-KE
            simple_log("info", success_msg)
            return r_ticket_in
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
            if (
                r_ticket_in.challenge_1 != None
                and r_ticket_in.key_exchange_salt_1 != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if (
                r_ticket_in.challenge_1 != None
                and r_ticket_in.challenge_2 != None
                and r_ticket_in.key_exchange_salt_2 != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
            if r_ticket_in.challenge_2 != None:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_ps(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_PS"
        failure_msg = f"-> FAILURE: VERIFY_PS"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # NO PS
            simple_log("info", success_msg)
            return r_ticket_in
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
            if r_ticket_in.iv_cmd != None:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if (
                r_ticket_in.associated_plaintext_cmd != None
                and r_ticket_in.ciphertext_cmd != None
                and r_ticket_in.iv_data != None
                and r_ticket_in.gcm_authentication_tag_cmd != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
            if (
                r_ticket_in.associated_plaintext_data != None
                and r_ticket_in.ciphertext_data != None
                and r_ticket_in.iv_cmd != None
                and r_ticket_in.gcm_authentication_tag_data != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
            if (
                r_ticket_in.associated_plaintext_data != None
                and r_ticket_in.ciphertext_data != None
                and r_ticket_in.iv_cmd != None
                and r_ticket_in.gcm_authentication_tag_data != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_device_signature(
        self,
        r_ticket_in: RTicket,
    ) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"
        # return r_ticket_in
        # Verify DEVICE_SIGNATURE through device_id
        # return r_ticket_in
        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            if self._verify_device_signature_on_r_ticket(
                r_ticket_in,
                str_to_key(r_ticket_in.device_id, "ecc-public-key"),
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", f"{failure_msg}")
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if self._verify_device_signature_on_r_ticket(
                r_ticket_in,
                str_to_key(self.current_session.current_holder_id, "ecc-public-key"),
            ):
                success_msg = f"-> SUCCESS: VERIFY_HOLDER_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"
                simple_log("info", success_msg)
                return r_ticket_in
            else:
                failure_msg = f"-> FAILURE: VERIFY_HOLDER_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"
                simple_log("error", f"{failure_msg}")
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
            # No DEVICE_SIGNATURE
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    ######################################################
    # Verify ECC Signature on RTicket
    ######################################################
    def _verify_device_signature_on_r_ticket(
        self, signed_r_ticket: RTicket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        # # # get public_key x y
        # public_numbers = public_key.public_numbers()
        # x = public_numbers.x
        # y = public_numbers.y
        # # to base64
        # x_base64str = byte_to_base64str(x.to_bytes(32, "big"))
        # y_base64str = byte_to_base64str(y.to_bytes(32, "big"))
        # print("想",x_base64str, y_base64str)

        # x_byte = base64str_backto_byte(x_base64str)
        # y_byte = base64str_backto_byte(y_base64str)
        # # reverse to the public key with curve SPEC256K1
        # x = int.from_bytes(x_byte, "little")
        # y = int.from_bytes(y_byte, "little")

        # public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
        # public_key =  public_numbers.public_key(default_backend())

        # Get Signature on RTicket
        r_base64str, s_base64str = signed_r_ticket.device_signature.split("-")

        # 將 r 和 s 的 Base64 字串轉回位元組
        r_byte = base64str_backto_byte(r_base64str)
        s_byte = base64str_backto_byte(s_base64str)

        # 將位元組轉回整數
        r = int.from_bytes(r_byte, byteorder="big")
        s = int.from_bytes(s_byte, byteorder="big")

        # 使用 cryptography 的 encode_dss_signature 將 r 和 s 轉回 signature_byte
        signature_byte = encode_dss_signature(r, s)

        # Verify Signature on Signed RTicket, but Prevent side effect on Signed RTicket
        unsigned_r_ticket = copy.deepcopy(signed_r_ticket)
        unsigned_r_ticket.device_signature = None
        unsigned_r_ticket.r_ticket_id = None

        unsigned_r_ticket_str = r_ticket_to_jsonstr(unsigned_r_ticket)
        unsigned_r_ticket_byte = str_to_byte(unsigned_r_ticket_str)

        # Verify Signature
        return ecc.verify_signature(signature_byte, unsigned_r_ticket_byte, public_key)
