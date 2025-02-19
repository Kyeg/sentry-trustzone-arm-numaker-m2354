# Data Model (RAM)
from typing import Optional
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.message_model.u_ticket import (
    UTicket,
    jsonstr_to_u_ticket,
    u_ticket_to_jsonstr,
)
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import (
    base64str_backto_byte,
    str_to_byte,
    dict_to_jsonstr,
)

# Resource (Crypto)
from cryptography.hazmat.primitives.asymmetric import ec
import ureka_framework.resource.crypto.ecc as ecc
from ureka_framework.resource.crypto import ecdh
import copy

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func


class UTicketVerifier:
    def __init__(self, this_device: Optional[ThisDevice]) -> None:
        self.this_device = this_device

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_json_schema(self, arbitrary_json: str) -> UTicket:
        success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"

        try:
            u_ticket_in: UTicket = jsonstr_to_u_ticket(arbitrary_json)
            simple_log("info", success_msg)
            return u_ticket_in
        except RuntimeError as error:  # pragma: no cover -> Weird U-Ticket
            # simple_log("error", f"{failure_msg}: {error}")
            raise RuntimeError(f"{failure_msg}: {error}")

    def verify_protocol_version(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = (
            f"-> SUCCESS: VERIFY_PROTOCOL_VERSION = {u_ticket_in.protocol_version}"
        )
        failure_msg = (
            f"-> FAILURE: VERIFY_PROTOCOL_VERSION = {u_ticket_in.protocol_version}"
        )

        if u_ticket_in.protocol_version == u_ticket.PROTOCOL_VERSION:
            simple_log("info", success_msg)
            return u_ticket_in
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_u_ticket_id(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_UTICKET_ID"
        failure_msg = f"-> FAILURE: VERIFY_UTICKET_ID"

        # Verify UTicket Id (Hash-based)
        ticket_without_id_and_sig = copy.deepcopy(u_ticket_in)
        ticket_without_id_and_sig.u_ticket_id = None
        ticket_without_id_and_sig.issuer_signature = None
        generated_hash = ecdh.generate_sha256_hash_str(
            u_ticket_to_jsonstr(ticket_without_id_and_sig)
        )
        if generated_hash == u_ticket_in.u_ticket_id:
            simple_log("info", success_msg)
            return u_ticket_in
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_u_ticket_type(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_UTICKET_TYPE = {u_ticket_in.u_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_UTICKET_TYPE = {u_ticket_in.u_ticket_type}"

        if u_ticket_in.u_ticket_type in u_ticket.LEGAL_UTICKET_TYPES:
            simple_log("info", success_msg)
            return u_ticket_in
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    # Because holder do not really know whether this device_id is correct before get RT
    def has_device_id(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: HAS_DEVICE_ID = {u_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: HAS_DEVICE_ID = {u_ticket_in.device_id}"

        if u_ticket_in.device_id != None:
            simple_log("info", success_msg)
            return u_ticket_in
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    # However, device can verify whether this device_id is correct
    def verify_device_id(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {u_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {u_ticket_in.device_id}"

        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            if u_ticket_in.device_id == "no_id":
                simple_log("info", success_msg)
                return u_ticket_in
            else:  # pragma: no cover -> Weird U-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            if u_ticket_in.device_id == self.this_device.device_pub_key_str:
                simple_log("info", success_msg)
                return u_ticket_in
            else:  # pragma: no cover -> Weird U-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_ticket_order(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_TICKET_ORDER"
        failure_msg = f"-> FAILURE: VERIFY_TICKET_ORDER"

        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            if self.this_device.ticket_order == 0:
                if u_ticket_in.ticket_order == 0:
                    simple_log("info", success_msg)
                    return u_ticket_in
                else:  # pragma: no cover -> Weird U-Ticket
                    simple_log("error", failure_msg)
                    raise RuntimeError(f"{failure_msg}")
            elif self.this_device.ticket_order > 0:
                failure_msg = (
                    "-> FAILURE: VERIFY_TICKET_ORDER: IOT_DEVICE ALREADY INITIALIZED"
                )
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
            else:  # pragma: no cover -> Weird U-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:
            if u_ticket_in.ticket_order == self.this_device.ticket_order:
                simple_log("info", success_msg)
                return u_ticket_in
            else:
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")

    def verify_holder_id(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_HOLDER_ID"
        failure_msg = f"-> FAILURE: VERIFY_HOLDER_ID"

        if (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
        ):
            # With HOLDER_ID
            if u_ticket_in.holder_id != None:
                simple_log("info", success_msg)
                return u_ticket_in
            else:  # pragma: no cover -> Weird U-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET:
            # HOLDER_ID must be Device Owner
            if u_ticket_in.holder_id == self.this_device.owner_pub_key_str:
                simple_log("info", success_msg)
                return u_ticket_in
            else:
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # No HOLDER_ID
            simple_log("info", success_msg)
            return u_ticket_in
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_task_scope(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_TASK_SCOPE"
        failure_msg = f"-> FAILURE: VERIFY_TASK_SCOPE"

        if (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # No TASK_SCOPE
            simple_log("info", success_msg)
            return u_ticket_in
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
            if u_ticket_in.task_scope != None:
                simple_log("info", success_msg)
                return u_ticket_in
            else:  # pragma: no cover -> Weird U-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET:
            if u_ticket_in.task_scope == dict_to_jsonstr({"ALL": "allow"}):
                simple_log("info", success_msg)
                return u_ticket_in
            else:  # pragma: no cover -> Weird U-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_ps(self, u_ticket_in: UTicket) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_PS"
        failure_msg = f"-> FAILURE: VERIFY_PS"

        if (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
        ):
            # No PS
            simple_log("info", success_msg)
            return u_ticket_in
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            if (
                u_ticket_in.associated_plaintext_cmd != None
                and u_ticket_in.ciphertext_cmd != None
                and u_ticket_in.iv_data != None
                and u_ticket_in.gcm_authentication_tag_cmd != None
            ):
                simple_log("info", success_msg)
                return u_ticket_in
            else:  # pragma: no cover -> Weird U-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_issuer_signature(
        self,
        u_ticket_in: UTicket,
    ) -> UTicket:
        success_msg = f"-> SUCCESS: VERIFY_ISSUER_SIGNATURE on {u_ticket_in.u_ticket_type} UTICKET"
        failure_msg = f"-> FAILURE: VERIFY_ISSUER_SIGNATURE on {u_ticket_in.u_ticket_type} UTICKET"

        # Verify ISSUER_SIGNATURE
        if (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # No ISSUER_SIGNATURE
            simple_log("info", success_msg)
            return u_ticket_in
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
        ):
            if self._verify_issuer_signature_on_u_ticket(
                u_ticket_in, self.this_device.owner_pub_key
            ):
                simple_log("info", success_msg)
                return u_ticket_in
            else:
                simple_log("error", f"{failure_msg}")
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    ######################################################
    # Verify ECC Signature on UTicket
    ######################################################
    def _verify_issuer_signature_on_u_ticket(
        self, signed_u_ticket: UTicket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        # Get Signature on UTicket
        signature_byte = base64str_backto_byte(signed_u_ticket.issuer_signature)

        # Verify Signature on Signed UTicket, but Prevent side effect on Signed UTicket
        unsigned_u_ticket = copy.deepcopy(signed_u_ticket)
        unsigned_u_ticket.issuer_signature = None

        unsigned_u_ticket_str = u_ticket_to_jsonstr(unsigned_u_ticket)
        unsigned_u_ticket_byte = str_to_byte(unsigned_u_ticket_str)

        # Verify Signature
        return ecc.verify_signature(signature_byte, unsigned_u_ticket_byte, public_key)
