# Data Model (RAM)
import copy
from pydantic import ValidationError
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.this_person import ThisPerson
from ureka_framework.model.data_model.other_device import OtherDevice
from ureka_framework.model.message_model.r_ticket import RTicket, r_ticket_to_jsonstr
import ureka_framework.model.message_model.r_ticket as r_ticket
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import (
    str_to_byte,
    byte_to_base64str,
)

# Resource (Crypto)
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto import ecdh

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
class RTicketGenerator:
    def __init__(
        self,
        this_device: ThisDevice,
        this_person: ThisPerson,
        device_table: dict[str, OtherDevice],
    ) -> None:
        self.this_device = this_device
        self.this_person = this_person
        self.device_table = device_table

    ######################################################
    # Message Generation Flow
    ######################################################
    def generate_arbitrary_r_ticket(self, arbitrary_dict: dict) -> RTicket:
        success_msg = "-> SUCCESS: GENERATE_RTICKET"
        failure_msg = "-> FAILURE: GENERATE_RTICKET"

        ######################################################
        # Unsigned RTicket
        ######################################################
        try:
            new_r_ticket = RTicket(**arbitrary_dict)
        except ValidationError as error:  # pragma: no cover -> Weird Ticket-Request
            simple_log("error", f"{failure_msg}: {error}")
            raise RuntimeError(failure_msg)

        # "device"
        if (
            new_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or new_r_ticket.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or new_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
            or new_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
            or new_r_ticket.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
            or new_r_ticket.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            new_r_ticket.ticket_order = self.this_device.ticket_order
        # "holder"
        elif new_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            new_r_ticket.ticket_order = self.device_table[
                new_r_ticket.device_id
            ].ticket_order
        else:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        # Generate UTicket Id (Hash-based)
        new_r_ticket.r_ticket_id = ecdh.generate_sha256_hash_str(
            r_ticket_to_jsonstr(new_r_ticket)
        )

        ######################################################
        # Signed RTicket
        ######################################################
        # Generate Signature
        # "device"
        if (
            new_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or new_r_ticket.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or new_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
            or new_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
            or new_r_ticket.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            new_r_ticket = self._add_device_signature_on_r_ticket(
                new_r_ticket, self.this_device.device_priv_key
            )
            simple_log("info", success_msg)
        # "holder"
        elif new_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            new_r_ticket = self._add_device_signature_on_r_ticket(
                new_r_ticket, self.this_person.person_priv_key
            )
            simple_log("info", success_msg)
        # "device"
        elif new_r_ticket.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
            # NO Signature
            simple_log("info", success_msg)
        else:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        return new_r_ticket

    ######################################################
    # Add ECC Signature on RTicket
    ######################################################
    def _add_device_signature_on_r_ticket(
        self, unsigned_r_ticket: RTicket, private_key: ec.EllipticCurvePrivateKey
    ) -> RTicket:
        # Message
        unsigned_r_ticket_str = r_ticket_to_jsonstr(unsigned_r_ticket)
        unsigned_r_ticket_byte = str_to_byte(unsigned_r_ticket_str)

        # print("啥子意思", unsigned_r_ticket_byte)
        # sha256 unsigned_u_ticket_byte
        # hash_byte to hex
        signature_byte = ecc.sign_signature(unsigned_r_ticket_byte, private_key)
        r, s = decode_dss_signature(signature_byte)
        # print("為甚麼", hex(r))  
        # print("為甚麼", hex(s))
        # print("為甚麼 工要使", self.this_person.person_pub_key_str)
        # print("為甚麼 斯要使", self.this_person.person_priv_key_str)
        
        # r, s from hex to byte
        r_byte = r.to_bytes(32, byteorder="big")
        s_byte = s.to_bytes(32, byteorder="big")
        r_base64str = byte_to_base64str(r_byte)
        s_base64str = byte_to_base64str(s_byte)
        # Add Signature on New Signed UTicket, but Prevent side effect on Unsigned UTicket
        signed_r_ticket = copy.deepcopy(unsigned_r_ticket)
        signed_r_ticket.device_signature = r_base64str + "-" + s_base64str
        # print("為甚麼 簽名", signed_r_ticket.device_signature)

        return signed_r_ticket
