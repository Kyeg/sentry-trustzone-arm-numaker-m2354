# Data Model (RAM)
from pydantic import BaseModel, ConfigDict, ValidationError
import ureka_framework.model.message_model.u_ticket as u_ticket
from typing import Optional

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

######################################################
# Message Type
######################################################
MESSAGE_TYPE: str = "RTICKET"

######################################################
# RTicket Type (same as UTicket Type)
# RTicket Type (CRKE)
# RTicket Type (PS)
######################################################
# UTicket
# TYPE_INITIALIZATION_UTICKET: str = "INITIALIZATION"
# TYPE_OWNERSHIP_UTICKET: str = "OWNERSHIP"
# CRKE
TYPE_CRKE1_RTICKET: str = "CR-KE-1"
TYPE_CRKE2_RTICKET: str = "CR-KE-2"
TYPE_CRKE3_RTICKET: str = "CR-KE-3"
# CRKE
LEGAL_CRKE_TYPES: {str} = {TYPE_CRKE1_RTICKET, TYPE_CRKE2_RTICKET, TYPE_CRKE3_RTICKET}
# RToken
TYPE_DATA_RTOKEN: str = "DATA_RTOKEN"
# RToken (ACCESS_END)
# TYPE_ACCESS_END_UTOKEN: str = "ACCESS_END"
# All
LEGAL_RTICKET_TYPES: {str} = {
    u_ticket.TYPE_INITIALIZATION_UTICKET,
    u_ticket.TYPE_OWNERSHIP_UTICKET,
    TYPE_CRKE1_RTICKET,
    TYPE_CRKE2_RTICKET,
    TYPE_CRKE3_RTICKET,
    TYPE_DATA_RTOKEN,
    u_ticket.TYPE_ACCESS_END_UTOKEN,
}


######################################################
# Data Model
######################################################
class RTicket(BaseModel):
    # RT
    protocol_version: Optional[str] = u_ticket.PROTOCOL_VERSION

    r_ticket_id: Optional[str] = None
    r_ticket_type: Optional[str] = None

    device_id: Optional[str] = None

    result: Optional[str] = None
    ticket_order: Optional[int] = None

    audit_start: Optional[str] = None
    audit_end: Optional[str] = None

    # CR-KE
    challenge_1: Optional[str] = None
    challenge_2: Optional[str] = None
    key_exchange_salt_1: Optional[str] = None
    key_exchange_salt_2: Optional[str] = None

    # PS-Cmd
    associated_plaintext_cmd: Optional[str] = None
    ciphertext_cmd: Optional[str] = None
    iv_cmd: Optional[str] = None
    gcm_authentication_tag_cmd: Optional[str] = None

    # PS-Data
    associated_plaintext_data: Optional[str] = None
    ciphertext_data: Optional[str] = None
    iv_data: Optional[str] = None
    gcm_authentication_tag_data: Optional[str] = None

    # RT
    device_signature: Optional[str] = None

    def __eq__(self, other):
        if type(other) == RTicket:
            return self.r_ticket_id == other.r_ticket_id
        return False

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                                < RTicket_obj >                               #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
@measure_worker_func
def r_ticket_to_jsonstr(r_ticket_obj: RTicket) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    r_ticket_json = r_ticket_obj.model_dump_json(indent=None, exclude_none=True)
    return r_ticket_json


def jsonstr_to_r_ticket(json_str: str) -> RTicket:
    try:
        # print(json_str)
        return RTicket.model_validate_json(json_str,strict=False)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID RTICKET SCHEMA"
        # simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
