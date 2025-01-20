# Data Model (Message)
from typing import Optional
from pydantic import BaseModel, ConfigDict, ValidationError

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

######################################################
# Protocol Version
######################################################
PROTOCOL_VERSION: str = "UREKA-1.0"

######################################################
# Message Type
######################################################
MESSAGE_TYPE: str = "UTICKET"

######################################################
# UTicket Type
######################################################
# UTicket
TYPE_INITIALIZATION_UTICKET: str = "INITIALIZATION"
TYPE_OWNERSHIP_UTICKET: str = "OWNERSHIP"
TYPE_SELFACCESS_UTICKET: str = "SELFACCESS"
TYPE_ACCESS_UTICKET: str = "ACCESS"
# TYPE_QUERY_UTICKET: str = "QUERY"
# UToken
TYPE_CMD_UTOKEN: str = "CMD_UTOKEN"
# RToken (ACCESS_END)
TYPE_ACCESS_END_UTOKEN: str = "ACCESS_END"
# UTicket
LEGAL_UTICKET_TYPES: {str} = {
    TYPE_INITIALIZATION_UTICKET,
    TYPE_OWNERSHIP_UTICKET,
    TYPE_SELFACCESS_UTICKET,
    TYPE_ACCESS_UTICKET,
    TYPE_CMD_UTOKEN,
    TYPE_ACCESS_END_UTOKEN,
}


######################################################
# Data Model
######################################################
class UTicket(BaseModel):
    # UT
    protocol_version: Optional[str] = PROTOCOL_VERSION

    u_ticket_id: Optional[str] = None
    u_ticket_type: Optional[str] = None

    device_id: Optional[str] = None

    ticket_order: Optional[int] = None

    holder_id: Optional[str] = None
    task_scope: Optional[str] = None

    issuer_signature: Optional[str] = None

    # PS-Cmd
    associated_plaintext_cmd: Optional[str] = None
    ciphertext_cmd: Optional[str] = None
    gcm_authentication_tag_cmd: Optional[str] = None

    # PS-Data
    iv_data: Optional[str] = None

    def __eq__(self, other):
        if type(other) == UTicket:
            return self.u_ticket_id == other.u_ticket_id
        return False

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                                < UTicket_obj >                               #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
@measure_worker_func
def u_ticket_to_jsonstr(u_ticket_obj: UTicket) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    u_ticket_json = u_ticket_obj.model_dump_json(indent=None, exclude_none=True)
    return u_ticket_json


def jsonstr_to_u_ticket(json_str: str) -> UTicket:
    try:
        return UTicket.model_validate_json(json_str, strict=False)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID UTICKET SCHEMA"
        # simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
