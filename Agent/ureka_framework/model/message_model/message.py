# Data Model (Message)
from typing import Optional
from pydantic import BaseModel, ConfigDict, ValidationError
import json


######################################################
# Message Operation
######################################################
MESSAGE_RECV_AND_STORE: str = "MESSAGE_RECV_AND_STORE"
MESSAGE_VERIFY_AND_EXECUTE: str = "MESSAGE_VERIFY_AND_EXECUTE"


######################################################
# Data Model
######################################################
class Message(BaseModel):
    # Message
    message_operation: Optional[str] = None
    message_type: Optional[str] = None
    message_str: Optional[str] = None

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                                < Message_obj >                               #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def message_to_jsonstr(message_obj: Message) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    message_json = message_obj.model_dump_json(indent=None, exclude_none=True)
    return message_json


def jsonstr_to_message(json_str: str) -> Message:
    try:
        return Message.model_validate_json(json_str, strict=False)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID MESSAGE SCHEMA"
        # simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
