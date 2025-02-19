# Data Model (RAM)
from typing import Optional
from pydantic import BaseModel, ConfigDict, ValidationError

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log


######################################################
# Data Model
######################################################
class CurrentSession(BaseModel):
    # Access UT
    current_u_ticket_id: Optional[str] = None
    current_device_id: Optional[str] = None
    current_holder_id: Optional[str] = None
    current_task_scope: Optional[str] = None

    # CR-KE
    challenge_1: Optional[str] = None
    challenge_2: Optional[str] = None
    key_exchange_salt_1: Optional[str] = None
    key_exchange_salt_2: Optional[str] = None

    # PS
    current_session_key_str: Optional[str] = None

    plaintext_cmd: Optional[str] = None
    associated_plaintext_cmd: Optional[str] = None
    iv_cmd: Optional[str] = None
    ciphertext_cmd: Optional[str] = None
    gcm_authentication_tag_cmd: Optional[str] = None

    plaintext_data: Optional[str] = None
    associated_plaintext_data: Optional[str] = None
    iv_data: Optional[str] = None
    ciphertext_data: Optional[str] = None
    gcm_authentication_tag_data: Optional[str] = None

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                             < CurrentSession_obj >                           #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def current_session_to_jsonstr(current_session_obj: CurrentSession) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    current_session_json = current_session_obj.model_dump_json(
        indent=4, exclude_none=True
    )
    return current_session_json


def jsonstr_to_current_session(json_str: str) -> CurrentSession:
    try:
        return CurrentSession.model_validate_json(json_str, strict=False)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID SCHEMA"
        # simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
