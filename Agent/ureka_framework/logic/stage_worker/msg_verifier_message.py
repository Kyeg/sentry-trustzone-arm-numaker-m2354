# Data Model (RAM)
from typing import Optional
from ureka_framework.model.data_model.this_device import ThisDevice

# Data Model (Message)
import ureka_framework.model.message_model.message as message
from ureka_framework.model.message_model.message import Message, jsonstr_to_message
import ureka_framework.model.message_model.u_ticket as u_ticket
import ureka_framework.model.message_model.r_ticket as r_ticket

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func


class MessageVerifier:
    def __init__(self, this_device: Optional[ThisDevice]) -> None:
        self.this_device = this_device

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_json_schema(self, arbitrary_json: str) -> Message:
        success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"

        try:
            message_in: Message = jsonstr_to_message(arbitrary_json)
            simple_log("info", success_msg)
            return message_in
        except RuntimeError as error:  # pragma: no cover -> Weird Message
            simple_log("error", f"{failure_msg}: {error}")
            raise RuntimeError(f"{failure_msg}: {error}")

    def verify_message_operation(self, message_in: Message) -> Message:
        success_msg = f"-> SUCCESS: VERIFY_MESSAGE_OPERATION"
        failure_msg = f"-> FAILURE: VERIFY_MESSAGE_OPERATION"

        if (
            message_in.message_operation == message.MESSAGE_RECV_AND_STORE
            or message_in.message_operation == message.MESSAGE_VERIFY_AND_EXECUTE
        ):
            simple_log("info", success_msg)
            return message_in
        else:  # pragma: no cover -> Weird Message
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_message_type(self, message_in: Message) -> Message:
        success_msg = f"-> SUCCESS: VERIFY_MESSAGE_TYPE"
        failure_msg = f"-> FAILURE: VERIFY_MESSAGE_TYPE"

        if (
            message_in.message_type == u_ticket.MESSAGE_TYPE
            or message_in.message_type == r_ticket.MESSAGE_TYPE
        ):
            simple_log("info", success_msg)
            return message_in
        else:  # pragma: no cover -> Weird Message
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_message_str(self, message_in: Message) -> Message:
        success_msg = f"-> SUCCESS: VERIFY_MESSAGE_STR"
        failure_msg = f"-> FAILURE: VERIFY_MESSAGE_STR"

        if message_in.message_str != None:
            simple_log("info", success_msg)
            return message_in
        else:  # pragma: no cover -> Weird Message
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")
