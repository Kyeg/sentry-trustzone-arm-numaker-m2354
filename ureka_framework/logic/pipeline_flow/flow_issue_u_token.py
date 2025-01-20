# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Data Model (Message)
import ureka_framework.model.message_model.message as message
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import UTicket
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.message_model.r_ticket import RTicket

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Measure Helper
from ureka_framework.logic.stage_worker.measure_helper import MeasureHelper

# Stage Worker
from ureka_framework.logic.stage_worker.received_msg_storer import ReceivedMsgStorer
from ureka_framework.logic.stage_worker.msg_verifier import MsgVerifier
from ureka_framework.logic.stage_worker.executor import Executor
from ureka_framework.logic.stage_worker.msg_generator import MsgGenerator
from ureka_framework.logic.stage_worker.generated_msg_storer import GeneratedMsgStorer
from ureka_framework.logic.stage_worker.msg_sender import MsgSender

# Pipeline Flow
from ureka_framework.logic.pipeline_flow.flow_apply_u_ticket import FlowApplyUTicket


class FlowIssueUToken:
    def __init__(
        self,
        share_data: SharedData,
        measure_helper: MeasureHelper,
        received_msg_storer: ReceivedMsgStorer,
        msg_verifier: MsgVerifier,
        executor: Executor,
        msg_generator: MsgGenerator,
        generated_msg_storer: GeneratedMsgStorer,
        msg_sender: MsgSender,
        flow_apply_u_ticket: FlowApplyUTicket,
    ) -> None:
        self.shared_data = share_data
        self.measure_helper = measure_helper
        self.received_msg_storer = received_msg_storer
        self.msg_verifier = msg_verifier
        self.executor = executor
        self.msg_generator = msg_generator
        self.generated_msg_storer = generated_msg_storer
        self.msg_sender = msg_sender
        self.flow_apply_u_ticket = flow_apply_u_ticket

    ######################################################
    # [PIPELINE FLOW]
    #
    # APY (PS):
    #       holder_send_cmd()   -> _device_recv_cmd()
    #       _holder_recv_data() <- _device_send_data()
    #                           ...
    #                       ..repeated..
    #                           ...
    #       holder_send_cmd(access_end) -> _device_recv_cmd(access_end)
    #       _holder_recv_r_ticket() <- _device_send_r_ticket()
    ######################################################
    def holder_send_cmd(
        self, device_id: str, cmd: str, access_end: bool = False
    ) -> None:
        ######################################################
        # Start Process Measurement
        ######################################################
        self.measure_helper.measure_process_perf_start()

        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table:
                # [STAGE: (E)]
                self.executor._execute_ps(executing_case="send-utoken", plaintext=cmd)

                if access_end == False:
                    # [STAGE: (C)]
                    self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_DATA)
                    # [STAGE: (G)]
                    u_ticket_type = f"{u_ticket.TYPE_CMD_UTOKEN}"
                else:
                    # [STAGE: (C)]
                    self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_RT)
                    # [STAGE: (G)]
                    u_ticket_type = f"{u_ticket.TYPE_ACCESS_END_UTOKEN}"

                # [STAGE: (G)]
                generated_request: dict = {
                    "device_id": f"{self.shared_data.current_session.current_device_id}",
                    "u_ticket_type": f"{u_ticket_type}",
                    "associated_plaintext_cmd": f"{self.shared_data.current_session.associated_plaintext_cmd}",
                    "ciphertext_cmd": f"{self.shared_data.current_session.ciphertext_cmd}",
                    "gcm_authentication_tag_cmd": f"{self.shared_data.current_session.gcm_authentication_tag_cmd}",
                    "iv_data": f"{self.shared_data.current_session.iv_data}",
                }
                generated_u_ticket_json: str = (
                    self.msg_generator._generate_xxx_u_ticket(generated_request)
                )
                # simple_log("debug", f"Generated UToken: {generated_u_ticket_json}")

                ######################################################
                # End Process Measurement
                ######################################################
                if access_end == False:
                    self.measure_helper.measure_recv_cli_perf_time("holder_send_cmd")
                else:
                    self.measure_helper.measure_recv_cli_perf_time("holder_send_access_end_cmd")

                ########################################################################
                # Start Comm Measurement
                ########################################################################
                if self.shared_data.this_device.device_name != "iot_device":
                    self.measure_helper.measure_comm_perf_start()

                # [STAGE: (S)]
                self.msg_sender._send_xxx_message(
                    message.MESSAGE_VERIFY_AND_EXECUTE,
                    u_ticket.MESSAGE_TYPE,
                    generated_u_ticket_json,
                )

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            error = "FAILURE: (VL)"
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except RuntimeError:  # pragma: no cover -> Weird TK-Request (ValidationError)
            failure_msg = f"FAILURE: (VTKREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

    def _device_recv_cmd(self, received_u_token: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # [STAGE: (VUT)]
            self.msg_verifier.verify_u_ticket_can_execute(received_u_token)

            # [STAGE: (VTK)(VTS)]
            # [STAGE: (E)]
            self.executor._execute_xxx_u_ticket(received_u_token)
            self.shared_data.result_message = f"-> SUCCESS: VERIFY_UT_CAN_EXECUTE"

            if received_u_token.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN:
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)
            elif received_u_token.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_UT)
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")

        except RuntimeError as error:
            self.shared_data.result_message = f"{error}"

            # [STAGE: (C)]
            self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        finally:
            # PS
            if received_u_token.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN:
                # [STAGE: (G)(S)]
                self._device_send_data(self.shared_data.result_message)
            elif received_u_token.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
                # [STAGE: (G)(S)]
                self.flow_apply_u_ticket._device_send_r_ticket(
                    received_u_token.u_ticket_type,
                    received_u_token.u_ticket_id,
                    self.shared_data.result_message,
                )
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")

    def _device_send_data(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            if "SUCCESS" in result_message:
                generated_request: dict = {
                    "r_ticket_type": f"{r_ticket.TYPE_DATA_RTOKEN}",
                    "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                    "result": f"{result_message}",
                    "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                    "associated_plaintext_data": f"{self.shared_data.current_session.associated_plaintext_data}",
                    "ciphertext_data": f"{self.shared_data.current_session.ciphertext_data}",
                    "gcm_authentication_tag_data": f"{self.shared_data.current_session.gcm_authentication_tag_data}",
                    "iv_cmd": f"{self.shared_data.current_session.iv_cmd}",
                }
            else:
                generated_request: dict = {
                    "r_ticket_type": f"{r_ticket.TYPE_DATA_RTOKEN}",
                    "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                    "result": f"{result_message}",
                }
            generated_r_ticket_json: str = self.msg_generator._generate_xxx_r_ticket(
                generated_request
            )
            # simple_log("debug", f"Generated RToken: {generated_r_ticket_json}")

            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_msg_perf_time(
                "_device_recv_cmd_and_send_data"
            )

            ########################################################################
            # Start Comm Measurement
            ########################################################################
            if self.shared_data.this_device.device_name != "iot_device":
                self.measure_helper.measure_comm_perf_start()

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(
                message.MESSAGE_VERIFY_AND_EXECUTE,
                r_ticket.MESSAGE_TYPE,
                generated_r_ticket_json,
            )

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        # Manually Finish Simulated Comm
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} manually finish PS~~ (device)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()

    def _holder_recv_data(self, received_r_token: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # Query Corresponding UTicket
            # [STAGE: (VL)(L)]
            device_id = received_r_token.device_id
            stored_u_ticket_json = self.shared_data.device_table[
                device_id
            ].device_u_ticket_for_owner
            simple_log("debug", f"Corresponding UTicket: {stored_u_ticket_json}")
            # [STAGE: (VR)]
            stored_u_ticket = self.msg_verifier._classify_u_ticket_is_defined_type(
                stored_u_ticket_json
            )

            # [STAGE: (VRT)]
            self.msg_verifier.verify_u_ticket_has_executed_through_r_ticket(
                r_ticket_in=received_r_token,
                audit_start_ticket=stored_u_ticket,
                audit_end_ticket=None,
            )

            # [STAGE: (VTK)]
            # [STAGE: (E)]
            self.executor._execute_xxx_r_ticket(
                r_ticket_in=received_r_token, comm_end="holder-or-device"
            )
            self.shared_data.result_message = f"-> SUCCESS: VERIFY_UT_HAS_EXECUTED"

            # [STAGE: (C)]
            self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)

            simple_log("debug", f"result_message = {self.shared_data.result_message}")

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            error = "FAILURE: (VL)"
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except RuntimeError as error:  # FAILURE: (VR)(VRT)(VTK)
            self.shared_data.result_message = f"{error}"

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        finally:
            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_msg_perf_time("_holder_recv_data")

            ########################################################################
            # Start Comm Measurement
            ########################################################################
            if self.shared_data.this_device.device_name != "iot_device":
                self.measure_helper.measure_comm_perf_start()

        # Manually Finish Simulated/Bluetooth Comm
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} manually finish PS~~ (holder)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()
        elif Environment.COMMUNICATION_CHANNEL == "BLUETOOTH":
            self.msg_sender.complete_bluetooth_comm()
