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
from ureka_framework.logic.pipeline_flow.flow_open_session import FlowOpenSession


class FlowApplyUTicket:
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
        flow_open_session: FlowOpenSession,
    ) -> None:
        self.shared_data = share_data
        self.measure_helper = measure_helper
        self.received_msg_storer = received_msg_storer
        self.msg_verifier = msg_verifier
        self.executor = executor
        self.msg_generator = msg_generator
        self.generated_msg_storer = generated_msg_storer
        self.msg_sender = msg_sender
        self.flow_open_session = flow_open_session

    ######################################################
    # [PIPELINE FLOW]
    #
    # APY (No CR):
    #       holder_apply_u_ticket() -> _device_recv_u_ticket()
    #       _holder_recv_r_ticket() <- _device_send_r_ticket()
    ######################################################
    def holder_apply_u_ticket(self, device_id: str, cmd: str = "") -> None:
        ######################################################
        # Start Process Measurement
        ######################################################
        self.measure_helper.measure_process_perf_start()

        try:
            # [STAGE: (VL)(L)]
            stored_u_ticket_json: str = self.shared_data.device_table[
                device_id
            ].device_u_ticket_for_owner
            # simple_log(
            #     "debug", f"Stored (& to be Forwarded) UTicket: {stored_u_ticket_json}"
            # )

            # [STAGE: (VR)]
            stored_u_ticket = self.msg_verifier._classify_u_ticket_is_defined_type(
                stored_u_ticket_json
            )

            if (
                stored_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or stored_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_RT)
            elif (
                stored_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                or stored_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                # [STAGE: (E)]
                self.executor._execute_cr_ke(
                    ticket_in=stored_u_ticket, comm_end="holder", cmd=cmd
                )
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_CRKE1)
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")

            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_cli_perf_time("holder_apply_u_ticket")

            ########################################################################
            # Start Comm Measurement
            ########################################################################
            if self.shared_data.this_device.device_name != "iot_device":
                self.measure_helper.measure_comm_perf_start()
            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(
                message.MESSAGE_VERIFY_AND_EXECUTE,
                u_ticket.MESSAGE_TYPE,
                stored_u_ticket_json,
            )

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            error = "FAILURE: (VL)"
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

    def _device_recv_u_ticket(self, received_u_ticket: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # [STAGE: (SR)]
            # No need to optionally _store_received_xxx_u_ticket

            # [STAGE: (VUT)]
            self.msg_verifier.verify_u_ticket_can_execute(received_u_ticket)
            self.shared_data.result_message = f"-> SUCCESS: VERIFY_UT_CAN_EXECUTE"

            # UT-RT
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                # [STAGE: (EO)]
                self.executor._execute_xxx_u_ticket(received_u_ticket)
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_UT)
            # CR-KE
            elif (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                # [STAGE: (E)]
                self.executor._execute_xxx_u_ticket(received_u_ticket)
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CRKE2)
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")

        except RuntimeError as error:
            self.shared_data.result_message = f"{error}"

            # [STAGE: (C)]
            self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_UT)

            # UT-RT
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                pass
            # CR-KE
            elif (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                # Automatically Terminate Simulated Comm
                simple_log(
                    "debug",
                    f"+ {self.shared_data.this_device.device_name} automatically terminate CR-KE-0~~ (device)",
                )
                if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
                    self.msg_sender.complete_simulated_comm()
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        finally:
            # UT-RT
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                # [STAGE: (G)(S)]
                self._device_send_r_ticket(
                    received_u_ticket.u_ticket_type,
                    received_u_ticket.u_ticket_id,
                    self.shared_data.result_message,
                )
            # CR-KE
            elif (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                # [STAGE: (G)(S)]
                self.flow_open_session._device_send_cr_ke_1(
                    self.shared_data.result_message
                )
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")

    def _device_send_r_ticket(
        self, u_ticket_type: str, u_ticket_id: str, result_message: str
    ) -> None:
        try:
            # [STAGE: (G)]
            if (
                u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                if "SUCCESS" in result_message:
                    r_ticket_request: dict = {
                        "r_ticket_type": f"{u_ticket_type}",
                        "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                        "result": f"{result_message}",
                        "audit_start": f"{u_ticket_id}",
                    }
                else:
                    r_ticket_request: dict = {
                        "r_ticket_type": f"{u_ticket_type}",
                        "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                        "result": f"{result_message}",
                    }
            elif u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
                if "SUCCESS" in result_message:
                    # audit_start has already stored when receiving Access UTicket
                    r_ticket_request: dict = {
                        "r_ticket_type": f"{u_ticket_type}",
                        "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                        "result": f"{result_message}",
                        "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                        "audit_end": f"ACCESS_END",
                    }
                else:  # pragma: no cover -> Weird U-Token
                    r_ticket_request: dict = {
                        "r_ticket_type": f"{u_ticket_type}",
                        "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                        "result": f"{result_message}",
                    }
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
            generated_r_ticket_json: str = self.msg_generator._generate_xxx_r_ticket(
                r_ticket_request
            )
            # simple_log("debug",f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (SG)]
            # Can optionally _stored_generated_xxx_r_ticket

            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_msg_perf_time(
                "_device_recv_u_ticket_and_send_r_ticket"
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
            f"+ {self.shared_data.this_device.device_name} manually finish UT-RT~~ (device)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()

    def _holder_recv_r_ticket(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # [STAGE: (SR)]
            self.received_msg_storer._store_received_xxx_r_ticket(received_r_ticket)

            if (
                received_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or received_r_ticket.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or received_r_ticket.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
            ):
                # Query Corresponding UTicket(s)
                #   Notice that even Initialization UTicket is copied in the device_table["device_id"]
                # [STAGE: (VL)(L)]
                stored_u_ticket_json: str = self.shared_data.device_table[
                    received_r_ticket.device_id
                ].device_u_ticket_for_owner
                simple_log("debug", f"Corresponding UTicket: {stored_u_ticket_json}")
                # [STAGE: (VR)]
                stored_u_ticket = self.msg_verifier._classify_u_ticket_is_defined_type(
                    stored_u_ticket_json
                )

                # [STAGE: (VRT)]
                self.msg_verifier.verify_u_ticket_has_executed_through_r_ticket(
                    r_ticket_in=received_r_ticket,
                    audit_start_ticket=stored_u_ticket,
                    audit_end_ticket=None,
                )

                # [STAGE: (E)(O)]
                self.executor._execute_xxx_r_ticket(
                    r_ticket_in=received_r_ticket, comm_end="holder-or-device"
                )
                self.shared_data.result_message = f"-> SUCCESS: VERIFY_UT_HAS_EXECUTED"

                # [STAGE: (C)]
                self.executor._change_state(
                    this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                )

            else:  # pragma: no cover -> TODO: Revocation UTicket
                # Query Corresponding UTicket(s)
                raise RuntimeError(f"Not implemented yet")

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            error = "FAILURE: (VL)"
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except RuntimeError as error:  # FAILURE: (VR)(VRT)
            self.shared_data.result_message = f"{error}"

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        finally:
            simple_log("debug", f"result_message = {self.shared_data.result_message}")

            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_msg_perf_time("_holder_recv_r_ticket")

            ########################################################################
            # Start Comm Measurement
            ########################################################################
            if self.shared_data.this_device.device_name != "iot_device":
                self.measure_helper.measure_comm_perf_start()

        # Manually Finish Simulated/Bluetooth Comm
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} manually finish UT-RT~~ (holder)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()
        elif Environment.COMMUNICATION_CHANNEL == "BLUETOOTH":
            self.msg_sender.complete_bluetooth_comm()
