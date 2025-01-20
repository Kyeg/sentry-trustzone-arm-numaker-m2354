# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Data Model (Message)
import ureka_framework.model.message_model.message as message
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import UTicket, jsonstr_to_u_ticket
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


class FlowIssueUTicket:
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
    ) -> None:
        self.shared_data = share_data
        self.measure_helper = measure_helper
        self.received_msg_storer = received_msg_storer
        self.msg_verifier = msg_verifier
        self.executor = executor
        self.msg_generator = msg_generator
        self.generated_msg_storer = generated_msg_storer
        self.msg_sender = msg_sender

    ######################################################
    # [PIPELINE FLOW]
    #
    # CST: issuer_issue_u_ticket_to_herself()
    # TODO: REQ: _issuer_recv_request() <- holder_send_request_to_issuer()
    # CST: issuer_issue_u_ticket_to_holder() -> _holder_recv_u_ticket()
    # RTN: _issuer_recv_r_ticket() <- holder_send_r_ticket_to_issuer()
    #
    # TODO: More complete Tx (with DID, etc.))
    # TODO: Rollback (e.g., delete the temporary stored state and stored message) if fail
    #         execution only change state after success, but need pay attention to (SR)
    # TODO: QoS Testing - Re-transmission, & Timeout
    #       (e.g., if RTicket is not returned, holder can request backup RTicket)
    #       (e.g., if CR or PS is Timeout, device can revert to the WAIT_FOR_UT state)
    ######################################################
    def issuer_issue_u_ticket_to_herself(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        ######################################################
        # Start Process Measurement
        ######################################################
        self.measure_helper.measure_process_perf_start()

        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table or device_id == "no_id":
                # [STAGE: (G)]
                generated_u_ticket_json: str = (
                    self.msg_generator._generate_xxx_u_ticket(arbitrary_dict)
                )
                #simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # [STAGE: (SG)]
                self.generated_msg_storer._store_generated_xxx_u_ticket(
                    generated_u_ticket_json
                )

                # [STAGE: (O)]
                self.executor._execute_update_ticket_order(
                    "holder-generate-or-receive-uticket",
                    jsonstr_to_u_ticket(generated_u_ticket_json),
                )

        except (
            RuntimeError
        ):  # pragma: no cover -> Weird Ticket-Request (ValidationError)
            failure_msg = f"FAILURE: (VUREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        finally:
            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_cli_perf_time(
                "issuer_issue_u_ticket_to_herself"
            )

            ########################################################################
            # Start Comm Measurement
            ########################################################################
            if self.shared_data.this_device.device_name != "iot_device":
                self.measure_helper.measure_comm_perf_start()

    def issuer_issue_u_ticket_to_holder(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        ######################################################
        # Start Process Measurement
        ######################################################
        self.measure_helper.measure_process_perf_start()

        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table:
                # [STAGE: (G)]
                generated_u_ticket_json: str = (
                    self.msg_generator._generate_xxx_u_ticket(arbitrary_dict)
                )
                # simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # [STAGE: (SG)]
                self.generated_msg_storer._store_generated_xxx_u_ticket(
                    generated_u_ticket_json
                )

                ######################################################
                # End Process Measurement
                ######################################################
                self.measure_helper.measure_recv_cli_perf_time(
                    "issuer_issue_u_ticket_to_holder"
                )

                ########################################################################
                # Start Comm Measurement
                ########################################################################
                if self.shared_data.this_device.device_name != "iot_device":
                    self.measure_helper.measure_comm_perf_start()

                # [STAGE: (S)]
                self.msg_sender._send_xxx_message(
                    message.MESSAGE_RECV_AND_STORE,
                    u_ticket.MESSAGE_TYPE,
                    generated_u_ticket_json,
                )

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            error = "FAILURE: (VL)"
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except (
            RuntimeError
        ):  # pragma: no cover -> Weird Ticket-Request (ValidationError)
            failure_msg = f"FAILURE: (VUREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        # Manually Finish Simulated Comm
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} manually finish UT-UT~~ (issuer)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()

    def _holder_recv_u_ticket(self, received_u_ticket: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]
            # But the actual device id & ticket order in device is still unknown
            # -> TODO: test_fail_when_double_issuing_or_double_spending

            # [STAGE: (SR)]
            self.received_msg_storer._store_received_xxx_u_ticket(received_u_ticket)

            # [STAGE: (O)]
            self.executor._execute_update_ticket_order(
                "holder-generate-or-receive-uticket", received_u_ticket
            )

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        finally:
            # [STAGE: (G)(S)]
            # Can optionally _generate_xxx_r_ticket & _send_xxx_message

            pass

            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_msg_perf_time(
                "_holder_recv_u_ticket",
            )

            # ########################################################################
            # # Start Comm Measurement
            # ########################################################################
            # if self.shared_data.this_device.device_name != "iot_device":
            #     self.measure_helper.measure_comm_perf_start()

        # Manually Finish Simulated Comm
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} manually finish UT-UT~~ (holder)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()

    def holder_send_r_ticket_to_issuer(self, device_id: str) -> None:
        ######################################################
        # Start Process Measurement
        ######################################################
        self.measure_helper.measure_process_perf_start()

        try:
            # [STAGE: (VL)(L)]
            stored_r_ticket_json: str = self.shared_data.device_table[
                device_id
            ].device_r_ticket_for_owner
            # simple_log("debug", f"Stored RTicket: {stored_r_ticket_json}")

            ######################################################
            # End Process Measurement
            ######################################################
            self.measure_helper.measure_recv_cli_perf_time(
                "holder_send_r_ticket_to_issuer"
            )

            ########################################################################
            # Start Comm Measurement
            ########################################################################
            if self.shared_data.this_device.device_name != "iot_device":
                self.measure_helper.measure_comm_perf_start()

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(
                message.MESSAGE_RECV_AND_STORE,
                r_ticket.MESSAGE_TYPE,
                stored_r_ticket_json,
            )

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            error = "FAILURE: (VL)"
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        # Manually Finish Simulated Comm
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} manually finish RT-RT~~ (holder)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()

    def _issuer_recv_r_ticket(self, received_r_ticket: RTicket) -> None:
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
                if received_r_ticket.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
                    stored_u_ticket_json: str = self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_ownership_u_ticket_for_others
                elif received_r_ticket.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
                    stored_u_ticket_json: str = self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_access_u_ticket_for_others
                else:  # pragma: no cover -> Shouldn't Reach Here
                    raise RuntimeError(f"Shouldn't Reach Here")
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
                    r_ticket_in=received_r_ticket, comm_end="issuer"
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

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)(VRT)
            # TODO: (VRT) test_fail_when_double_issuing_or_double_spending
            error = "FAILURE: (VR)(VRT)"
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        finally:
            simple_log("debug", f"result_message = {self.shared_data.result_message}")

            # ######################################################
            # # End Process Measurement
            # ######################################################
            # self.measure_helper.measure_recv_msg_perf_time(
            #     "_issuer_recv_r_ticket",
            # )

            # ########################################################################
            # # Start Comm Measurement
            # ########################################################################
            # if self.shared_data.this_device.device_name != "iot_device":
            #     self.measure_helper.measure_comm_perf_start()

        # Manually Finish Simulated Comm
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} manually finish RT-RT~~ (issuer)",
        )
        if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
            self.msg_sender.complete_simulated_comm()
