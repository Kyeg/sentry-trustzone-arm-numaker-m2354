# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from pydantic import ValidationError
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.message_model.message as message
from ureka_framework.model.message_model.message import Message, message_to_jsonstr
import ureka_framework.model.message_model.u_ticket as u_ticket
import ureka_framework.model.message_model.u_ticket as r_ticket
import ureka_framework.environment as environment
import json

# Resource (Bluetooth Comm)
try:
    HAS_PYBLUEZ = True
    import ureka_framework.resource.communication.bluetooth.bluetooth_service as bt_service
    from ureka_framework.resource.communication.bluetooth.bluetooth_service import (
        AcceptSocket,
        ConnectingWorker,
        ConnectionSocket,
    )
except ImportError:
    HAS_PYBLUEZ = False
    # raise RuntimeError(
    #     "PyBlueZ not found - only support SIMULATED comm but not BLUETOOTH comm"
    # )

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Measure Helper
from ureka_framework.logic.stage_worker.measure_helper import MeasureHelper

# Threading
import time

class MsgSender:
    def __init__(
        self,
        shared_data: SharedData,
        measure_helper: MeasureHelper,
    ) -> None:
        self.shared_data = shared_data
        self.measure_helper = measure_helper

    ######################################################
    # Resource (Simulated Comm)
    ######################################################
    def start_simulated_comm(self) -> None:
        self.shared_data.simulated_comm_completed_flag = False

    def complete_simulated_comm(self) -> None:
        self.shared_data.simulated_comm_completed_flag = True

    def wait_simulated_comm_completed(self) -> None:
        if Environment.DEPLOYMENT_ENV == "TEST":
            # Pytest terminates all daemon threads when main thread is finished
            while not self.shared_data.simulated_comm_completed_flag:
                time.sleep(Environment.SIMULULATED_COMM_INTERRUPT_CYCLE_TIME)
        elif Environment.DEPLOYMENT_ENV == "PRODUCTION":
            self.shared_data.simulated_comm_receiver_thread.join()

    ######################################################
    # Resource (Bluetooth Comm)
    ######################################################
    def start_bluetooth_comm(self) -> None:
        self.shared_data.bluetooth_comm_completed_flag = False

    def complete_bluetooth_comm(self) -> None:
        self.shared_data.bluetooth_comm_completed_flag = True

    def connect_bluetooth_comm(self) -> None:
        self.shared_data.connecting_worker = ConnectingWorker(
            service_uuid=bt_service.SERVICE_UUID,
            service_name=bt_service.SERVICE_NAME,
            reconnect_times=bt_service.RECONNECT_TIMES,
            reconnect_interval=bt_service.RECONNECT_INTERVAL,
        )
        self.shared_data.connection_socket: ConnectionSocket = (
            self.shared_data.connecting_worker.connect()
        )

    def close_bluetooth_connection(self) -> None:
        self.shared_data.connection_socket.close()

    ######################################################
    # [STAGE: (S)] Send Message
    ######################################################
    @measure_worker_func
    def _send_xxx_message(
        self, message_operation: str, message_type: str, sent_message_json: str
    ) -> None:
        global my_ticket
        simple_log("debug", f"sent_message_json: {sent_message_json}")
        # Generate Message
        if (
            message_operation == message.MESSAGE_RECV_AND_STORE
            or message.MESSAGE_VERIFY_AND_EXECUTE
        ) and (message_type == u_ticket.MESSAGE_TYPE or r_ticket.MESSAGE_TYPE):
            message_request: dict = {
                "message_operation": f"{message_operation}",
                "message_type": f"{message_type}",
                "message_str": f"{sent_message_json}",
            }
            try:
                new_message = Message(**message_request)
                new_message_json = message_to_jsonstr(new_message)
                # simple_log("debug", f"sent_message_json: {sent_message_json}")
            except ValidationError as error:  # pragma: no cover -> Weird M-Request
                raise RuntimeError(f"Weird M-Request: {error}")
        else:  # pragma: no cover -> Weird M-Request
            raise RuntimeError("Weird M-Request")
        environment.my_ticket = new_message_json
        # if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
        #     simple_log(
        #         "info",
        #         f"+ {self.shared_data.this_device.device_name} is sending message "
        #         f"to {self.shared_data.simulated_comm_channel.end.shared_data.this_device.device_name}...",
        #     )

        #     # Simulate Network Delay
        #     for _ in range(Environment.SIMULULATED_COMM_DELAY_COUNT):
        #         simple_log("info", f"+ network delay")
        #         simple_log("info", f"+ network delay")
        #         simple_log("info", f"+ network delay")
        #         if (
        #             Environment.DEPLOYMENT_ENV == "PRODUCTION"
        #         ):  # pragma: no cover -> PRODUCTION
        #             time.sleep(Environment.SIMULULATED_COMM_DELAY_DURATION)

        #     self.shared_data.simulated_comm_channel.sender_queue.put(new_message_json)
        # else:  # pragma: no cover -> PRODUCTION
        #     simple_log(
        #         "info",
        #         f"+ {self.shared_data.this_device.device_name} is sending message "
        #         f"to BT_address or BT_name...",
        #     )

            #self.shared_data.connection_socket.send_message(new_message_json)
