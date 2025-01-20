# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from typing import Optional
from ureka_framework.model.shared_data import SharedData
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.other_device import OtherDevice
from ureka_framework.model.data_model.current_session import CurrentSession
from ureka_framework.model.data_model.this_person import ThisPerson

# Data Model (Message)
from ureka_framework.model.message_model.u_ticket import UTicket
from ureka_framework.model.message_model.r_ticket import RTicket

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Simulated Comm)
from ureka_framework.resource.communication.simulated_comm.simulated_comm_channel import (
    SimulatedCommChannel,
)

# Resource (Bluetooth Comm)
try:
    HAS_PYBLUEZ = True
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

# Threading
import time
import threading
from queue import Queue

# Measure Helper
from ureka_framework.logic.stage_worker.measure_helper import MeasureHelper

# Stage Worker
from ureka_framework.logic.stage_worker.msg_receiver import MsgReceiver
from ureka_framework.logic.stage_worker.received_msg_storer import ReceivedMsgStorer
from ureka_framework.logic.stage_worker.msg_verifier import MsgVerifier
from ureka_framework.logic.stage_worker.executor import Executor
from ureka_framework.logic.stage_worker.msg_generator import MsgGenerator
from ureka_framework.logic.stage_worker.generated_msg_storer import GeneratedMsgStorer
from ureka_framework.logic.stage_worker.msg_sender import MsgSender

# Pipeline Flow
from ureka_framework.logic.pipeline_flow.flow_issue_u_ticket import FlowIssueUTicket
from ureka_framework.logic.pipeline_flow.flow_apply_u_ticket import FlowApplyUTicket
from ureka_framework.logic.pipeline_flow.flow_open_session import FlowOpenSession
from ureka_framework.logic.pipeline_flow.flow_issue_u_token import FlowIssueUToken


class DeviceController:
    def __init__(self, device_type: str = None, device_name: str = None) -> None:
        # Data Model (RAM)
        self.shared_data = SharedData(
            this_device=ThisDevice(),
            current_session=CurrentSession(),
            this_person=ThisPerson(),
            device_table={},
            state=None,
        )

        # Resource (Storage)
        self.simple_storage = SimpleStorage(device_name=device_name)

        # Resource (Simulated Comm)
        self.shared_data.simulated_comm_channel = SimulatedCommChannel(
            end=None, receiver_queue=Queue(), sender_queue=None
        )
        # Resource (Bluetooth Comm)
        if HAS_PYBLUEZ == True:
            self.shared_data.accept_socket: Optional[AcceptSocket] = None
            self.shared_data.connecting_worker: Optional[ConnectingWorker] = None
            self.shared_data.connection_socket: Optional[ConnectionSocket] = None

        # Measurer
        self.shared_data.measure_rec = dict()
        self.measure_helper = MeasureHelper(shared_data=self.shared_data)

        # Stage Worker
        self.received_msg_storer = ReceivedMsgStorer(
            shared_data=self.shared_data,
            measure_helper=self.measure_helper,
            simple_storage=self.simple_storage,
        )
        self.msg_verifier = MsgVerifier(
            shared_data=self.shared_data,
            measure_helper=self.measure_helper,
        )
        self.executor = Executor(
            shared_data=self.shared_data,
            measure_helper=self.measure_helper,
            simple_storage=self.simple_storage,
            msg_verifier=self.msg_verifier,
        )
        self.msg_generator = MsgGenerator(
            shared_data=self.shared_data,
            measure_helper=self.measure_helper,
        )
        self.generated_msg_storer = GeneratedMsgStorer(
            shared_data=self.shared_data,
            measure_helper=self.measure_helper,
            simple_storage=self.simple_storage,
        )
        self.msg_sender = MsgSender(
            shared_data=self.shared_data,
            measure_helper=self.measure_helper,
        )

        # Flow
        self.flow_issuer_issue_u_ticket = FlowIssueUTicket(
            share_data=self.shared_data,
            measure_helper=self.measure_helper,
            received_msg_storer=self.received_msg_storer,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_generator=self.msg_generator,
            generated_msg_storer=self.generated_msg_storer,
            msg_sender=self.msg_sender,
        )
        self.flow_open_session = FlowOpenSession(
            share_data=self.shared_data,
            measure_helper=self.measure_helper,
            received_msg_storer=self.received_msg_storer,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_generator=self.msg_generator,
            generated_msg_storer=self.generated_msg_storer,
            msg_sender=self.msg_sender,
        )
        self.flow_apply_u_ticket = FlowApplyUTicket(
            share_data=self.shared_data,
            measure_helper=self.measure_helper,
            received_msg_storer=self.received_msg_storer,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_generator=self.msg_generator,
            generated_msg_storer=self.generated_msg_storer,
            msg_sender=self.msg_sender,
            flow_open_session=self.flow_open_session,
        )
        self.flow_issue_u_token = FlowIssueUToken(
            share_data=self.shared_data,
            measure_helper=self.measure_helper,
            received_msg_storer=self.received_msg_storer,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_generator=self.msg_generator,
            generated_msg_storer=self.generated_msg_storer,
            msg_sender=self.msg_sender,
            flow_apply_u_ticket=self.flow_apply_u_ticket,
        )

        # Stage Worker
        self.msg_receiver = MsgReceiver(
            shared_data=self.shared_data,
            measure_helper=self.measure_helper,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_sender=self.msg_sender,
            flow_issuer_issue_u_ticket=self.flow_issuer_issue_u_ticket,
            flow_apply_u_ticket=self.flow_apply_u_ticket,
            flow_open_session=self.flow_open_session,
            flow_issue_u_token=self.flow_issue_u_token,
        )

        # Always load Storage after Reboot
        (
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        ) = self.simple_storage.load_storage()

        # Set Device Type (must after loading storage)
        if self.shared_data.this_device.has_device_type is False:
            self.executor._execute_one_time_set_time_device_type_and_name(
                device_type, device_name
            )

        # Set Intialized State
        self.executor._intialize_state()

        simple_log("info", f"+ Here is a {self.shared_data.this_device.device_name}...")

    ######################################################
    # Device Activity Cycle
    ######################################################
    def reboot_device(self) -> None:
        simple_log("info", f"+ Reboot {self.shared_data.this_device.device_name}...")
        self.__init__(
            device_type=self.shared_data.this_device.device_type,
            device_name=self.shared_data.this_device.device_name,
        )
