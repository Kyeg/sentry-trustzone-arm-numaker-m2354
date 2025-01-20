# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from typing import Optional
from dataclasses import dataclass, field
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.current_session import CurrentSession
from ureka_framework.model.data_model.this_person import ThisPerson
from ureka_framework.model.data_model.other_device import OtherDevice

# Threading
import threading

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


@dataclass
class SharedData:
    # Data Model (Persistent)
    this_device: Optional[ThisDevice] = None
    current_session: Optional[CurrentSession] = None
    # Data Model (Persistent: User Agent or Cloud Server only)
    this_person: Optional[ThisPerson] = None
    device_table: Optional[dict[str, OtherDevice]] = field(default_factory=dict)
    # Data Model (RAM-only)
    state: Optional[str] = None

    # CLI Output
    received_message_json: Optional[str] = None
    result_message: Optional[str] = None
    # target_device_id: Optional[str] = None

    # Measurement Record
    measure_rec: dict = None

    # Resource (Simulated Comm)
    simulated_comm_channel: Optional[SimulatedCommChannel] = None
    simulated_comm_receiver_thread: threading.Thread = None
    simulated_comm_completed_flag: Optional[bool] = None

    # Resource (Bluetooth Comm)
    if HAS_PYBLUEZ == True:
        accept_socket: Optional[AcceptSocket] = None
        connecting_worker: Optional[ConnectingWorker] = None
        connection_socket: Optional[ConnectionSocket] = None
        bluetooth_comm_completed_flag: Optional[bool] = None
