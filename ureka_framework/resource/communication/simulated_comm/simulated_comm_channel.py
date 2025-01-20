# Data Model (RAM)
from typing import Optional
from dataclasses import dataclass

# Threading
from queue import Queue

# Prevent circular import by TYPE_CHECKING (mypy's recommanded trick through forward declarations)
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover -> TYPE_CHECKING
    from ureka_framework.logic.device_controller import DeviceController


@dataclass
class SimulatedCommChannel:
    # "Mutable default values" are problematic in Python because they are shared among all instances of the class.
    end: "DeviceController" = None
    # put/get str in Queue
    receiver_queue: Optional[Queue] = None
    sender_queue: Optional[Queue] = None
