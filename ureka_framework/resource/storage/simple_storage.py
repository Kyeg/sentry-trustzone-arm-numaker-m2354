# Data Model (RAM)
from typing import Tuple
from ureka_framework.model.data_model.this_device import (
    ThisDevice,
    jsonstr_to_this_device,
    this_device_to_jsonstr,
)
from ureka_framework.model.data_model.other_device import (
    OtherDevice,
    jsonstr_to_device_table,
    device_table_to_jsonstr,
)
from ureka_framework.model.data_model.this_person import (
    ThisPerson,
    jsonstr_to_this_person,
    this_person_to_jsonstr,
)
from ureka_framework.model.data_model.current_session import (
    CurrentSession,
    jsonstr_to_current_session,
    current_session_to_jsonstr,
)

# File I/O
from pathlib import Path
import shutil

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_resource_func


class SimpleStorage:
    # Class Variables
    path_storage: Path = Path(__file__).parent / "SimpleStorage"

    # Instance Variables
    def __init__(self, device_name: str) -> None:
        # Directory Path
        self.path_device_controller: Path = self.path_storage / device_name
        self._create_root_directory_for_each_device_controller()

        # File Path for Data Model
        self.path_this_device: Path = self.path_device_controller / "this_device.json"
        self.path_device_table: Path = self.path_device_controller / "device_table.json"
        self.path_u_ticket_table: Path = (
            self.path_device_controller / "u_ticket_table.json"
        )
        self.path_this_person: Path = self.path_device_controller / "this_person.json"
        self.path_current_session: Path = (
            self.path_device_controller / "current_session.json"
        )

    def _create_root_directory_for_each_device_controller(self) -> None:
        # Create a new directory if it doesn't exist
        if not Path(self.path_device_controller).exists():
            self.path_device_controller.mkdir(parents=True)
            simple_log("debug", f"Create: {self.path_device_controller}")
        else:
            simple_log("debug", f"Exist: {self.path_device_controller}")

    # The data access can be further optimized by more fine-grained interface
    # so that we can access each variable rather than access the whole object (faster, but more code)
    @measure_resource_func
    def store_storage(
        self,
        this_device: ThisDevice,
        device_table: dict[str, OtherDevice],
        this_person: ThisPerson,
        current_session: CurrentSession,
    ) -> None:
        with self.path_this_device.open("w") as file:
            file.write(this_device_to_jsonstr(this_device))

        with self.path_device_table.open("w") as file:
            file.write(device_table_to_jsonstr(device_table))

        with self.path_this_person.open("w") as file:
            file.write(this_person_to_jsonstr(this_person))

        with self.path_current_session.open("w") as file:
            file.write(current_session_to_jsonstr(current_session))

    # The data access can be further optimized by more fine-grained interface
    # so that we can access each variable rather than access the whole object (faster, but more code)
    @measure_resource_func
    def load_storage(
        self,
    ) -> Tuple[ThisDevice, dict[str, OtherDevice], ThisPerson, CurrentSession]:
        # Before execute_one_time_set_time_device_type_and_name: Intialized Object with default value
        this_device: ThisDevice = ThisDevice()
        device_table: dict[str, OtherDevice] = {}
        this_person: ThisPerson = ThisPerson()
        current_session: CurrentSession = CurrentSession()

        # After execute_one_time_set_time_device_type_and_name: the default value will be overwritten
        if Path(self.path_this_device).exists():
            with self.path_this_device.open("r") as file:
                this_device = jsonstr_to_this_device(file.read())

        if Path(self.path_device_table).exists():
            with self.path_device_table.open("r") as file:
                device_table = jsonstr_to_device_table(file.read())

        if Path(self.path_this_person).exists():
            with self.path_this_person.open("r") as file:
                this_person = jsonstr_to_this_person(file.read())

        if Path(self.path_current_session).exists():
            with self.path_current_session.open("r") as file:
                current_session = jsonstr_to_current_session(file.read())

        return (this_device, device_table, this_person, current_session)

    # Teardown - Development Only Function
    @classmethod
    def delete_storage_in_test(cls) -> None:
        # removing directory (If use Path.rmdir(), the directory must be empty...)
        try:
            shutil.rmtree(cls.path_storage)
            simple_log("debug", f"Delete: {cls.path_storage}")
        except OSError as e:
            # simple_log("error",f"FAILURE: {e.filename} - {e.strerror}.")
            pass
