# Environment
from ureka_framework.environment import Environment

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model (Message)
import json

# Data Model (RAM)
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device

# Threading
import time


class MenuIoTDevice:
    ######################################################
    # Environment
    ######################################################
    @classmethod
    def set_environment(cls, situation: str = "measurement") -> None:
        if situation == "cli":
            Environment.DEPLOYMENT_ENV = "PRODUCTION"
            Environment.DEBUG_LOG = "CLOSED"
            Environment.CLI_LOG = "OPEN"
            Environment.MEASURE_LOG = "CLOSED"
            Environment.MORE_MEASURE_WORKER_LOG = "CLOSED"
            Environment.MORE_MEASURE_RESOURCE_LOG = "CLOSED"
        elif situation == "measurement":
            Environment.DEPLOYMENT_ENV = "PRODUCTION"
            Environment.DEBUG_LOG = "CLOSED"
            Environment.CLI_LOG = "CLOSED"
            Environment.MEASURE_LOG = "CLOSED"
            Environment.MORE_MEASURE_WORKER_LOG = "CLOSED"
            Environment.MORE_MEASURE_RESOURCE_LOG = "CLOSED"

    ######################################################
    # Secure Mode
    ######################################################
    def __init__(self, device_name: str) -> None:
        # GIVEN: Load IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name=device_name,
        )
        # self.sleep_time = 0.2  # Simulate blocked I/O

    def get_iot_device(self) -> DeviceController:
        return self.iot_device

    def receive_u_ticket_through_bluetooth(self) -> DeviceController:
        # WHEN: Accept bluetooth connection from UA or CS
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.iot_device.msg_receiver.accept_bluetooth_comm()

        # WHEN: Receive/Send Message in Connection
        self.iot_device.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth Connection with UA or CS
        self.iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Stop Accepting New bluetooth Connections from UA or CS
        self.iot_device.msg_receiver.close_bluetooth_acception()

        return self.iot_device

    ######################################################
    # Insecure Mode
    ######################################################
    def receive_insecure_cmd_through_bluetooth(
        self, option: str = "with_device_id"
    ) -> DeviceController:
        # WHEN: Accept bluetooth connection from UA or CS
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.iot_device.msg_receiver.accept_bluetooth_comm()

        # WHEN: IoTD receive the insecure_cmd from UA or CS
        while True:
            try:
                # This will block until message is received
                insecure_cmd_json = (
                    self.iot_device.shared_data.connection_socket.recv_message()
                )

                ########################################################################
                # Message Size Measurement
                ########################################################################
                self.iot_device.measure_helper.measure_message_size(
                    "_recv_message", insecure_cmd_json
                )
                simple_log("cli", f"Received Command: {insecure_cmd_json}")

                ######################################################
                # Start Process Measurement
                ######################################################
                self.iot_device.measure_helper.measure_process_perf_start()

                # WHEN: IoTD do data processing
                if option == "shortest":
                    insecure_data_json = f"Data: {insecure_cmd_json}"
                    # if self.sleep_time > 0:
                    #     time.sleep(self.sleep_time)  # Simulate blocked I/O
                    #     self.sleep_time = self.sleep_time - 0.02
                else:
                    insecure_cmd_dict = json.loads(insecure_cmd_json, strict=False) 
                    insecure_data_dict = {
                        "protocol_version": insecure_cmd_dict["protocol_version"],
                        "device_id": insecure_cmd_dict["device_id"],
                        "insecure_data_response": f"Data: {insecure_cmd_dict['insecure_command']}",
                    }
                    insecure_data_json = json.dumps(insecure_data_dict, indent=4)
                    # if self.sleep_time > 0:
                    #     time.sleep(self.sleep_time)  # Simulate blocked I/O
                    #     self.sleep_time = self.sleep_time - 0.02

                # WHEN: IoTD return the insecure_data to UA or CS
                self.iot_device.shared_data.connection_socket.send_message(
                    insecure_data_json
                )
                simple_log("cli", f"Sent Data: {insecure_data_json}")

                ######################################################
                # End Process Measurement
                ######################################################
                self.iot_device.measure_helper.measure_recv_msg_perf_time(
                    "_device_recv_insecure_cmd"
                )

                ########################################################################
                # Start Comm Measurement
                ########################################################################
                if self.iot_device.shared_data.this_device.device_name != "iot_device":
                    self.iot_device.measure_helper.measure_comm_perf_start()

                simple_log(
                    "debug",
                    f"+ {self.iot_device.shared_data.this_device.device_name} manually finish CMD-DATA~~ (device)",
                )
            except OSError:
                simple_log("cli", f"")
                simple_log("cli", f"+ Connection is closed by peer.")
                break

        # RE-GIVEN: Close bluetooth connection with UA or CS
        self.iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Stop Accepting New bluetooth Connections from UA or CS
        self.iot_device.msg_receiver.close_bluetooth_acception()

        return self.iot_device
