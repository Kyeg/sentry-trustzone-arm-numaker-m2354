# Environment
from ureka_framework.environment import Environment

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model (Message)
import json

# Data Model (RAM)
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr

# Simulated Communication
from tests.conftest import (
    create_simulated_comm_connection,
    wait_simulated_comm_completed,
)


class MenuAgentOrServer:
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
        # GIVEN: Load UA or CS
        self.agent_or_server = DeviceController(
            device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
            device_name=device_name,
        )

    def get_agent_or_server(self) -> DeviceController:
        return self.agent_or_server

    def get_target_device_id(self) -> str:
        # TODO: For complicated case, show a device list and let user choose
        # show_device_list()...
        # input()...

        # For simple case, just return the first device id
        if list(self.agent_or_server.shared_data.device_table.keys())[0] == "no_id":
            return list(self.agent_or_server.shared_data.device_table.keys())[1]
        else:
            return list(self.agent_or_server.shared_data.device_table.keys())[0]

    def intialize_agent_or_server_through_cli(self) -> DeviceController:
        # WHEN: Initialize UA or CS
        if self.agent_or_server.shared_data.this_device.ticket_order == 0:
            self.agent_or_server.executor._execute_one_time_intialize_agent_or_server()

        return self.agent_or_server

    def apply_initialization_ticket_through_bluetooth(self) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Issuer: DM's CS generate the intialization_u_ticket to herself
        id_for_initialization_u_ticket = "no_id"
        generated_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.agent_or_server.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )

        # WHEN: Holder: DM's CS forward the intialization_u_ticket to Uninitialized IoTD
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(
            id_for_initialization_u_ticket
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish UT-RT~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def issue_ownership_ticket_through_simulated_comm(
        self, target_device_id: str, new_owner: DeviceController
    ) -> None:
        # WHEN: Issuer: Old owner generate & send the ownership_u_ticket to New Owner
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_simulated_comm_connection(self.agent_or_server, new_owner)
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{new_owner.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        wait_simulated_comm_completed(new_owner, self.agent_or_server)

    def apply_ownership_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the ownership_u_ticket to IoTD
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(target_device_id)
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish UT-RT~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def apply_self_access_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Issuer: DM's CS generate the self_access_u_ticket to herself
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.agent_or_server.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_SELFACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=target_device_id, arbitrary_dict=generated_request
        )

        # WHEN: Holder: DM's CS forward the self_access_u_ticket to Uninitialized IoTD
        generated_command = "HELLO-1"
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish CR-KE~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def issue_access_ticket_through_simulated_comm(
        self, target_device_id: str, new_accessor: DeviceController
    ) -> None:
        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_simulated_comm_connection(self.agent_or_server, new_accessor)
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{new_accessor.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        wait_simulated_comm_completed(new_accessor, self.agent_or_server)

    def apply_access_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "HELLO-1"
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(
            device_id=target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish CR-KE~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def apply_cmd_token_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "HELLO-2"
        self.agent_or_server.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish PS~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def apply_access_end_token_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "ACCESS_END"
        self.agent_or_server.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command, access_end=True
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish PS~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def return_r_ticket_through_simulated_comm(
        self, target_device_id: str, original_issuer: DeviceController
    ) -> None:
        # WHEN: Holder: Holder return the r_ticket to Issuer
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_simulated_comm_connection(original_issuer, self.agent_or_server)
        self.agent_or_server.flow_issuer_issue_u_ticket.holder_send_r_ticket_to_issuer(
            target_device_id
        )
        wait_simulated_comm_completed(original_issuer, self.agent_or_server)

    ######################################################
    # Insecure Mode
    ######################################################
    def apply_insecure_cmd_through_bluetooth(
        self, option: str = "with_device_id"
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: UA or CS send the insecure_cmd to IoTD

        ########################################################################
        # Start Process Measurement
        ########################################################################
        self.agent_or_server.measure_helper.measure_process_perf_start()

        if option == "shortest":
            insecure_cmd_json = "HELLO"
        elif option == "with_device_id":
            insecure_cmd_dict = {
                "protocol_version": "UREKA-1.0",
                "device_id": "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuWt9xdWLXffJE-CydWYBTH05kv7xFmMGl-L3DT_7-YH2ocgHJWUUAPxQjjRBQGOeITMandJxLDye7jK8W26GmA==",
                "insecure_command": "HELLO",
            }
            insecure_cmd_json = json.dumps(insecure_cmd_dict, indent=4)
        elif option == "u_ticket_size":
            insecure_cmd_dict = {
                "protocol_version": "UREKA-1.0",
                "device_id": "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuWt9xdWLXffJE-CydWYBTH05kv7xFmMGl-L3DT_7-YH2ocgHJWUUAPxQjjRBQGOeITMandJxLDye7jK8W26GmA==",
                "insecure_command": "HELLO" * 150,
            }
            insecure_cmd_json = json.dumps(insecure_cmd_dict, indent=4)

        self.agent_or_server.shared_data.connection_socket.send_message(
            insecure_cmd_json
        )
        simple_log("cli", f"Sent Command: {insecure_cmd_json}")

        ######################################################
        # End Process Measurement
        ######################################################
        self.agent_or_server.measure_helper.measure_recv_cli_perf_time(
            "holder_apply_insecure_cmd"
        )

        ########################################################################
        # Start Comm Measurement
        ########################################################################
        if self.agent_or_server.shared_data.this_device.device_name != "iot_device":
            self.agent_or_server.measure_helper.measure_comm_perf_start()

        # WHEN: UA or CS receive the insecure_data from IoTD
        try:
            ########################################################################
            # Start Comm Measurement
            ########################################################################
            self.agent_or_server.measure_helper.measure_comm_perf_start()

            # This will block until message is received
            insecure_data_json = (
                self.agent_or_server.shared_data.connection_socket.recv_message()
            )

            ########################################################################
            # End Comm Measurement
            ########################################################################
            self.agent_or_server.measure_helper.measure_comm_time("_recv_message")

            ########################################################################
            # Message Size Measurement
            ########################################################################
            self.agent_or_server.measure_helper.measure_message_size(
                "_recv_message", insecure_data_json
            )
            simple_log("cli", f"Received Data: {insecure_data_json}")

            ########################################################################
            # Start Process Measurement
            ########################################################################
            self.agent_or_server.measure_helper.measure_process_perf_start()

            # WHEN: UA/CS do data processing

            ######################################################
            # End Process Measurement
            ######################################################
            self.agent_or_server.measure_helper.measure_recv_msg_perf_time(
                "_holder_recv_insecure_data"
            )

            ########################################################################
            # Start Comm Measurement
            ########################################################################
            if self.agent_or_server.shared_data.this_device.device_name != "iot_device":
                self.agent_or_server.measure_helper.measure_comm_perf_start()

            simple_log("debug", f"+ Finish CMD-DATA~~ (holder)")
        except OSError:
            simple_log("cli", f"")
            simple_log("cli", f"+ Connection is closed by peer.")

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish CMD-DATA~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server
