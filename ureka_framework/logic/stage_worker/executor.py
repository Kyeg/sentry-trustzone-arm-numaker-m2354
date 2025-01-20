# Data Model (RAM)
from typing import Union, Optional, Tuple
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device
from ureka_framework.model.data_model.current_session import current_session_to_jsonstr

# Data Model (Message)
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import UTicket
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.message_model.r_ticket import RTicket

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Crypto)
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidTag
from ureka_framework.resource.crypto.serialization_util import (
    base64str_backto_byte,
    byte_to_base64str,
    str_to_key,
    str_to_byte,
    byte_backto_str,
)

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Stage Worker
from ureka_framework.logic.stage_worker.msg_verifier import MsgVerifier

# Measure Helper
from ureka_framework.logic.stage_worker.measure_helper import MeasureHelper


class Executor:
    def __init__(
        self,
        shared_data: SharedData,
        measure_helper: MeasureHelper,
        simple_storage: SimpleStorage,
        msg_verifier: MsgVerifier,
    ) -> None:
        self.shared_data = shared_data
        self.measure_helper = measure_helper
        self.simple_storage = simple_storage
        self.msg_verifier = msg_verifier

    ######################################################
    # [STAGE: (E)] Execute
    ######################################################
    # @measure_worker_func
    def _intialize_state(self) -> bool:
        ######################################################
        # Initial State
        ######################################################
        # [STAGE: (C)]
        if self.shared_data.this_device.device_type == this_device.IOT_DEVICE:
            self._change_state(this_device.STATE_DEVICE_WAIT_FOR_UT)
        elif (
            self.shared_data.this_device.device_type
            == this_device.USER_AGENT_OR_CLOUD_SERVER
        ):
            self._change_state(this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT)

    # Execute Initialization (Update Keystore)
    # @measure_worker_func
    def _execute_one_time_set_time_device_type_and_name(
        self, device_type: str, device_name: str
    ) -> bool:
        ######################################################
        # Determine device type name, but still be uninitialized
        # Determine device name (for test)
        ######################################################
        self.shared_data.this_device.device_type = device_type
        self.shared_data.this_device.device_name = device_name
        self.shared_data.this_device.has_device_type = True

        ######################################################
        # Initial Order
        ######################################################
        # [STAGE: (O)]
        self._execute_update_ticket_order("has-type")

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    # @measure_worker_func
    def _execute_one_time_intialize_agent_or_server(self) -> None:
        ######################################################
        # Start Process Measurement
        ######################################################
        self.measure_helper.measure_process_perf_start()

        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is initializing...",
        )

        ######################################################
        # TODO: New way for _execute_one_time_intialize_agent_or_server()
        #         + DM: Apply Initialization Ticket
        #         + DM: Apply Personal Key Gen Ticket
        #         + DO: Generate Personal Key
        #         + DO: Request Ownership Ticket from DM
        ######################################################

        if (
            self.shared_data.this_device.device_type
            != this_device.USER_AGENT_OR_CLOUD_SERVER
        ):
            # FAILURE: (VRESET)
            failure_msg = "-> FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        if self.shared_data.this_device.ticket_order != 0:
            # FAILURE: (VUT)
            failure_msg = "-> FAILURE: VERIFY_TICKET_ORDER: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        (device_priv_key, device_pub_key) = ecc.generate_key_pair()
        # print(f"device_priv_key: {device_priv_key}")
        # print(f"device_pub_key: {device_pub_key.public_numbers().x}")
        # print(f"device_pub_key: {device_pub_key.public_numbers().y}")

        # RAM
        self.shared_data.this_device.device_priv_key = device_priv_key
        self.shared_data.this_device.device_pub_key = device_pub_key

        ######################################################
        # Initialize Personal Id
        ######################################################
        # CRYPTO
        (person_priv_key, person_pub_key) = ecc.generate_key_pair()

        # RAM
        self.shared_data.this_person.person_priv_key = person_priv_key
        self.shared_data.this_person.person_pub_key = person_pub_key

        ######################################################
        # Initialize Device Owner
        ######################################################
        # RAM
        self.shared_data.this_device.owner_pub_key = (
            self.shared_data.this_person.person_pub_key
        )

        # [STAGE: (O)]
        self._execute_update_ticket_order("agent-initialization")

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

        ######################################################
        # End Process Measurement
        ######################################################
        self.measure_helper.measure_recv_cli_perf_time(
            "_execute_one_time_intialize_agent_or_server"
        )

    # Execute UTicket (Update Keystore, Session, & Ticket Order)
    @measure_worker_func
    def _execute_xxx_u_ticket(self, u_ticket_in: UTicket) -> None:
        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            try:
                # [STAGE: (E)]
                self._execute_one_time_initialize_iot_device(u_ticket_in)
                # [STAGE: (O)]
                self._execute_update_ticket_order("device-verify-uticket", u_ticket_in)
            except (
                RuntimeError
            ) as error:  # pragma: no cover -> TODO: New way for _execute_one_time_intialize_agent_or_server()
                simple_log("error", f"{error}")
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
            # [STAGE: (E)]
            self._execute_ownership_transfer(u_ticket_in)
            # [STAGE: (O)]
            self._execute_update_ticket_order("device-verify-uticket", u_ticket_in)
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
        ):
            # [STAGE: (E)]
            self._execute_cr_ke(ticket_in=u_ticket_in, comm_end="device")
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # [STAGE: (VTK)(VTS)]
            # [STAGE: (E)]
            # Update Session: PS-Cmd
            self._execute_ps(executing_case="recv-utoken", ticket_in=u_ticket_in)
            # Data Processing
            (plaintext_data, associated_plaintext_data) = self._execute_data_processing(
                self.shared_data.current_session.plaintext_cmd,
                self.shared_data.current_session.associated_plaintext_cmd,
            )
            # Update Session: PS-Data
            self._execute_ps(
                executing_case="send-rtoken",
                ticket_in=u_ticket_in,
                plaintext=plaintext_data,
                associated_plaintext=associated_plaintext_data,
            )
            if u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
                # [STAGE: (VTK)]
                if self.shared_data.current_session.plaintext_cmd == "ACCESS_END":
                    self.shared_data.result_message = f"-> SUCCESS: VERIFY_ACCESS_END"
                    simple_log("info", self.shared_data.result_message)
                    # [STAGE: (O)]
                    self._execute_update_ticket_order(
                        "device-verify-uticket", u_ticket_in
                    )
                else:  # pragma: no cover -> FAILURE: (VTK)
                    self.shared_data.result_message = f"-> FAILURE: VERIFY_ACCESS_END"
                    simple_log("error", self.shared_data.result_message)
                    raise RuntimeError(self.shared_data.result_message)
        else:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

    # Execute RTicket (Update Session, & Ticket Order)
    @measure_worker_func
    def _execute_xxx_r_ticket(
        self, r_ticket_in: RTicket, comm_end="holder-or-device"
    ) -> None:
        if comm_end == "holder-or-device":
            if (
                r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
            ):
                # [STAGE: (O)]
                self._execute_update_ticket_order(
                    "holder-or-issuer-verify-rticket", r_ticket_in
                )
            elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
                # [STAGE: (E)]
                self._execute_cr_ke(ticket_in=r_ticket_in, comm_end="holder")
            elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
                # [STAGE: (E)]
                self._execute_cr_ke(ticket_in=r_ticket_in, comm_end="device")
            elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
                # [STAGE: (E)]
                self._execute_cr_ke(ticket_in=r_ticket_in, comm_end="holder")
            elif r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
                # [STAGE: (E)]
                self._execute_ps(executing_case="recv-rtoken", ticket_in=r_ticket_in)
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
        elif comm_end == "issuer":
            if r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
                # Not owner anymore, delete this device in table
                self.shared_data.device_table.pop(r_ticket_in.device_id)
                ######################################################
                # Storage
                ######################################################
                self.simple_storage.store_storage(
                    self.shared_data.this_device,
                    self.shared_data.device_table,
                    self.shared_data.this_person,
                    self.shared_data.current_session,
                )
            elif r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
                # Still owner, but keep/delete device_access_u_ticket_for_others in table
                self.shared_data.device_table[
                    r_ticket_in.device_id
                ].device_access_u_ticket_for_others = None
                self.shared_data.device_table[
                    r_ticket_in.device_id
                ].device_access_end_r_ticket_for_others = None
                # [STAGE: (O)]
                self._execute_update_ticket_order(
                    "holder-or-issuer-verify-rticket", r_ticket_in
                )
                ######################################################
                # Storage
                ######################################################
                self.simple_storage.store_storage(
                    self.shared_data.this_device,
                    self.shared_data.device_table,
                    self.shared_data.this_person,
                    self.shared_data.current_session,
                )
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")

    # Ownership
    # @measure_worker_func
    def _execute_one_time_initialize_iot_device(self, u_ticket_in: UTicket) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is intializing...",
        )

        if (
            self.shared_data.this_device.device_type != this_device.IOT_DEVICE
        ):  # pragma: no cover -> TODO: New way for _execute_one_time_intialize_agent_or_server()
            failure_msg = (
                "-> FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION"
            )
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        (device_priv_key, device_pub_key) = ecc.generate_key_pair()

        # RAM
        self.shared_data.this_device.device_priv_key = device_priv_key
        self.shared_data.this_device.device_pub_key = device_pub_key

        ######################################################
        # Initialize Device Owner
        ######################################################
        # RAM
        self.shared_data.this_device.owner_pub_key = str_to_key(
            u_ticket_in.holder_id, "ecc-public-key"
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    # @measure_worker_func
    def _execute_ownership_transfer(self, new_u_ticket: UTicket) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is transferring ownership...",
        )

        ######################################################
        # Update Device Owner
        ######################################################
        # RAM
        self.shared_data.this_device.owner_pub_key = str_to_key(
            new_u_ticket.holder_id, key_type="ecc-public-key"
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    # CR-KE
    @measure_worker_func
    def _execute_cr_ke(
        self, ticket_in: Union[UTicket, RTicket], comm_end: str, cmd: str = ""
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is updating current session...",
        )
        if (
            type(ticket_in) == UTicket
            and ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
        ) or (
            type(ticket_in) == UTicket
            and ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
        ):
            if comm_end == "holder":
                # Update Session: Access UT
                self.shared_data.current_session.current_u_ticket_id = (
                    ticket_in.u_ticket_id
                )
                self.shared_data.current_session.current_device_id = ticket_in.device_id
                self.shared_data.current_session.current_holder_id = ticket_in.holder_id
                self.shared_data.current_session.current_task_scope = (
                    ticket_in.task_scope
                )
                # Update Session: PS-Cmd (Input: Plaintext, Associated-Plaintext)
                self._execute_ps(executing_case="send-ut", plaintext=cmd)
            elif comm_end == "device":
                # Update Session: Access UT
                self.shared_data.current_session.current_u_ticket_id = (
                    ticket_in.u_ticket_id
                )
                self.shared_data.current_session.current_device_id = ticket_in.device_id
                self.shared_data.current_session.current_holder_id = ticket_in.holder_id
                self.shared_data.current_session.current_task_scope = (
                    ticket_in.task_scope
                )
                # Update Session: CR
                self.shared_data.current_session.challenge_1 = ecdh.generate_random_str(
                    32
                )
                # Update Session: KE
                self.shared_data.current_session.key_exchange_salt_1 = (
                    ecdh.generate_random_str(32)
                )
                # Update Session: PS-Cmd
                self._execute_ps(executing_case="recv-ut-and-send-crke1")
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
        ):
            # Update Session: CR
            self.shared_data.current_session.challenge_1 = ticket_in.challenge_1
            self.shared_data.current_session.challenge_2 = ecdh.generate_random_str(32)
            # Update Session: KE
            self.shared_data.current_session.key_exchange_salt_1 = (
                ticket_in.key_exchange_salt_1
            )
            self.shared_data.current_session.key_exchange_salt_2 = (
                ecdh.generate_random_str(32)
            )
            # print(self.shared_data.current_session.current_device_id)
            # Update Session: KE
            current_session_key_byte = self._execute_generate_session_key(
                salt_1=self.shared_data.current_session.key_exchange_salt_1,
                salt_2=self.shared_data.current_session.key_exchange_salt_2,
                server_priv_key=self.shared_data.this_person.person_priv_key,
                peer_pub_key=str_to_key(
                    self.shared_data.current_session.current_device_id,
                    "ecc-public-key",
                ),
            )
            self.shared_data.current_session.current_session_key_str = (
                byte_to_base64str(current_session_key_byte)
            )
            # Update Session: PS-Cmd
            self._execute_ps(
                executing_case="recv-crke1-and-send-crke2", ticket_in=ticket_in
            )
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET
        ):
            # Update Session: CR
            self.shared_data.current_session.challenge_2 = ticket_in.challenge_2
            # Update Session: KE
            self.shared_data.current_session.key_exchange_salt_2 = (
                ticket_in.key_exchange_salt_2
            )
            # Update Session: KE
            current_session_key_byte = self._execute_generate_session_key(
                salt_1=self.shared_data.current_session.key_exchange_salt_1,
                salt_2=ticket_in.key_exchange_salt_2,
                server_priv_key=self.shared_data.this_device.device_priv_key,
                peer_pub_key=str_to_key(
                    self.shared_data.current_session.current_holder_id,
                    "ecc-public-key",
                ),
            )
            self.shared_data.current_session.current_session_key_str = (
                byte_to_base64str(current_session_key_byte)
            )
            # Update Session: PS-Cmd
            self._execute_ps(executing_case="recv-crke2", ticket_in=ticket_in)
            # Data Processing
            (plaintext_data, associated_plaintext_data) = self._execute_data_processing(
                self.shared_data.current_session.plaintext_cmd,
                self.shared_data.current_session.associated_plaintext_cmd,
            )
            # Update Session: PS-Data
            self._execute_ps(
                executing_case="send-crke3",
                ticket_in=ticket_in,
                plaintext=plaintext_data,
                associated_plaintext=associated_plaintext_data,
            )
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
        ):
            # Update Session: PS-Data
            self._execute_ps(executing_case="recv-crke3", ticket_in=ticket_in)
        else:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        ######################################################
        # Storage (Persistent vs. RAM-only)
        ######################################################
        # self.simple_storage.store_storage(
        #     self.shared_data.this_device, self.shared_data.device_table, self.shared_data.this_person, self.shared_data.current_session
        # )

    # @measure_worker_func
    def _execute_generate_session_key(
        self,
        salt_1: str,
        salt_2: str,
        server_priv_key: ec.EllipticCurvePrivateKey,
        peer_pub_key: ec.EllipticCurvePublicKey,
    ) -> bytes:
        salt_1_byte = base64str_backto_byte(salt_1)
        salt_2_byte = base64str_backto_byte(salt_2)
        # # Bitweise AND operation (python operates bit through int, & bytes is int arrary)
        # type(salt_1[0])  # = int
        # salt_1_bit = "".join(format(byte, "08b") for byte in salt_1)
        # simple_log("debug", f"salt_1_bit = {salt_1_bit}")
        # salt_2_bit = "".join(format(byte, "08b") for byte in salt_2)
        # simple_log("debug", f"salt_2_bit = {salt_2_bit}")
        # shared_salt_bit = "".join(format(byte, "08b") for byte in shared_salt)
        # simple_log("debug", f"share_salt = {shared_salt_bit}")
        # simple_log("debug", f"share_salt length (byte) = {len(shared_salt_bit)}")
        shared_salt_byte = bytes(
            [salt_1_byte[i] & salt_2_byte[i] for i in range(len(salt_1_byte))]
        )
        # len(shared_salt)  # = 32 bytes
        current_session_key: bytes = ecdh.generate_ecdh_key(
            server_private_key=server_priv_key,
            salt=shared_salt_byte,
            info=None,
            peer_public_key=peer_pub_key,
        )
        # len(current_session_key)  # = 32 bytes
        return current_session_key

    # PS
    @measure_worker_func
    def _execute_ps(
        self,
        executing_case: str,
        ticket_in: Union[None, UTicket, RTicket] = None,
        plaintext: Optional[str] = None,
        associated_plaintext: Optional[str] = None,
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is updating current session...",
        )

        # CR-KE
        if executing_case == "send-ut":
            # Update Session: PS-Cmd (Input: Plaintext, Associated-Plaintext)
            self.shared_data.current_session.plaintext_cmd = plaintext
            self.shared_data.current_session.associated_plaintext_cmd = (
                "AUC"
            )
        elif executing_case == "recv-ut-and-send-crke1":
            # Update Session: Next-IV
            self.shared_data.current_session.iv_cmd = self._gen_next_iv()
        elif executing_case == "recv-crke1-and-send-crke2":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            self.shared_data.current_session.iv_cmd = ticket_in.iv_cmd
            # Update Session: PS-Cmd (Input: Plaintext, Associated-Plaintext)
            # Update Session: PS-Cmd (Encyrption)
            (ciphertext, gcm_authentication_tag) = self._execute_encrypt_plaintext(
                plaintext=self.shared_data.current_session.plaintext_cmd,
                associated_plaintext=self.shared_data.current_session.associated_plaintext_cmd,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_cmd,
            )
            # Update Session: PS-Cmd (Output: Ciphertext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_cmd = ciphertext
            self.shared_data.current_session.gcm_authentication_tag_cmd = (
                gcm_authentication_tag
            )
            # Update Session: Next-IV
            self.shared_data.current_session.iv_data = self._gen_next_iv()
        elif executing_case == "recv-crke2":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            # Update Session: PS-Cmd (Input: Ciphertext, Associated-Plaintext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_cmd = ticket_in.ciphertext_cmd
            self.shared_data.current_session.associated_plaintext_cmd = (
                ticket_in.associated_plaintext_cmd
            )
            self.shared_data.current_session.gcm_authentication_tag_cmd = (
                ticket_in.gcm_authentication_tag_cmd
            )
            # [STAGE: (VTK)(VTS)]
            # Update Session: PS-Cmd (Decyrption)
            plaintext_cmd = self._execute_decrypt_ciphertext(
                ciphertext=self.shared_data.current_session.ciphertext_cmd,
                associated_plaintext=self.shared_data.current_session.associated_plaintext_cmd,
                gcm_authentication_tag=self.shared_data.current_session.gcm_authentication_tag_cmd,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_cmd,
            )
            self.msg_verifier.verify_cmd_is_in_task_scope(plaintext_cmd)
            # Update Session: PS-Cmd (Output: Plaintext)
            self.shared_data.current_session.plaintext_cmd = plaintext_cmd
        elif executing_case == "send-crke3":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            self.shared_data.current_session.iv_data = ticket_in.iv_data
            # Update Session: PS-Data (Input: Plaintext, Associated-Plaintext)
            self.shared_data.current_session.plaintext_data = plaintext
            self.shared_data.current_session.associated_plaintext_data = (
                associated_plaintext
            )
            # Update Session: PS-Data (Encyrption)
            (ciphertext, gcm_authentication_tag) = self._execute_encrypt_plaintext(
                plaintext=self.shared_data.current_session.plaintext_data,
                associated_plaintext=self.shared_data.current_session.associated_plaintext_data,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_data,
            )
            # Update Session: PS-Data (Output: Ciphertext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_data = ciphertext
            self.shared_data.current_session.gcm_authentication_tag_data = (
                gcm_authentication_tag
            )
            # Update Session: Next-IV
            self.shared_data.current_session.iv_cmd = self._gen_next_iv()
        elif executing_case == "recv-crke3":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            self.shared_data.current_session.iv_cmd = ticket_in.iv_cmd
            # Update Session: PS-Data (Input: Ciphertext, Associated-Plaintext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_data = ticket_in.ciphertext_data
            self.shared_data.current_session.associated_plaintext_data = (
                ticket_in.associated_plaintext_data
            )
            self.shared_data.current_session.gcm_authentication_tag_data = (
                ticket_in.gcm_authentication_tag_data
            )
            # [STAGE: (VTK)]
            # Update Session: PS-Data (Decyrption)
            plaintext_data = self._execute_decrypt_ciphertext(
                ciphertext=self.shared_data.current_session.ciphertext_data,
                associated_plaintext=self.shared_data.current_session.associated_plaintext_data,
                gcm_authentication_tag=self.shared_data.current_session.gcm_authentication_tag_data,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_data,
            )
            # Update Session: PS-Data (Output: Plaintext)
            self.shared_data.current_session.plaintext_data = plaintext_data
        # PS
        elif executing_case == "send-utoken":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            # Update Session: PS-Cmd (Input: Plaintext, Associated-Plaintext)
            self.shared_data.current_session.plaintext_cmd = plaintext
            self.shared_data.current_session.associated_plaintext_cmd = (
                "AUC"
            )
            # Update Session: PS-Cmd (Encyrption)
            (ciphertext, gcm_authentication_tag) = self._execute_encrypt_plaintext(
                plaintext=self.shared_data.current_session.plaintext_cmd,
                associated_plaintext=self.shared_data.current_session.associated_plaintext_cmd,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_cmd,
            )
            # Update Session: PS-Cmd (Output: Ciphertext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_cmd = ciphertext
            self.shared_data.current_session.gcm_authentication_tag_cmd = (
                gcm_authentication_tag
            )
            # Update Session: Next-IV
            self.shared_data.current_session.iv_data = self._gen_next_iv()
        elif executing_case == "recv-utoken":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            # Update Session: PS-Cmd (Input: Ciphertext, Associated-Plaintext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_cmd = ticket_in.ciphertext_cmd
            self.shared_data.current_session.associated_plaintext_cmd = (
                ticket_in.associated_plaintext_cmd
            )
            self.shared_data.current_session.gcm_authentication_tag_cmd = (
                ticket_in.gcm_authentication_tag_cmd
            )
            # [STAGE: (VTK)(VTS)]
            # Update Session: PS-Cmd (Decyrption)
            plaintext_cmd = self._execute_decrypt_ciphertext(
                ciphertext=self.shared_data.current_session.ciphertext_cmd,
                associated_plaintext=self.shared_data.current_session.associated_plaintext_cmd,
                gcm_authentication_tag=self.shared_data.current_session.gcm_authentication_tag_cmd,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_cmd,
            )
            if ticket_in.u_ticket_type != u_ticket.TYPE_ACCESS_END_UTOKEN:
                self.msg_verifier.verify_cmd_is_in_task_scope(plaintext_cmd)
                
            # Update Session: PS-Cmd (Output: Plaintext)
            self.shared_data.current_session.plaintext_cmd = plaintext_cmd
        elif executing_case == "send-rtoken":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            self.shared_data.current_session.iv_data = ticket_in.iv_data
            # Update Session: PS-Data (Input: Plaintext, Associated-Plaintext)
            self.shared_data.current_session.plaintext_data = plaintext
            self.shared_data.current_session.associated_plaintext_data = (
                associated_plaintext
            )
            # Update Session: PS-Data (Encyrption)
            (ciphertext, gcm_authentication_tag) = self._execute_encrypt_plaintext(
                plaintext=plaintext,
                associated_plaintext=associated_plaintext,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_data,
            )
            # Update Session: PS-Data (Output: Ciphertext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_data = ciphertext
            self.shared_data.current_session.gcm_authentication_tag_data = (
                gcm_authentication_tag
            )
            # Update Session: Next-IV
            self.shared_data.current_session.iv_cmd = self._gen_next_iv()
        elif executing_case == "recv-rtoken":
            # Update Session: PS-Cmd (Input: Key)
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Cmd (Input: This-IV)
            self.shared_data.current_session.iv_cmd = ticket_in.iv_cmd
            # Update Session: PS-Data (Input: Ciphertext, Associated-Plaintext, GCM-Authentication-Tag)
            self.shared_data.current_session.ciphertext_data = ticket_in.ciphertext_data
            self.shared_data.current_session.associated_plaintext_data = (
                ticket_in.associated_plaintext_data
            )
            self.shared_data.current_session.gcm_authentication_tag_data = (
                ticket_in.gcm_authentication_tag_data
            )
            # [STAGE: (VTK)]
            # Update Session: PS-Data (Decyrption)
            plaintext_data = self._execute_decrypt_ciphertext(
                ciphertext=self.shared_data.current_session.ciphertext_data,
                associated_plaintext=self.shared_data.current_session.associated_plaintext_data,
                gcm_authentication_tag=self.shared_data.current_session.gcm_authentication_tag_data,
                session_key=current_session_key_byte,
                iv=self.shared_data.current_session.iv_data,
            )
            # Update Session: PS-Data (Output: Plaintext)
            self.shared_data.current_session.plaintext_data = plaintext_data
        else:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        # simple_log(
        #     "debug",
        #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
        # )

        ######################################################
        # Storage (Persistent vs. RAM-only)
        ######################################################
        # self.simple_storage.store_storage(
        #     self.shared_data.this_device, self.shared_data.device_table, self.shared_data.this_person, self.shared_data.current_session
        # )

    # @measure_worker_func
    def _gen_next_iv(self) -> str:
        return byte_to_base64str(ecdh.gcm_gen_iv())

    # @measure_worker_func
    def _execute_encrypt_plaintext(
        self,
        plaintext: str,
        associated_plaintext: str,
        session_key: bytes,
        iv: str = "",
    ) -> Tuple[str, str, str]:
        plaintext_byte: bytes = str_to_byte(plaintext)
        associated_plaintext_byte: bytes = str_to_byte(associated_plaintext)
        iv_byte: bytes = base64str_backto_byte(iv)
        (ciphertext_byte, gcm_authentication_tag_byte) = ecdh.gcm_encrypt(
            plaintext_byte, associated_plaintext_byte, session_key, iv_byte
        )
        ciphertext = byte_to_base64str(ciphertext_byte)
        gcm_authentication_tag = byte_to_base64str(gcm_authentication_tag_byte)

        return (ciphertext, gcm_authentication_tag)

    # @measure_worker_func
    def _execute_decrypt_ciphertext(
        self,
        ciphertext: str,
        associated_plaintext: str,
        gcm_authentication_tag: str,
        session_key: bytes,
        iv: str,
    ) -> str:
        # [STAGE: (VTK)] Verify HMAC before Execution
        try:
            ciphertext_byte: bytes = base64str_backto_byte(ciphertext)
            associated_plaintext_byte: bytes = str_to_byte(associated_plaintext)
            gcm_authentication_tag_byte: bytes = base64str_backto_byte(
                gcm_authentication_tag
            )
            iv_byte: bytes = base64str_backto_byte(iv)
            # print("iv_byte", iv_byte)
            # verify_token_through_hmac
            plaintext_byte: bytes = ecdh.gcm_decrypt(
                ciphertext_byte,
                associated_plaintext_byte,
                gcm_authentication_tag_byte,
                session_key,
                iv_byte,
            )

            plaintext: str = byte_backto_str(plaintext_byte)

            # print("plaintext from voting machine", plaintext)

            self.shared_data.result_message = f"-> SUCCESS: VERIFY_IV_AND_HMAC"
            simple_log("info", self.shared_data.result_message)

            return plaintext

        except InvalidTag:
            self.shared_data.result_message = f"-> FAILURE: VERIFY_IV_AND_HMAC"
            simple_log("error", self.shared_data.result_message)
            raise RuntimeError(self.shared_data.result_message)

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

    # Execute Application & Data Processing
    # @measure_worker_func
    def _execute_data_processing(
        self, plaintext_cmd: str, associated_plaintext_cmd: str
    ) -> Tuple[str, str]:
        simple_log(
            "debug",
            f"+ {self.shared_data.this_device.device_name} is executing application...",
        )

        plaintext_data = f"DATA: {plaintext_cmd}"
        associated_plaintext_cmd = f"DATA: {associated_plaintext_cmd}"

        return (plaintext_data, associated_plaintext_cmd)

    ######################################################
    # [STAGE: (O)] Update Ticket Order
    #   Update Ticket Order after:
    #       "has-type": Intial Ticket Order = 0
    #       "agent-initialization": Ticket Order = 1 after device/agent is initialized
    #       "holder-generate-or-receive-uticket": Generate or Receive UTicket (expected ticket order)
    #       "device-verify-uticket": Verify UTicket & End TX (actual ticket order)
    #       "holder-or-issuer-verify-rticket": Verify RTicket (actual ticket order)
    ######################################################
    @measure_worker_func
    def _execute_update_ticket_order(
        self, updating_case: str, ticket_in: Union[UTicket, RTicket] = None
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is updating ticket order... + {updating_case}",
        )

        if updating_case == "has-type":
            self.shared_data.this_device.ticket_order = 0
        elif updating_case == "agent-initialization":
            self.shared_data.this_device.ticket_order = (
                self.shared_data.this_device.ticket_order + 1
            )
        elif updating_case == "holder-generate-or-receive-uticket":
            # Recieve UTicket
            if type(ticket_in) == UTicket and (
                ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                self.shared_data.device_table[
                    ticket_in.device_id
                ].ticket_order = ticket_in.ticket_order
                simple_log(
                    "debug",
                    f"{self.shared_data.this_device.device_name}: Predicted ticket_order={self.shared_data.device_table[ticket_in.device_id].ticket_order}",
                )
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
        elif updating_case == "device-verify-uticket":
            # Execute UTicket
            if type(ticket_in) == UTicket and (
                ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
            ):
                self.shared_data.this_device.ticket_order = (
                    self.shared_data.this_device.ticket_order + 1
                )
                simple_log(
                    "debug",
                    f"{self.shared_data.this_device.device_name}: Updated ticket_order={self.shared_data.this_device.ticket_order}",
                )
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
        elif updating_case == "holder-or-issuer-verify-rticket":
            # Execute UTicket
            if type(ticket_in) == RTicket and (
                ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
            ):
                self.shared_data.device_table[
                    ticket_in.device_id
                ].ticket_order = ticket_in.ticket_order
                simple_log(
                    "debug",
                    f"{self.shared_data.this_device.device_name}: Updated ticket_order={self.shared_data.device_table[ticket_in.device_id].ticket_order}",
                )
            else:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
        else:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    ######################################################
    # [STAGE: (C)] Change Reciever State
    ######################################################
    @measure_worker_func
    def _change_state(self, new_state: str) -> None:
        self.shared_data.state = new_state
