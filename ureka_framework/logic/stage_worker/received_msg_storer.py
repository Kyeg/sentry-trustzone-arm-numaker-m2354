# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
from ureka_framework.model.data_model.other_device import OtherDevice

# Data Model (Message)
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import (
    UTicket,
    u_ticket_to_jsonstr,
)
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.message_model.r_ticket import (
    RTicket,
    r_ticket_to_jsonstr,
)

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Measure Helper
from ureka_framework.logic.stage_worker.measure_helper import MeasureHelper


class ReceivedMsgStorer:
    def __init__(
        self,
        shared_data: SharedData,
        measure_helper: MeasureHelper,
        simple_storage: SimpleStorage,
    ) -> None:
        self.shared_data = shared_data
        self.measure_helper = measure_helper
        self.simple_storage = simple_storage

    ######################################################
    # [STAGE: (SR)] Store Received Message
    ######################################################
    @measure_worker_func
    def _store_received_xxx_u_ticket(self, received_u_ticket: UTicket) -> None:
        try:
            received_u_ticket_json = u_ticket_to_jsonstr(received_u_ticket)

            # We store this UTicket in device_table["device_id"]
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                # or received_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                self.shared_data.device_table[
                    received_u_ticket.device_id
                ] = OtherDevice(
                    device_id=received_u_ticket.device_id,
                    device_u_ticket_for_owner=received_u_ticket_json,
                )
            # Normally, we do not forward Initialization UTicket
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

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

    @measure_worker_func
    def _store_received_xxx_r_ticket(self, received_r_ticket: RTicket) -> None:
        try:
            received_r_ticket_json = r_ticket_to_jsonstr(received_r_ticket)

            # We store this RTicket (but not verified) in device_table["device_id"]
            if received_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
                # Holder (for Owner)
                # Create new table by newly-created device public key
                created_device_id = received_r_ticket.device_id
                # Put u_ticket (temporary in device_table["no_id"]) & r_ticket in device_table["created_device_id"]
                self.shared_data.device_table[created_device_id] = OtherDevice(
                    device_id=created_device_id,
                    ticket_order = received_r_ticket.ticket_order,
                    device_u_ticket_for_owner=self.shared_data.device_table[
                        "no_id"
                    ].device_u_ticket_for_owner,
                    device_r_ticket_for_owner=received_r_ticket_json,
                )
            elif received_r_ticket.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
                # Holder (for Owner)
                if (
                    self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_ownership_u_ticket_for_others
                    == None
                ):
                    # Not create new table, just add r_ticket to existing table
                    self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_r_ticket_for_owner = received_r_ticket_json
                # Issuer (for Others)
                else:
                    # Not create new table, just add r_ticket to existing table
                    self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_ownership_r_ticket_for_others = received_r_ticket_json
            elif received_r_ticket.r_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN:
                # Holder (for Owner)
                if (
                    self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_access_u_ticket_for_others
                    == None
                ):
                    # Not create new table, just add r_ticket to existing table
                    self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_r_ticket_for_owner = received_r_ticket_json
                # Issuer (for Others)
                else:
                    # Not create new table, just add r_ticket to existing table
                    self.shared_data.device_table[
                        received_r_ticket.device_id
                    ].device_access_end_r_ticket_for_others = received_r_ticket_json
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

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")
