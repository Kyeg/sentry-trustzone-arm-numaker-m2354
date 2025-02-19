# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
from ureka_framework.model.data_model.other_device import OtherDevice

# Data Model (Message)
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import jsonstr_to_u_ticket

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Measure Helper
from ureka_framework.logic.stage_worker.measure_helper import MeasureHelper


class GeneratedMsgStorer:
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
    # [STAGE: (SG)] Store Generated Message
    ######################################################
    @measure_worker_func
    def _store_generated_xxx_u_ticket(self, generated_u_ticket_json: str) -> None:
        try:
            # [STAGE: (VR)]
            generated_u_ticket = jsonstr_to_u_ticket(generated_u_ticket_json)

            # Because device hasn't created the id yet,
            #   we temporary store Initialization UTicket in device_table["no_id"]
            #   and the device_table will be updated by its RTicket with newly-created device_id
            if generated_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
                # Holder (for Owner)
                device_id_for_initialization_u_ticket = "no_id"
                self.shared_data.device_table[
                    device_id_for_initialization_u_ticket
                ] = OtherDevice(
                    device_id=device_id_for_initialization_u_ticket,
                    device_u_ticket_for_owner=generated_u_ticket_json,
                )
            elif generated_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
                # Issuer (for Others)
                # Not create new table, just add u_ticket to existing table
                device_id_for_u_ticket = generated_u_ticket.device_id
                self.shared_data.device_table[
                    device_id_for_u_ticket
                ].device_ownership_u_ticket_for_others = generated_u_ticket_json
            elif generated_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET:
                # Holder (for Owner)
                # Not create new table, just add u_ticket to existing table
                device_id_for_u_ticket = generated_u_ticket.device_id
                self.shared_data.device_table[
                    generated_u_ticket.device_id
                ].device_u_ticket_for_owner = generated_u_ticket_json
            elif generated_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
                # Issuer (for Others)
                # Not create new table, just add u_ticket to existing table
                device_id_for_u_ticket = generated_u_ticket.device_id
                self.shared_data.device_table[
                    device_id_for_u_ticket
                ].device_access_u_ticket_for_others = generated_u_ticket_json
            else:  # pragma: no cover -> TODO: Revocation UTicket
                raise RuntimeError(f"Not implemented yet")

            ######################################################
            # Storage
            ######################################################
            self.simple_storage.store_storage(
                self.shared_data.this_device,
                self.shared_data.device_table,
                self.shared_data.this_person,
                self.shared_data.current_session,
            )

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
            self.shared_data.result_message = f"{error}"
            raise RuntimeError(f"{error}")

        except:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")
