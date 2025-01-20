# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData

# Data Model (Message)
from ureka_framework.model.message_model.u_ticket import u_ticket_to_jsonstr
from ureka_framework.model.message_model.r_ticket import r_ticket_to_jsonstr

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Stage Worker
from ureka_framework.logic.stage_worker.msg_generator_u_ticket import UTicketGenerator
from ureka_framework.logic.stage_worker.msg_generator_r_ticket import RTicketGenerator

# Measure Helper
from ureka_framework.logic.stage_worker.measure_helper import MeasureHelper


class MsgGenerator:
    def __init__(
        self,
        shared_data: SharedData,
        measure_helper: MeasureHelper,
    ) -> None:
        self.shared_data = shared_data
        self.measure_helper = measure_helper

    ######################################################
    # [STAGE: (G)] Generate Message
    ######################################################
    @measure_worker_func
    def _generate_xxx_u_ticket(self, arbitrary_dict: dict) -> str:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is generating u_ticket...",
        )

        u_ticket_generator = UTicketGenerator(
            self.shared_data.this_device,
            self.shared_data.this_person,
            self.shared_data.device_table,
        )
        generated_u_ticket = u_ticket_generator.generate_arbitrary_u_ticket(
            arbitrary_dict
        )
        generated_u_ticket_json = u_ticket_to_jsonstr(generated_u_ticket)

        return generated_u_ticket_json

    @measure_worker_func
    def _generate_xxx_r_ticket(self, arbitrary_dict: dict) -> str:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is generating r_ticket...",
        )

        r_ticket_generator = RTicketGenerator(
            self.shared_data.this_device,
            self.shared_data.this_person,
            self.shared_data.device_table,
        )
        generated_r_ticket = r_ticket_generator.generate_arbitrary_r_ticket(
            arbitrary_dict
        )
        generated_r_ticket_json = r_ticket_to_jsonstr(generated_r_ticket)

        return generated_r_ticket_json
