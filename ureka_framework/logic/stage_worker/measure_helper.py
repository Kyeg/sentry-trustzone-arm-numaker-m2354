# Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import (
    start_process_timer,
    start_perf_timer,
    get_process_time,
    get_perf_time,
    start_comm_timer,
    get_comm_time,
    simple_size_calculator,
)


class MeasureHelper:
    def __init__(self, shared_data: SharedData) -> None:
        self.shared_data = shared_data

    ######################################################
    # Measurement Helper:
    #   Process Response Time
    ######################################################
    @measure_worker_func
    def measure_process_perf_start(self) -> None:
        start_process_timer()
        start_perf_timer()

    @measure_worker_func
    def measure_recv_cli_perf_time(self, cli_name: str) -> None:
        # Response Time
        cli_process_time: float = get_process_time()
        cli_perf_time: float = get_perf_time()
        cli_blocked_time: float = abs(cli_perf_time - cli_process_time)

        # Collect Measurement Raw Data
        if self.shared_data.measure_rec.get(cli_name) is None:
            self.shared_data.measure_rec[cli_name] = {}
        # Record cli_perf_time
        self.shared_data.measure_rec[cli_name]["cli_perf_time"] = cli_perf_time
        self.shared_data.measure_rec[cli_name]["cli_blocked_time"] = cli_blocked_time
        # simple_log("measure", f"measure_rec = {self.shared_data.measure_rec}")

        # Print Measurement Raw Data
        simple_log("measure", f"")
        simple_log("measure", f"+ Receive CLI Input: {cli_name}")
        simple_log(
            "measure",
            f"cli_perf_time = {cli_perf_time:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )
        if cli_blocked_time > Environment.IO_BLOCKING_TOLERANCE_TIME:
            simple_log("warning", f"+ PROC I/O MAYBE BLOCKED TOO LONG...")
            simple_log(
                "warning",
                f"cli_blocked_time = {cli_blocked_time:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

    @measure_worker_func
    def measure_recv_msg_perf_time(self, comm_name: str) -> None:
        # Response Time
        msg_process_time: float = get_process_time()
        msg_perf_time: float = get_perf_time()
        msg_blocked_time: float = abs(msg_perf_time - msg_process_time)

        # Collect Measurement Raw Data
        if self.shared_data.measure_rec.get(comm_name) is None:
            self.shared_data.measure_rec[comm_name] = {}
        # Record msg_perf_time
        self.shared_data.measure_rec[comm_name]["msg_perf_time"] = msg_perf_time
        self.shared_data.measure_rec[comm_name]["msg_blocked_time"] = msg_blocked_time
        # Record cached comm_time & message_size
        if (
            self.shared_data.measure_rec.get("_recv_message") is not None
            and self.shared_data.measure_rec.get("_recv_message").get("comm_time")
            is not None
        ):
            self.shared_data.measure_rec[comm_name][
                "comm_time"
            ] = self.shared_data.measure_rec["_recv_message"]["comm_time"]
        if (
            self.shared_data.measure_rec.get("_recv_message") is not None
            and self.shared_data.measure_rec.get("_recv_message").get("message_size")
            is not None
        ):
            self.shared_data.measure_rec[comm_name][
                "message_size"
            ] = self.shared_data.measure_rec["_recv_message"]["message_size"]
        # simple_log("measure", f"measure_rec = {self.shared_data.measure_rec}")

        # Print Measurement Raw Data
        simple_log(
            "measure",
            f"msg_perf_time = {msg_perf_time:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )
        if msg_blocked_time > Environment.IO_BLOCKING_TOLERANCE_TIME:
            simple_log("warning", f"+ PROC I/O MAYBE BLOCKED TOO LONG...")
            simple_log(
                "warning",
                f"msg_blocked_time = {msg_blocked_time:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )
        simple_log("measure", f"+ Receive Message Input: {comm_name}")
        simple_log("measure", f"")

    ######################################################
    # Measurement Helper:
    #   Comm Response Time
    ######################################################
    @measure_worker_func
    def measure_comm_perf_start(self) -> None:
        start_comm_timer()

    @measure_worker_func
    def measure_comm_time(self, comm_name: str) -> None:
        # Response Time
        comm_time: float = get_comm_time()

        # Collect Measurement Raw Data
        if self.shared_data.measure_rec.get(comm_name) is None:
            self.shared_data.measure_rec[comm_name] = {}
        # Cache comm_time
        self.shared_data.measure_rec[comm_name]["comm_time"] = comm_time
        # simple_log("measure", f"measure_rec = {self.shared_data.measure_rec}")

        # Print Measurement Raw Data
        simple_log("measure", f"")
        simple_log("measure", f"+ Receive Comm Input: {comm_name}")
        simple_log(
            "measure",
            f"comm_time = {comm_time:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )
        if comm_time > Environment.COMM_BLOCKING_TOLERANCE_TIME:
            simple_log("warning", f"+ COMM I/O MAYBE BLOCKED TOO LONG...")
            simple_log(
                "warning",
                f"comm_time = {comm_time:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

    ######################################################
    # Measurement Helper:
    #   Data Size
    ######################################################
    @measure_worker_func
    def measure_message_size(
        self, comm_name: str, received_message_with_header: str
    ) -> None:
        # Data Size
        message_size: int = simple_size_calculator(received_message_with_header)

        # Collect Measurement Raw Data
        if self.shared_data.measure_rec.get(comm_name) is None:
            self.shared_data.measure_rec[comm_name] = {}
        # Cache message_size
        self.shared_data.measure_rec[comm_name]["message_size"] = message_size
        # simple_log("measure", f"measure_rec = {self.shared_data.measure_rec}")

        # Print Measurement Raw Data
        simple_log("measure", f"message_size = {message_size} bytes")
