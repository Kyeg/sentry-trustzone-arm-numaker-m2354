# Deployment Environment
from ureka_framework.environment import Environment

# timer
import time

# function stack
import inspect

# TYPE HINTS
from typing import Callable

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log


######################################################
# Decorator
######################################################
MAX_FUNC_NAME_LENGTH: int = 50


def measure_worker_func(func_to_be_measured: Callable):
    def measured_worker_func(*args, **kwargs):
        # Open/Close the @Decorator
        if Environment.MORE_MEASURE_WORKER_LOG == "OPEN":
            # Measurement
            start_process_time = time.process_time()
            start_perf_time = time.perf_counter()
            result = func_to_be_measured(*args, **kwargs)
            end_process_time = time.process_time()
            end_perf_time = time.perf_counter()
            elapsed_perf_time = end_perf_time - start_perf_time
            elapsed_process_time = end_process_time - start_process_time
            elapsed_block_time = abs(elapsed_perf_time - elapsed_process_time)

            # Measurement Log
            func_name = func_to_be_measured.__name__

            # Function Stack
            caller_name = ""
            caller_frame = inspect.currentframe().f_back
            caller_name = inspect.getframeinfo(caller_frame).function

            # Can opitionally set Threshold: Only show blocking overhead large enough to be noticed
            if (
                elapsed_block_time
                >= Environment.MORE_MEASUREMENT_BLOCKING_THRESHOLD_TIME
            ):
                print(
                    f"[M-WORKER] : block_time = {caller_name:>{MAX_FUNC_NAME_LENGTH}} -> {func_name:>{MAX_FUNC_NAME_LENGTH}}"
                    f" : {elapsed_block_time:>{Environment.MORE_MEASUREMENT_TIME_PRECISION}} seconds"
                )

            # Can opitionally set Threshold: Only show overhead large enough to be noticed
            # if elapsed_perf_time >= Environment.MORE_MEASUREMENT_PERF_THRESHOLD_TIME:
            #     print(
            #         f"[M-WORKER] :  perf_time = {caller_name:>{MAX_FUNC_NAME_LENGTH}} -> {func_name:>{MAX_FUNC_NAME_LENGTH}}"
            #         f" : {elapsed_perf_time:>{Environment.MORE_MEASUREMENT_TIME_PRECISION}} seconds"
            #     )

            return result
        else:
            return func_to_be_measured(*args, **kwargs)

    return measured_worker_func


def measure_resource_func(func_to_be_measured: Callable):
    def measured_resource_func(*args, **kwargs):
        # Open/Close the @Decorator
        if Environment.MORE_MEASURE_RESOURCE_LOG == "OPEN":
            # Measurement
            start_process_time = time.process_time()
            start_perf_time = time.perf_counter()
            result = func_to_be_measured(*args, **kwargs)
            end_process_time = time.process_time()
            end_perf_time = time.perf_counter()
            elapsed_perf_time = end_perf_time - start_perf_time
            elapsed_process_time = end_process_time - start_process_time
            elapsed_block_time = abs(elapsed_perf_time - elapsed_process_time)

            # Measurement Log
            func_name = func_to_be_measured.__name__

            # Function Stack
            caller_name = ""
            caller_frame = inspect.currentframe().f_back
            caller_name = inspect.getframeinfo(caller_frame).function

            # # Deeper Function Stack
            # caller2_name = ""
            # if caller_name != "<module>":
            #     caller2_frame = inspect.currentframe().f_back.f_back
            #     caller2_name = inspect.getframeinfo(caller2_frame).function
            #     if caller2_name != "<module>":
            #         caller3_frame = inspect.currentframe().f_back.f_back.f_back
            #         caller3_name = inspect.getframeinfo(caller3_frame).function

            # Can opitionally set Threshold: Only show blocking overhead large enough to be noticed
            if (
                elapsed_block_time
                >= Environment.MORE_MEASUREMENT_BLOCKING_THRESHOLD_TIME
            ):
                print(
                    f"[M-WORKER] : block_time = {caller_name:>{MAX_FUNC_NAME_LENGTH}} -> {func_name:>{MAX_FUNC_NAME_LENGTH}}"
                    f" : {elapsed_block_time:>{Environment.MORE_MEASUREMENT_TIME_PRECISION}} seconds"
                )

            # Can opitionally set Threshold: Only show overhead large enough to be noticed
            if elapsed_perf_time >= Environment.MORE_MEASUREMENT_PERF_THRESHOLD_TIME:
                print(
                    f"[M-WORKER] :  perf_time = {caller_name:>{MAX_FUNC_NAME_LENGTH}} -> {func_name:>{MAX_FUNC_NAME_LENGTH}}"
                    f" : {elapsed_perf_time:>{Environment.MORE_MEASUREMENT_TIME_PRECISION}} seconds"
                )

            return result
        else:
            return func_to_be_measured(*args, **kwargs)

    return measured_resource_func


######################################################
# Response Time Measurement (Process)
######################################################
# start timer
start_process: float = 0.0
start_perf_counter: float = 0.0

# ...
# time-consuming processing...
# ...

# end timer
end_process: float = 0.0
end_perf_counter: float = 0.0

# elapsed time
elapsed_process_time: float = 0.0
elapsed_perf_time: float = 0.0


def start_process_timer() -> None:
    global start_process

    start_process = time.process_time()


def start_perf_timer() -> None:
    global start_perf_counter

    start_perf_counter = time.perf_counter()


def get_process_time() -> float:
    global start_process
    global elapsed_process_time

    end_process = time.process_time()

    elapsed_process_time = end_process - start_process
    return elapsed_process_time


def get_perf_time() -> float:
    global start_perf_counter
    global elapsed_perf_time

    end_perf_counter = time.perf_counter()

    elapsed_perf_time = end_perf_counter - start_perf_counter
    return elapsed_perf_time


######################################################
# Response Time Measurement (RTT-based Comm.)
######################################################
# start timer
start_comm: float = 0.0

# ...
# time-consuming processing...
# ...

# end timer
end_comm: float = 0.0
elapsed_comm_time: float = 0.0


def start_comm_timer() -> None:
    global start_comm

    # start_comm = time.process_time()
    start_comm = time.perf_counter()


def get_comm_time() -> float:
    global start_comm
    global elapsed_comm_time

    # end_comm = time.process_time()
    end_comm = time.perf_counter()
    elapsed_comm_time = end_comm - start_comm
    return elapsed_comm_time


######################################################
# Data Size Measurement
######################################################
def simple_size_calculator(message: str) -> int:
    return len(message.encode("UTF-8"))
