my_ticket = ""
def initialize(): 
 global my_ticket
 my_ticket = ""
class Environment:
    ######################################################
    # Deployment Environment
    ######################################################
    # "TEST": Test Mode (e.g., logging, etc.)
    # "PRODUCTION": Production Mode (e.g., print, etc.)
    DEPLOYMENT_ENV = "TEST"

    ######################################################
    # Communication Channel
    ######################################################
    # "SIMULATED": Exchange message through shared memory
    # "BLUETOOTH": Exchange message through bluetooth communication
    COMMUNICATION_CHANNEL = "SIMULATED"

    # "TEST": No Delay (complete tests faster)
    # "PRODUCTION": With Delay (make local simulation interactive)
    SIMULULATED_COMM_INTERRUPT_CYCLE_TIME = 0.01
    SIMULULATED_COMM_DELAY_COUNT = 3
    # SIMULULATED_COMM_DELAY_DURATION = 0.3
    SIMULULATED_COMM_DELAY_DURATION = 0

    # "TEST": No Time Out (Pytest terminates all daemon threads when main thread is finished)
    # "PRODUCTION": Terminates the worker threads through Timeout
    #                 and make sure TIME_OUT must be larger than DELAY_COUNT * DELAY_DURATION + Process Time in worker thread
    SIMULULATED_COMM_TIME_OUT = 2

    ######################################################
    # Log
    ######################################################
    # "OPEN": Print Log
    # "CLOSED": Not Print Log
    DEBUG_LOG = "OPEN"
    CLI_LOG = "OPEN"
    MEASURE_LOG = "CLOSED"
    MORE_MEASURE_WORKER_LOG = "CLOSED"
    MORE_MEASURE_RESOURCE_LOG = "CLOSED"

    ######################################################
    # Measurement
    ######################################################
    IO_BLOCKING_TOLERANCE_TIME = 0.015
    MORE_MEASUREMENT_BLOCKING_THRESHOLD_TIME = 0.001
    MORE_MEASUREMENT_PERF_THRESHOLD_TIME = 0.015
    COMM_BLOCKING_TOLERANCE_TIME = 0.070
    MEASUREMENT_TIME_PRECISION: str = ".3f"
    MORE_MEASUREMENT_TIME_PRECISION: str = "6.3f"
    MEASUREMENT_REPEAT_TIMES = 5
