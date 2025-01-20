import logging
from ureka_framework.environment import Environment
import os

cur_path = os.path.dirname(os.path.realpath(__file__))
log_path = os.path.join(cur_path, "simple_logger.log")
# logging.basicConfig( 
#     filename=log_path,
#     level=logging.DEBUG,
#     format="%(asctime)s [%(levelname)s] : %(message)s",
# )
file_handler = logging.FileHandler(log_path)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] : %(message)s"))
logger = logging.getLogger()
logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)
def simple_log(log_level: str, log_info: str) -> None:  # pragma: no cover -> PRODUCTION
    global logger
    if Environment.DEPLOYMENT_ENV == "TEST":
        if Environment.DEBUG_LOG == "OPEN":
            if log_level == "debug":
                logger.debug(log_info)
                return
            elif log_level == "info":
                logger.info(log_info)
                return
        if Environment.DEBUG_LOG == "OPEN" or Environment.DEBUG_LOG == "CLOSED":
            if log_level == "warning":
                logger.warning(log_info)
                return
            elif log_level == "error":
                logger.error(log_info)
                return
            elif log_level == "critical":
                logger.critical(log_info)
                return

        if Environment.CLI_LOG == "OPEN":
            if log_level == "cli":
                logger.debug(log_info)
                return

        if Environment.MEASURE_LOG == "OPEN":
            if log_level == "measure":
                logger.debug(log_info)
                return

    elif Environment.DEPLOYMENT_ENV == "PRODUCTION":
        if Environment.DEBUG_LOG == "OPEN":
            if log_level == "debug":
                print(f"[   DEBUG] : {log_info}")
                return
            elif log_level == "info":
                print(f"[    INFO] : {log_info}")
                return
                

        if Environment.DEBUG_LOG == "OPEN" or Environment.DEBUG_LOG == "CLOSED":
            if log_level == "warning":
                print(f"[ WARNING] : {log_info}")
                return
            elif log_level == "error":
                print(f"[   ERROR] : {log_info}")
                return
            elif log_level == "critical":
                print(f"[CRITICAL] : {log_info}")
                return

        if Environment.CLI_LOG == "OPEN":
            if log_level == "cli":
                print(f"[     CLI] : {log_info}")
                return

        if Environment.MEASURE_LOG == "OPEN":
            if log_level == "measure":
                print(f"[ MEASURE] : {log_info}")
                return

    else:
        raise RuntimeError(
            f"Deployment Environment: {Environment.DEPLOYMENT_ENV} is not supported."
        )