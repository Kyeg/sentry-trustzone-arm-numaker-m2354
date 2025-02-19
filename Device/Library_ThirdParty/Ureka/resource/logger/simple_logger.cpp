#include "simple_logger.hpp"
#include <iostream>
#include <stdexcept>

void SimpleLogger::log(const std::string& log_level, const std::string& log_info) {
    if (Environment::DEPLOYMENT_ENV == "TEST") {
        test_log(log_level, log_info);
    } else if (Environment::DEPLOYMENT_ENV == "PRODUCTION") {
        production_log(log_level, log_info);
    } else {
        throw std::runtime_error("Deployment Environment: " + Environment::DEPLOYMENT_ENV + " is not supported.");
    }
}

void SimpleLogger::test_log(const std::string& log_level, const std::string& log_info) {
    if (Environment::DEBUG_LOG == "OPEN") {
        if (log_level == "debug") {
            std::cout << "[DEBUG] " << log_info << std::endl;
        } else if (log_level == "info") {
            std::cout << "[INFO] " << log_info << std::endl;
        }
    }

    if (Environment::DEBUG_LOG == "OPEN" || Environment::DEBUG_LOG == "CLOSED") {
        if (log_level == "warning") {
            std::cout << "[WARNING] " << log_info << std::endl;
        } else if (log_level == "error") {
            std::cerr << "[ERROR] " << log_info << std::endl;
        } else if (log_level == "critical") {
            std::cerr << "[CRITICAL] " << log_info << std::endl;
        }
    }

    if (Environment::CLI_LOG == "OPEN" && log_level == "cli") {
        std::cout << "[CLI] " << log_info << std::endl;
    }

    if (Environment::MEASURE_LOG == "OPEN" && log_level == "measure") {
        std::cout << "[MEASURE] " << log_info << std::endl;
    }
}

void SimpleLogger::production_log(const std::string& log_level, const std::string& log_info) {
    if (Environment::DEBUG_LOG == "OPEN") {
        if (log_level == "debug") {
            std::cout << "[   DEBUG] : " << log_info << std::endl;
        } else if (log_level == "info") {
            std::cout << "[    INFO] : " << log_info << std::endl;
        }
    }

    if (Environment::DEBUG_LOG == "OPEN" || Environment::DEBUG_LOG == "CLOSED") {
        if (log_level == "warning") {
            std::cout << "[ WARNING] : " << log_info << std::endl;
        } else if (log_level == "error") {
            std::cerr << "[   ERROR] : " << log_info << std::endl;
        } else if (log_level == "critical") {
            std::cerr << "[CRITICAL] : " << log_info << std::endl;
        }
    }

    if (Environment::CLI_LOG == "OPEN" && log_level == "cli") {
        std::cout << "[     CLI] : " << log_info << std::endl;
    }

    if (Environment::MEASURE_LOG == "OPEN" && log_level == "measure") {
        std::cout << "[ MEASURE] : " << log_info << std::endl;
    }
}