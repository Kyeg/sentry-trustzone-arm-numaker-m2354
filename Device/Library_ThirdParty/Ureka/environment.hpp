#ifndef ENVIRONMENT_HPP
#define ENVIRONMENT_HPP

#include <string>

extern std::string SIMULATED_GLOBAL_CHANNEL;
namespace Environment {


    //////////////////////////////////////////////////////
    // Deployment Environment
    //////////////////////////////////////////////////////
    // "TEST": Test mode (e.g., logging, etc.)
    // "PRODUCTION": Production mode (e.g., printing, etc.)
     const std::string DEPLOYMENT_ENV = "TEST";

    //////////////////////////////////////////////////////
    // Communication Channel
    //////////////////////////////////////////////////////
    // "SIMULATED": Exchange messages through shared memory
    // "BLUETOOTH": Exchange messages through Bluetooth communication
     const std::string COMMUNICATION_CHANNEL = "UART";

    // "TEST": No delay (complete tests faster)
    // "PRODUCTION": With delay (make local simulation interactive)
     const double SIMULULATED_COMM_INTERRUPT_CYCLE_TIME = 0.01;
     const int SIMULULATED_COMM_DELAY_COUNT = 3;
     const double SIMULULATED_COMM_DELAY_DURATION = 0;

    // "TEST": No timeout (Pytest terminates all daemon threads when main thread is finished)
    // "PRODUCTION": Terminates worker threads through timeout
    //               and ensure TIME_OUT must be greater than DELAY_COUNT * DELAY_DURATION + processing time in worker thread
     const double SIMULULATED_COMM_TIME_OUT = 2;

    //////////////////////////////////////////////////////
    // Log
    //////////////////////////////////////////////////////
    // "OPEN": Print log
    // "CLOSED": Do not print log
     const std::string DEBUG_LOG = "OPEN";
     const std::string CLI_LOG = "OPEN";
     const std::string MEASURE_LOG = "CLOSED";
     const std::string MORE_MEASURE_WORKER_LOG = "CLOSED";
     const std::string MORE_MEASURE_RESOURCE_LOG = "CLOSED";

    //////////////////////////////////////////////////////
    // Measurement
    //////////////////////////////////////////////////////
     const double IO_BLOCKING_TOLERANCE_TIME = 0.015;
     const double MORE_MEASUREMENT_BLOCKING_THRESHOLD_TIME = 0.01;
     const double MORE_MEASUREMENT_PERF_THRESHOLD_TIME = 0.015;
     const double COMM_BLOCKING_TOLERANCE_TIME = 0.07;
     const std::string MEASUREMENT_TIME_PRECISION = ".3f";
     const std::string MORE_MEASUREMENT_TIME_PRECISION = "6.3f";
     const int MEASUREMENT_REPEAT_TIMES = 5;
};

#endif // ENVIRONMENT_HPP