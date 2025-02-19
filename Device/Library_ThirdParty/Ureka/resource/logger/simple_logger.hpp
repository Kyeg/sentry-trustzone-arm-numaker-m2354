#ifndef SIMPLE_LOGGER_HPP
#define SIMPLE_LOGGER_HPP

#include <string>
#include "../../environment.hpp"

class SimpleLogger {
public:
    static void log(const std::string& log_level, const std::string& log_info);

private:
    static void test_log(const std::string& log_level, const std::string& log_info);
    static void production_log(const std::string& log_level, const std::string& log_info);
};

#endif // SIMPLE_LOGGER_HPP