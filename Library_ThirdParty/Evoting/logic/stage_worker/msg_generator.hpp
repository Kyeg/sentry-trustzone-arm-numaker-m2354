#ifndef MSG_GENERATOR_HPP
#define MSG_GENERATOR_HPP
#include <string>
#include <cstdlib>
#include "shared_data.hpp"
#include "u_ticket.hpp"
#include "r_ticket.hpp"
#include "msg_generator_r_ticket.hpp"

using namespace std;

class MsgGenerator
{
private:
    SharedData *shared_data;
    // MeasureHelper measure_helper;
public:
    MsgGenerator(SharedData *shared_data /*, MeasureHelper measure_helper*/)
    {
        this->shared_data = shared_data;
        // this->measure_helper = measure_helper;
    }

    MsgGenerator() {};

    MsgGenerator(const MsgGenerator &msg_generator)
    {
        this->shared_data = msg_generator.shared_data;
        // this->measure_helper = msg_generator.measure_helper;
    }

    // string self_generate_xxx_u_ticket(string arbitrary_dict);
    string self_generate_xxx_r_ticket(string arbitrary_dict);
};

#endif