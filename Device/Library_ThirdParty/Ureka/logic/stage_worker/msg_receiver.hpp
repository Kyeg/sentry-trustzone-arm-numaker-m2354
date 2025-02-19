#ifndef MSG_RECEIVER_HPP
#define MSG_RECEIVER_HPP

#include <queue>
#include "shared_data.hpp"
#include "msg_verifier.hpp"
#include "environment.hpp"
// #include "../../resource/stora/simple_logger.hpp"
#include "u_ticket.hpp"
#include "r_ticket.hpp"

class DeviceController;

class MsgReceiver
{
public:
    MsgReceiver(
        SharedData *shared_data,
        MsgVerifier *msg_verifier);

    void create_simulated_comm_connection();
    void accept_bluetooth_comm();
    void close_bluetooth_connection();
    void close_bluetooth_acception();
    void recv_xxx_message();

private:
    SharedData *shared_data;
    // MeasureHelper* measure_helper_;
    MsgVerifier *msg_verifier;
};

#endif