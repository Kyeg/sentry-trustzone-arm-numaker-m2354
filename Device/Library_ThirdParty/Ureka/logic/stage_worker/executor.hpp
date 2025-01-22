#ifndef EXECUTOR_HPP
#define EXECUTOR_HPP
#include <string>
#include "shared_data.hpp"
#include "this_device.hpp"
#include "u_ticket.hpp"
#include "r_ticket.hpp"
#include "msg_verifier.hpp"

using namespace std;

class Executor
{
public:
    SharedData *shared_data;
    // MeasureHelper measure_helper;
    // SimpleStorage simple_storage;
    MsgVerifier *msg_verifier;

    Executor(SharedData *shared_data, MsgVerifier *msg_verifier)
    {
        this->shared_data = shared_data;
        this->msg_verifier = msg_verifier;
    }

    Executor() {};

    Executor(const Executor &executor)
    {
        this->shared_data = executor.shared_data;
        this->msg_verifier = executor.msg_verifier;
    }

    bool self_initialize_state();

    bool self_execute_one_time_set_time_device_type_and_name(string device_type, string device_name);

    // void self_execute_one_time_initialize_agent_or_server();

    void self_execute_xxx_u_ticket(UTicket u_ticket_in);

    void self_execute_xxx_r_ticket(RTicket r_ticket_in, string comm_end = "holder-or-device");

    void self_execute_one_time_initialize_iot_device(UTicket u_ticket_in);

    void self_execute_ownership_transfer(UTicket u_ticket_in);

    void self_execute_cr_ke(int UR, UTicket u_ticket_in, RTicket r_ticket_in, string comm_end, string cmd = "");

    string self_execute_generate_session_key(string salt_1, string salt_2, string priv_key, string pub_key);

    void self_execute_ps(string executing_case, int UR, UTicket u_ticket_in, RTicket r_ticket_in, string plaintext, string associated_plaintext);

    string self_gen_next_iv();

    string *self_execute_encrypt_plaintext(string plaintext, string associated_plaintext, string session_key, string iv = "");

    string self_execute_decrypt_ciphertext(string ciphertext, string associated_plaintext, string gcm_authentication_tag, string session_key, string iv);

    string *self_execute_data_processing(string plaintext_cmd, string associated_plaintext_cmd);

    void self_execute_update_ticket_order(string updating_case, int UR, UTicket u_ticket_in, RTicket r_ticket_in);

    void self_change_state(string new_state);
};

#endif