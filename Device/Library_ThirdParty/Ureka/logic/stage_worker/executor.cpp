#include <string>
#include "executor.hpp"

extern "C"
{
    extern mbedtls_ecdsa_context generate_key_pair();
    void pub_key_to_string(mbedtls_ecdsa_context key, char *ret_key);
    void pk_key_to_string(mbedtls_ecdsa_context key, char *ret_key);
}

void Executor::self_change_state(string new_state)
{
    shared_data->state = new_state;
}

bool Executor::self_initialize_state()
{
    if (shared_data->this_device.device_type == this_device::IOT_DEVICE)
    {
        self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        return true;
    }
    else if (shared_data->this_device.device_type == this_device::USER_AGENT_OR_CLOUD_SERVER)
    {
        self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);
        return true;
    }

    return false;
}

bool Executor::self_execute_one_time_set_time_device_type_and_name(string device_type, string device_name)
{
    /*####################################################
    # Determine device type name, but still be uninitialized
    # Determine device name (for test)
    ####################################################*/
    shared_data->this_device.device_type = device_type;
    shared_data->this_device.device_name = device_name;
    shared_data->this_device.has_device_type = true;

    /*####################################################
    # Initial Order
    ####################################################*/

    // [STAGE: (O)]
    UTicket u_ticket;
    RTicket r_ticket;
    self_execute_update_ticket_order("has-type", 0, u_ticket, r_ticket);

    /*####################################################
    # Storage
    ####################################################*/

    // TODO
    return true;
}

void Executor::self_execute_one_time_initialize_agent_or_server()
{
    /*####################################################
    # Start Process Measurement
    ####################################################*/
    // measure_helper.measure_process_perf_start();

    printf("info: %s is initializing...\n", shared_data->this_device.device_name.c_str());

    /*####################################################
    # TODO: New way for _execute_one_time_intialize_agent_or_server()
    #         + DM: Apply Initialization Ticket
    #         + DM: Apply Personal Key Gen Ticket
    #         + DO: Generate Personal Key
    #         + DO: Request Ownership Ticket from DM
    ####################################################*/

    if (shared_data->this_device.device_type != this_device::USER_AGENT_OR_CLOUD_SERVER)
    {
        // FAILURE: (VRESET)
        printf("-> FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION\n");
        throw std::runtime_error("-> FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION");
        return;
    }

    if (shared_data->this_device.ticket_order != 0)
    {
        // FAILURE: (VUT)
        printf("-> FAILURE: VERIFY_TICKET_ORDER: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED\n");
        throw std::runtime_error("-> FAILURE: VERIFY_TICKET_ORDER: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED");
        return;
    }

    /*####################################################
    # Initialize Device Id
    ####################################################*/

    // CRYPTO
    mbedtls_ecdsa_context pp_key = generate_key_pair();

    // RAM
    char *device_pk_ch = (char *)malloc(500);
    char *device_pb_ch = (char *)malloc(500);
    pk_key_to_string(pp_key, device_pk_ch);
    pub_key_to_string(pp_key, device_pb_ch);
    string device_priv_key = string(device_pk_ch);
    string device_pub_key = string(device_pb_ch);
    shared_data->this_device.device_priv_key = device_priv_key;
    shared_data->this_device.device_pub_key = device_pub_key;

    /*####################################################
    # Initialize Personal Id
    ####################################################*/

    // CRYPTO
    mbedtls_ecdsa_context personal_key = generate_key_pair();

    // RAM

    char *personal_pk_ch = (char *)malloc(500);
    char *personal_pb_ch = (char *)malloc(500);
    pk_key_to_string(personal_key, personal_pk_ch);
    pub_key_to_string(personal_key, personal_pb_ch);
    string personal_priv_key = string(personal_pk_ch);
    string personal_pub_key = string(personal_pb_ch);
    shared_data->this_person.person_priv_key = personal_priv_key;
    shared_data->this_person.person_pub_key = personal_pub_key;

    /*####################################################
    # Initialize Device Owner
    ####################################################*/

    // RAM
    shared_data->this_device.owner_pub_key = shared_data->this_person.person_pub_key;

    // [STAGE: (O)]
    UTicket u_ticket;
    RTicket r_ticket;
    self_execute_update_ticket_order("agent-initialization", 0, u_ticket, r_ticket);

    /*####################################################
    # Storage
    ####################################################*/
    // TODO

    /*####################################################
    # End Process Measurement
    ####################################################*/
    // measure_helper.measure_recv_cli_perf_time("_execute_one_time_intialize_agent_or_server");
}

void Executor::self_execute_xxx_u_ticket(UTicket u_ticket_in)
{
    RTicket no_use_r_ticket;
    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_one_time_initialize_iot_device(u_ticket_in);

        // [STAGE: (O)]
        self_execute_update_ticket_order("device-verify-uticket", 1, u_ticket_in, no_use_r_ticket);
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_ownership_transfer(u_ticket_in);

        // [STAGE: (O)]
        self_execute_update_ticket_order("device-verify-uticket", 1, u_ticket_in, no_use_r_ticket);
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_cr_ke(1, u_ticket_in, no_use_r_ticket, "device");
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        // [STAGE: (VTK)(VTS)]
        // [STAGE: (E)]
        self_execute_ps("recv-utoken", 1, u_ticket_in, no_use_r_ticket, "", "");

        // Date Processing
        string *data_processing_result = self_execute_data_processing(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd);

        string plaintext_data = data_processing_result[0];
        string associated_plaintext_data = data_processing_result[1];

        // Update Session: PS-Data
        self_execute_ps("send-rtoken", 1, u_ticket_in, no_use_r_ticket, plaintext_data, associated_plaintext_data);

        if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (VTK)]
            if (shared_data->current_session.plaintext_cmd == "ACCESS_END")
            {
                shared_data->result_message = "-> SUCCESS: VERIFY_ACCESS_END";

                // [STAGE: (O)]
                self_execute_update_ticket_order("device-verify-uticket", 1, u_ticket_in, no_use_r_ticket);
            }
            else
            {
                shared_data->result_message = "-> FAILURE: VERIFY_ACCESS_END";
                printf("-> FAILURE: VERIFY_ACCESS_END\n");
            }
        }
        else
        {
            printf("should not be here (self_execute_xxx_u_ticket)\n");
        }
    }
}

void Executor::self_execute_xxx_r_ticket(RTicket r_ticket_in, string comm_end)
{
    UTicket no_use_u_ticket;
    if (comm_end == "holder-or-device")
    {
        if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (O)]
            self_execute_update_ticket_order("holder-or-issuer-verify-rticket", 2, no_use_u_ticket, r_ticket_in);
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
        {
            // [STAGE: (E)]
            self_execute_cr_ke(2, no_use_u_ticket, r_ticket_in, "holder");
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
        {
            // [STAGE: (E)]
            self_execute_cr_ke(2, no_use_u_ticket, r_ticket_in, "device");
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
        {
            // [STAGE: (E)]
            self_execute_cr_ke(2, no_use_u_ticket, r_ticket_in, "holder");
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
        {
            // [STAGE: (E)]
            self_execute_ps("recv-rtoken", 2, no_use_u_ticket, r_ticket_in, "", "");
        }
        else
        {
            printf("should not be here (self_execute_xxx_r_ticket)\n");
        }
    }
    else if (comm_end == "issuer")
    {
        if (r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // not owner anymore, delete this device in table
            shared_data->device_table.erase(r_ticket_in.device_id);

            /*############################################
            # Storage
            ############################################*/

            // TODO
        }
        else if (r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // still owner, but keep/delete device_access_u_ticket_for_others in table
            shared_data->device_table[r_ticket_in.device_id].device_access_u_ticket_for_others = "";
            shared_data->device_table[r_ticket_in.device_id].device_access_end_r_ticket_for_others = "";
            // [STAGE: (O)]
            self_execute_update_ticket_order("holder-or-issuer-verify-rticket", 2, no_use_u_ticket, r_ticket_in);

            /*############################################
            # Storage
            ############################################*/

            // TODO
        }
        else
        {
            printf("should not be here (self_execute_xxx_r_ticket)\n");
        }
    }
}

void Executor::self_execute_one_time_initialize_iot_device(UTicket u_ticket_in)
{
    printf("info: %s is initializing...\n", shared_data->this_device.device_name.c_str());

    if (shared_data->this_device.device_type != this_device::IOT_DEVICE)
    {
        // FAILURE: (VRESET)
        printf("-> FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION\n");
        return;
    }

    /*####################################################
    # Initialize Device Id
    ####################################################*/
    // CRYPTO
    mbedtls_ecdsa_context pp_key = generate_key_pair();

    // RAM
    char *device_pk_ch = (char *)malloc(500);
    char *device_pb_ch = (char *)malloc(500);
    pk_key_to_string(pp_key, device_pk_ch);
    pub_key_to_string(pp_key, device_pb_ch);
    string device_priv_key = string(device_pk_ch);
    string device_pub_key = string(device_pb_ch);
    shared_data->this_device.device_priv_key = device_priv_key;
    shared_data->this_device.device_pub_key = device_pub_key;

    /*####################################################
    # Initialize Device Owner
    ####################################################*/

    // RAM
    shared_data->this_device.owner_pub_key = u_ticket_in.holder_id;

    /*####################################################
    # Storage
    ####################################################*/

    // TODO
}

void Executor::self_execute_ownership_transfer(UTicket u_ticket_in)
{
    printf("info: %s is transferring ownership...\n", shared_data->this_device.device_name.c_str());

    /*####################################################
    # Update Device Owner
    ####################################################*/

    // RAM
    shared_data->this_device.owner_pub_key = u_ticket_in.holder_id;

    /*####################################################
    # Storage
    ####################################################*/

    // TODO
}

void Executor::self_execute_cr_ke(int UR, UTicket u_ticket_in, RTicket r_ticket_in, string comm_end, string cmd)
{
    printf("info: %s is executing cr_ke...\n", shared_data->this_device.device_name.c_str());

    UTicket no_use_u_ticket;
    RTicket no_use_r_ticket;
    if (UR == 1 &&
        (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET))
    {
        if (comm_end == "holder")
        {
            // Update session: Access UT
            shared_data->current_session.current_u_ticket_id = u_ticket_in.u_ticket_id;
            shared_data->current_session.current_device_id = u_ticket_in.device_id;
            shared_data->current_session.current_holder_id = u_ticket_in.holder_id;
            shared_data->current_session.current_task_scope = u_ticket_in.task_scope;

            // Update Session: PS-Cmd(Input: Plaintext, Associated-Plaintext)
            self_execute_ps("send-ut", 0, no_use_u_ticket, no_use_r_ticket, cmd, "");
        }
        else if (comm_end == "device")
        {
            // Update session: Access UT
            shared_data->current_session.current_u_ticket_id = u_ticket_in.u_ticket_id;
            shared_data->current_session.current_device_id = u_ticket_in.device_id;
            shared_data->current_session.current_holder_id = u_ticket_in.holder_id;
            shared_data->current_session.current_task_scope = u_ticket_in.task_scope;

            // Update Session: CR
            shared_data->current_session.challenge_1 = generate_random_str(32);

            // Update Session: KE
            shared_data->current_session.key_exchange_salt_1 = generate_random_str(32);

            // Update Session: PS-Cmd
            self_execute_ps("recv-ut-and-send-crke1", 0, no_use_u_ticket, no_use_r_ticket, "", "");
        }
        else
        {
            printf("should not be here (self_execute_cr_ke)\n");
        }
    }
    else if (UR == 2 && r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
    {

        // Update Session: CR
        shared_data->current_session.challenge_1 = r_ticket_in.challenge_1;
        shared_data->current_session.challenge_2 = generate_random_str(32);

        // Update Session: KE
        shared_data->current_session.key_exchange_salt_1 = r_ticket_in.key_exchange_salt_1;
        shared_data->current_session.key_exchange_salt_2 = generate_random_str(32);

        string current_session_key_byte = self_execute_generate_session_key(
            shared_data->current_session.key_exchange_salt_1,
            shared_data->current_session.key_exchange_salt_2,
            shared_data->this_person.person_priv_key,
            shared_data->current_session.current_device_id);

        shared_data->current_session.current_session_key_str = current_session_key_byte;

        // Update Session: PS-Cmd
        self_execute_ps("recv-crke1-and-send-crke2", 2, no_use_u_ticket, r_ticket_in, "", "");
    }
    else if (UR == 2 && r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        // Update Session: CR
        shared_data->current_session.challenge_2 = r_ticket_in.challenge_2;

        // Update Session: KE
        shared_data->current_session.key_exchange_salt_2 = r_ticket_in.key_exchange_salt_2;

        string current_session_key_byte = self_execute_generate_session_key(
            shared_data->current_session.key_exchange_salt_1,
            shared_data->current_session.key_exchange_salt_2,
            shared_data->this_device.device_priv_key,
            shared_data->current_session.current_holder_id);

        shared_data->current_session.current_session_key_str = current_session_key_byte;

        // Update Session: PS-Cmd
        self_execute_ps("recv-crke2", 2, no_use_u_ticket, r_ticket_in, "", "");

        string *data_processing_result = self_execute_data_processing(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd);

        string plaintext_data = data_processing_result[0];
        string associated_plaintext_data = data_processing_result[1];

        // Update Session: PS-Data

        self_execute_ps("send-crke3", 2, no_use_u_ticket, r_ticket_in, plaintext_data, associated_plaintext_data);
    }
    else if (UR == 2 && r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
    {
        // Update Session: PS-Data
        self_execute_ps("recv-crke3", 2, no_use_u_ticket, r_ticket_in, "", "");
    }
    else
    {
        printf("should not be here (self_execute_cr_ke)\n");
    }
}

string Executor::self_execute_generate_session_key(string salt_1, string salt_2, string priv_key, string pub_key)
{
    string shared_salt_bytes;
    for (int i = 0; i < salt_1.size(); i++)
    {
        shared_salt_bytes += salt_1[i] & salt_2[i];
    }

    string current_session_key = generate_ecdh_key(priv_key, pub_key, shared_salt_bytes, "");

    return current_session_key;
}

void Executor::self_execute_ps(string executing_case, int UR, UTicket u_ticket_in, RTicket r_ticket_in, string plaintext, string associated_plaintext)
{
    printf("info: %s is executing ps...\n", shared_data->this_device.device_name.c_str());

    if (executing_case == "send-ut")
    {
        // Update Session: PS-Cmd (input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_cmd = plaintext;
        shared_data->current_session.associated_plaintext_cmd = "additional unencrypted cmd";
    }
    else if (executing_case == "recv-ut-and-send-crke1")
    {
        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "recv-crke1-and-send-crke2")
    {
        // Update Session: PS-Cmd (Input: this-IV)
        if (UR == 1)
        {
            printf("should not be here (self_execute_ps) (recv-crke1-and-send-crke2)\n");
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_cmd = r_ticket_in.iv_cmd;
        }

        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        shared_data->current_session.ciphertext_cmd = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_cmd = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_data = self_gen_next_iv();
    }
    else if (executing_case == "recv-crke2")
    {
        // Update Session: PS-Data
        if (UR == 1)
        {
            shared_data->current_session.ciphertext_cmd = u_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = u_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = u_ticket_in.gcm_authentication_tag_cmd;
        }
        else if (UR == 2)
        {
            shared_data->current_session.ciphertext_cmd = r_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = r_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = r_ticket_in.gcm_authentication_tag_cmd;
        }

        // [STAGE: (VTK)(VTS)]
        // Update Session: PS-cmd (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.gcm_authentication_tag_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        msg_verifier->verify_cmd_is_in_task_scope(decrypted_plaintext);

        // Update Session: PS-Cmd (Output: plaintext)
        shared_data->current_session.plaintext_cmd = decrypted_plaintext;
    }
    else if (executing_case == "send-crke3")
    {
        // update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            shared_data->current_session.iv_data = u_ticket_in.iv_data;
        }
        else if (UR == 2)
        {
            printf("should not be here (self_execute_ps) (send-crke3)\n");
            shared_data->current_session.iv_data = r_ticket_in.iv_data;
        }

        // Update Session: PS-Cmd (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_data = plaintext;
        shared_data->current_session.associated_plaintext_data = associated_plaintext;

        // Update Session: PS-Data(Encryption)
        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data(Output: CipherText, GCM-Authentication-Tag)
        shared_data->current_session.ciphertext_data = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_data = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "recv-crke3")
    {
        // Update Session: PS-Cmd(Input: This-IV)
        if (UR == 1)
        {
            printf("should not be here (self_execute_ps) (recv-crke3)\n");
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_cmd = r_ticket_in.iv_cmd;
            // Update Session: PS-Data (input: ciphertext, associated_plaintext, gcm_authentication_tag)
            shared_data->current_session.ciphertext_data = r_ticket_in.ciphertext_data;
            shared_data->current_session.associated_plaintext_data = r_ticket_in.associated_plaintext_data;
            shared_data->current_session.gcm_authentication_tag_data = r_ticket_in.gcm_authentication_tag_data;
        }

        // [STAGE: (VTK)]
        // Update Session: PS-Data (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.gcm_authentication_tag_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data (Output: plaintext)
        shared_data->current_session.plaintext_data = decrypted_plaintext;
        // PS
    }
    else if (executing_case == "send-utoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        // Update Session: PS-Cmd (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_cmd = plaintext;
        shared_data->current_session.associated_plaintext_cmd = "additional unencrypted cmd";

        // Update Session: PS-Cmd (Encryption)
        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        // Update Session: PS-Cmd (Output: ciphertext, gcm_authentication_tag)
        shared_data->current_session.ciphertext_cmd = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_cmd = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_data = self_gen_next_iv();
    }
    else if (executing_case == "recv-utoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        // Update Session: PS-Cmd (Input: ciphertext, associated_plaintext, gcm_authentication_tag)
        if (UR == 1)
        {
            shared_data->current_session.ciphertext_cmd = u_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = u_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = u_ticket_in.gcm_authentication_tag_cmd;
        }
        else if (UR == 2)
        {
            shared_data->current_session.ciphertext_cmd = r_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = r_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = r_ticket_in.gcm_authentication_tag_cmd;
        }

        // [STAGE: (VTK)(VTS)]
        // Update Session: PS-Cmd (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.gcm_authentication_tag_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        if (UR == 1 && u_ticket_in.u_ticket_type != u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            msg_verifier->verify_cmd_is_in_task_scope(decrypted_plaintext);
        }
        else
        {
            printf("should not be here (self_execute_ps) (recv-utoken)\n");
        }

        // Update Session: PS-Cmd (Output: plaintext)
        shared_data->current_session.plaintext_cmd = decrypted_plaintext;
    }
    else if (executing_case == "send-rtoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            shared_data->current_session.iv_data = u_ticket_in.iv_data;
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_data = r_ticket_in.iv_data;
        }

        // Update Session: PS-DATA (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_data = plaintext;
        shared_data->current_session.associated_plaintext_data = associated_plaintext;

        // Update Session: PS-Data (Encryption)
        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data (Output: ciphertext, gcm_authentication_tag)
        shared_data->current_session.ciphertext_data = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_data = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "recv-rtoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            printf("should not be here (self_execute_ps) (recv-rtoken)\n");
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_cmd = r_ticket_in.iv_cmd;
            // Update Session: PS-Data (Input: ciphertext, associated_plaintext, gcm_authentication_tag)
            shared_data->current_session.ciphertext_data = r_ticket_in.ciphertext_data;
            shared_data->current_session.associated_plaintext_data = r_ticket_in.associated_plaintext_data;
            shared_data->current_session.gcm_authentication_tag_data = r_ticket_in.gcm_authentication_tag_data;
        }

        // [STAGE: (VTK)]
        // Update Session: PS-Data (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.gcm_authentication_tag_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data (Output: plaintext)
        shared_data->current_session.plaintext_data = decrypted_plaintext;
    }
    else
    {
        printf("%s\n", executing_case.c_str());
        throw std::runtime_error("should not be here (self_execute_ps)");
    }

    /*############################################
    # Storage
    ############################################*/

    // TODO
}

string *Executor::self_execute_encrypt_plaintext(string plaintext, string associated_plaintext, string session_key, string iv)
{
    printf("info: %s is encrypting plaintext...\n", shared_data->this_device.device_name.c_str());

    string *encrypted_plaintext = new string[2];

    // CRYPTO
    encrypted_plaintext = gcm_encrypt(plaintext, associated_plaintext, session_key, iv);

    return encrypted_plaintext;
}

string Executor::self_execute_decrypt_ciphertext(string ciphertext, string associated_plaintext, string gcm_authentication_tag, string session_key, string iv)
{
    printf("info: %s is decrypting ciphertext...\n", shared_data->this_device.device_name.c_str());

    try
    {
        // CRYPTO
        string decrypted_plaintext = gcm_decrypt(ciphertext, associated_plaintext, gcm_authentication_tag, session_key, iv);

        shared_data->result_message = "-> SUCCESS: VERIFY_IV_AND_HMAC";

        return decrypted_plaintext;
    }
    catch (const std::exception &e)
    {
        string error_message = e.what();
        shared_data->result_message = "-> FAILURE: VERIFY_IV_AND_HMAC";
        printf("error: %s\n", error_message.c_str());
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("should not be here (self_execute_decrypt_ciphertext)");
    }
}

string *Executor::self_execute_data_processing(string plaintext_cmd, string associated_plaintext_cmd)
{
    printf("info: %s is executing application...\n", shared_data->this_device.device_name.c_str());

    string plaintext_data = "DATA: " + plaintext_cmd;
    associated_plaintext_cmd = "DATA: " + associated_plaintext_cmd;

    string *data_processing_result = new string[2];

    data_processing_result[0] = plaintext_data;
    data_processing_result[1] = associated_plaintext_cmd;

    return data_processing_result;
}

/*####################################################
# [STAGE: (O)] Update Ticket Order
#   Update Ticket Order after:
#       "has-type": Intial Ticket Order = 0
#       "agent-initialization": Ticket Order = 1 after device/agent is initialized
#       "holder-generate-or-receive-uticket": Generate or Receive UTicket (expected ticket order)
#       "device-verify-uticket": Verify UTicket & End TX (actual ticket order)
#       "holder-or-issuer-verify-rticket": Verify RTicket (actual ticket order)
####################################################*/

void Executor::self_execute_update_ticket_order(string updating_case, int UR, UTicket u_ticket_in, RTicket r_ticket_in)
{
    printf("info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());

    if (updating_case == "has-type")
    {
        shared_data->this_device.ticket_order = 0;
    }
    else if (updating_case == "agent-initialization")
    {
        shared_data->this_device.ticket_order += 1;
    }
    else if (updating_case == "holder-generate-or-receive-uticket")
    {
        // Receive UTicket
        if (UR == 1 && (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET))
        {
            shared_data->device_table[u_ticket_in.device_id].ticket_order = u_ticket_in.ticket_order;
        }
        else
        {
            printf("should not be here (self_execute_update_ticket_order)\n");
        }
    }
    else if (updating_case == "device-verify-uticket")
    {
        // Execute UTicket
        if (UR == 1 && (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN))
        {
            shared_data->this_device.ticket_order += 1;
            printf("info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());
        }
        else
        {
            printf("should not be here (self_execute_update_ticket_order)\n");
        }
    }
    else if (updating_case == "holder-or-issuer-verify-rticket")
    {
        // Execute RTicket
        if (UR == 2 && (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN))
        {
            shared_data->device_table[r_ticket_in.device_id].ticket_order = r_ticket_in.ticket_order;
            printf("info: %d\n", r_ticket_in.ticket_order);
            printf("info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());
        }
        else
        {
            printf("should not be here (self_execute_update_ticket_order)\n");
        }
    }
    else
    {
        printf("should not be here (self_execute_update_ticket_order)\n");
    }

    /*############################################
    # Storage
    ############################################*/

    // TODO
}
