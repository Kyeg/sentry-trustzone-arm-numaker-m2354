#ifndef DEVICE_CONTROLLER_HPP
#define DEVICE_CONTROLLER_HPP

#include "shared_data.hpp"
#include "storage/simple_storage.hpp"
// #include "measure_helper.hpp"
#include "message.hpp"
#include "r_ticket.hpp"
#include "u_ticket.hpp"
// #include "simple_logger.hpp"
#include <string>

using namespace std;

// 前向声明
class SharedData;

class DeviceController {
  public:
    DeviceController(const std::string &device_type = "",
                     const std::string &device_name = "");
    ~DeviceController();
    void reboot_device();

    SharedData *shared_data;

    void initialize();
    void cleanup();

    // flow open session
    void self_device_send_cr_ke_1(const string &result_message);
    void self_device_recv_cr_ke_2(RTicket &received_r_ticket);
    void self_device_send_cr_ke_3(const string &result_message);

    // flow apply u ticket
    void self_device_recv_u_ticket(UTicket &received_u_ticket);
    RTicket
    self_device_send_r_ticket_generate_request(const string &u_ticket_type,
                                               const string &u_ticket_id,
                                               const string &result_message);
    void self_device_send_r_ticket(const string &u_ticket_type,
                                   const string &u_ticket_id,
                                   const string &result_message);

    // flow issue u token
    void self_device_recv_cmd(UTicket &received_u_token);
    void self_device_send_data(const std::string &result_message);

    // receive permissionless
    void self_device_recv_permissionless();

    // msg receiver
    void recv_xxx_message_ble(char *received_message);
    void recv_xxx_message();

    // r ticket generator
    RTicket generate_arbitrary_r_ticket(RTicket received_r_ticket);

    void self_add_device_signature_on_r_ticket(RTicket &unsigned_r_ticket,
                                               const string &private_key,
                                               const string &r_ticket_str);

    // msg_verifier
    int self_classify_message_is_defined_type(char *arbitrary_json,
                                              char *received_message);
    void self_classify_u_ticket_is_defined_type(UTicket &received_u_ticket);
    void self_classify_r_ticket_is_defined_type(RTicket &received_r_ticket);
    void verify_u_ticket_can_execute(UTicket u_ticket_in);
    void
    verify_u_ticket_has_executed_through_r_ticket(RTicket &r_ticket_in,
                                                  UTicket &audit_start_ticket,
                                                  UTicket &audit_end_ticket);
    void verify_cmd_is_in_task_scope(const string &cmd);

    // executor
    bool self_initialize_state();

    bool self_execute_one_time_set_time_device_type_and_name(
        const string &device_type, const string &device_name);
    void self_execute_xxx_u_ticket(UTicket u_ticket_in);
    void self_execute_xxx_r_ticket(RTicket r_ticket_in,
                                   const string &comm_end = "holder-or-device");
    void self_execute_one_time_initialize_iot_device(UTicket u_ticket_in);
    void self_execute_ownership_transfer(UTicket u_ticket_in);
    void self_execute_cr_ke(int UR, UTicket &u_ticket_in, RTicket &r_ticket_in,
                            const string &comm_end, const string &cmd = "");
    string self_execute_generate_session_key(const string &salt_1,
                                             const string &salt_2,
                                             string &priv_key, string &pub_key);

    // void self_execute_cmd(const string &cmd);
    void self_execute_ps(const string &executing_case, int UR,
                         UTicket u_ticket_in, RTicket r_ticket_in,
                         const string &plaintext,
                         const string &associated_plaintext);
    string self_gen_next_iv();
    void self_execute_encrypt_plaintext(const string &plaintext,
                                        const string &associated_plaintext,
                                        const string &session_key,
                                        string &ciphertext,
                                        string &gcm_authentication_tag,
                                        const string &iv = "");
    void self_execute_decrypt_ciphertext(const string &ciphertext,
                                         const string &associated_plaintext,
                                         const string &gcm_authentication_tag,
                                         const string &session_key,
                                         const string &iv,
                                         char *decrypted_plaintext);
    void self_execute_data_processing(string &plaintext_cmd,
                                      string &associated_plaintext_cmd);
    void self_execute_update_ticket_order(const string &updating_case, int UR,
                                          UTicket u_ticket_in,
                                          RTicket r_ticket_in);
    void self_change_state(const string &new_state);

    // msg_generator
    void self_generate_xxx_r_ticket(RTicket &received_r_ticket);

    // msg_sender
    void send_xxx_message(const std::string &message_operation,
                          const std::string &message_type,
                          const RTicket &sent_message_json);

    // uticket verifier
    UTicket u_ticket_verify_json_schema(const char *arbitrary_json);

    void u_ticket_verify_protocol_version(UTicket &u_ticket_in);

    void u_ticket_verify_u_ticket_id(UTicket &u_ticket_in);

    void u_ticket_verify_u_ticket_type(UTicket &u_ticket_in);

    void u_ticket_has_device_id(UTicket &u_ticket_in);

    void u_ticket_verify_device_id(UTicket &u_ticket_in);

    void u_ticket_verify_ticket_order(UTicket &u_ticket_in);

    void u_ticket_verify_holder_id(UTicket &u_ticket_in);

    void u_ticket_verify_task_scope(UTicket &u_ticket_in);

    void u_ticket_verify_ps(UTicket &u_ticket_in);

    void u_ticket_verify_issuer_signature(UTicket &u_ticket_in);

    /*####################################################
    # Verify ECC Signature on UTicket
    ####################################################*/

    bool self_verify_issuer_signature_on_u_ticket(UTicket &signed_u_ticket,
                                                  const string &public_key);

    // r ticket verifier

    RTicket r_ticket_verify_json_schema(const string &arbitrary_json);

    void r_ticket_verify_protocol_version(RTicket &r_ticket_in);

    void r_ticket_verify_r_ticket_id(RTicket &r_ticket_in);

    void r_ticket_verify_r_ticket_type(RTicket &r_ticket_in);

    void r_ticket_has_device_id(RTicket &r_ticket_in);

    void r_ticket_verify_device_id(RTicket &r_ticket_in,
                                   UTicket &audit_start_ticket);

    void r_ticket_verify_result(RTicket &r_ticket_in);

    void r_ticket_verify_ticket_order(RTicket &r_ticket_in);

    void r_ticket_verify_audit_start(RTicket &r_ticket_in,
                                     UTicket &audit_start_ticket);

    void r_ticket_verify_audit_end(RTicket &r_ticket_in);

    void r_ticket_verify_cr_key(RTicket &r_ticket_in);

    void r_ticket_verify_ps(RTicket &r_ticket_in);

    void r_ticket_verify_device_signature(RTicket &r_ticket_in);

    void msg_verify_json_schema(const string &arbitrary_json,
                                Message &message_in);

    void msg_verify_message_operation(const char *arbitrary_json);

    int msg_verify_message_type(const char *arbitrary_json);

    void msg_verify_message_str(const char *arbitrary_json, char *msg);

    void addStringToUTicket(const string &key, const string &value,
                            UTicket &u_ticket_in);
    void parse_uticket(const string &arbitrary_json, UTicket &u_ticket_in);

    void uticket_from_json_str(const string &json_str, UTicket &ticket);

    /*####################################################
    # Verify ECC Signature on RTicket
    ####################################################*/

    bool self_verify_device_signature_on_r_ticket(RTicket &signed_r_ticket,
                                                  const string &public_key);
};

#endif