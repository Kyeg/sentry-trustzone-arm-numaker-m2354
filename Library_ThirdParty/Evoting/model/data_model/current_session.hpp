#ifndef CURRENT_SESSION_HPP
#define CURRENT_SESSION_HPP
#include <string>

using namespace std;

class CurrentSession {
  public:
    CurrentSession() {};

    CurrentSession(const CurrentSession &current_session) {
        current_u_ticket_id = current_session.current_u_ticket_id;
        current_device_id = current_session.current_device_id;
        current_holder_id = current_session.current_holder_id;
        current_task_scope = current_session.current_task_scope;
        challenge_1 = current_session.challenge_1;
        challenge_2 = current_session.challenge_2;
        key_exchange_salt_1 = current_session.key_exchange_salt_1;
        key_exchange_salt_2 = current_session.key_exchange_salt_2;
        current_session_key_str = current_session.current_session_key_str;
        plaintext_cmd = current_session.plaintext_cmd;
        associated_plaintext_cmd = current_session.associated_plaintext_cmd;
        iv_cmd = current_session.iv_cmd;
        ciphertext_cmd = current_session.ciphertext_cmd;
        gcm_authentication_tag_cmd = current_session.gcm_authentication_tag_cmd;
        plaintext_data = current_session.plaintext_data;
        associated_plaintext_data = current_session.associated_plaintext_data;
        iv_data = current_session.iv_data;
        ciphertext_data = current_session.ciphertext_data;
        gcm_authentication_tag_data =
            current_session.gcm_authentication_tag_data;
    }

    // access UT
    string current_u_ticket_id;
    string current_device_id;
    string current_holder_id;
    string current_task_scope;

    // CR-KE
    string challenge_1;
    string challenge_2;
    string key_exchange_salt_1;
    string key_exchange_salt_2;

    // PS

    string current_session_key_str;
    string plaintext_cmd = "";
    string associated_plaintext_cmd = "";
    string iv_cmd;
    string ciphertext_cmd;
    string gcm_authentication_tag_cmd;

    string plaintext_data;
    string associated_plaintext_data;
    string iv_data;
    string ciphertext_data;
    string gcm_authentication_tag_data;

    string to_json();
    void clear_session() {
        current_u_ticket_id = "";
        current_device_id = "";
        current_holder_id = "";
        current_task_scope = "";
        challenge_1 = "";
        challenge_2 = "";
        key_exchange_salt_1 = "";
        key_exchange_salt_2 = "";
        current_session_key_str = "";
        associated_plaintext_cmd = "";
        iv_cmd = "";
        ciphertext_cmd = "";
        gcm_authentication_tag_cmd = "";
        plaintext_data = "";
        associated_plaintext_data = "";
        iv_data = "";
        ciphertext_data = "";
        gcm_authentication_tag_data = "";
    }
};

// CurrentSession json_to_current_session(json j);

#endif