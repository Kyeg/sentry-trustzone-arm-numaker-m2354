#ifndef R_TICKET_HPP
#define R_TICKET_HPP

#include <set>
#include <string>

#include "jsonBuild.hpp"

using namespace std;

namespace r_ticket {

const string MESSAGE_TYPE = "RTICKET";
// Constants for RTicket types
const string TYPE_CRKE1_RTICKET = "CR-KE-1";
const string TYPE_CRKE2_RTICKET = "CR-KE-2";
const string TYPE_CRKE3_RTICKET = "CR-KE-3";
const string TYPE_DATA_RTOKEN = "DATA_RTOKEN";

const set<string> LEGAL_CRKE_TYPES = {r_ticket::TYPE_CRKE1_RTICKET,
                                      r_ticket::TYPE_CRKE2_RTICKET,
                                      r_ticket::TYPE_CRKE3_RTICKET};

const set<string> LEGAL_RTICKET_TYPES = {
    "INITIALIZATION", "OWNERSHIP",   "CR-KE-1",   "CR-KE-2",
    "CR-KE-3",        "DATA_RTOKEN", "ACCESS_END"};
} // namespace r_ticket

class RTicket {
  public:
    // Optional fields
    string protocol_version = "UREKA-1.0";
    string r_ticket_id = "";
    string r_ticket_type = "";
    string device_id = "";
    string result = "";
    int ticket_order = 0;
    string audit_start = "";
    string audit_end = "";
    string challenge_1 = "";
    string challenge_2 = "";
    string key_exchange_salt_1 = "";
    string key_exchange_salt_2 = "";
    string associated_plaintext_cmd = "";
    string ciphertext_cmd = "";
    string iv_cmd = "";
    string gcm_authentication_tag_cmd = "";
    string associated_plaintext_data = "";
    string ciphertext_data;
    string iv_data = "";
    string gcm_authentication_tag_data = "";
    string device_signature = "";

    // Serialization and deserialization
    string to_json_str();

  private:
    // Helper to throw if the JSON is not valid
    void validate_json(const json &json);
};

void rticket_from_json_str(const string &json_str, RTicket &rticket);

#endif // RTICKET_HPP