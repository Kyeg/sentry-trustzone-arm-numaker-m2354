#ifndef U_TICKET_HPP
#define U_TICKET_HPP

#include <set>
#include <string>

// #include "jsonBuild.hpp"

using namespace std;

namespace u_ticket {

/*####################################################
# Protocol Version
####################################################*/
const string PROTOCOL_VERSION = "UREKA-1.0";

/*####################################################
# Message Type
####################################################*/
const string MESSAGE_TYPE = "UTICKET";

// Constants for UTicket types
const string TYPE_INITIALIZATION_UTICKET = "INITIALIZATION";
const string TYPE_OWNERSHIP_UTICKET = "OWNERSHIP";
const string TYPE_SELFACCESS_UTICKET = "SELFACCESS";
const string TYPE_ACCESS_UTICKET = "ACCESS";
const string TYPE_CMD_UTOKEN = "CMD_UTOKEN";
const string TYPE_ACCESS_END_UTOKEN = "ACCESS_END";

// LEGAL_UTICKET_TYPES: {str} = {
//     TYPE_INITIALIZATION_UTICKET,
//     TYPE_OWNERSHIP_UTICKET,
//     TYPE_SELFACCESS_UTICKET,
//     TYPE_ACCESS_UTICKET,
//     TYPE_CMD_UTOKEN,
//     TYPE_ACCESS_END_UTOKEN,
// }

const set<string> LEGAL_UTICKET_TYPES = {u_ticket::TYPE_INITIALIZATION_UTICKET,
                                         u_ticket::TYPE_OWNERSHIP_UTICKET,
                                         u_ticket::TYPE_SELFACCESS_UTICKET,
                                         u_ticket::TYPE_ACCESS_UTICKET,
                                         u_ticket::TYPE_CMD_UTOKEN,
                                         u_ticket::TYPE_ACCESS_END_UTOKEN};

} // namespace u_ticket

class UTicket {
  public:
    // Optional fields
    string protocol_version = "UREKA-1.0";
    string u_ticket_id;
    string u_ticket_type;
    string device_id;
    int ticket_order;
    string holder_id;
    string task_scope;
    string issuer_signature;
    string associated_plaintext_cmd;
    string ciphertext_cmd;
    string gcm_authentication_tag_cmd;
    string iv_data;

    // Serialization and deserialization
    string to_json_str();

  private:
    // Helper to throw if the JSON is not valid
    // void validate_json(const json &json);
};

void uticket_from_json_str(const string &json_str, UTicket &ticket);

#endif // UTICKET_HPP