#include "message.hpp"

string Message::to_json_str() const
{
    json j;
    if (message_operation != "")
        j["message_operation"] = message_operation;
    if (message_type != "")
        j["message_type"] = message_type;
    if (message_str != "")
        j["message_str"] = message_str;

    return j.dump(4); // Indentation of 4 spaces
}

Message message_from_json_str(const string &json_str)
{
    json j = json::parse(json_str);
    // validate_json(j);÷
    Message msg;
    if (j.contains("message_operation"))
        msg.message_operation = j["message_operation"];
    if (j.contains("message_type"))
        msg.message_type = j["message_type"];
    if (j.contains("message_str"))
        msg.message_str = j["message_str"];
    return msg;
}

void Message::validate_json(const json &j)
{
    // Implement validation logic here
    // For example, check for required fields, types, etc.
}