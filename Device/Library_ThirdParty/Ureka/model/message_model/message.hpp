#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <string>

#include "jsonBuild.hpp"

using namespace std;

namespace message
{
    // Constants for message operations
    const string MESSAGE_RECV_AND_STORE = "MESSAGE_RECV_AND_STORE";
    const string MESSAGE_VERIFY_AND_EXECUTE = "MESSAGE_VERIFY_AND_EXECUTE";
};

class Message
{
public:
    // Optional fields
    string message_operation = "";
    string message_type = "";
    string message_str = "";

    // Serialization and deserialization
    string to_json_str();

private:
    // Helper to throw if the JSON is not valid
    static void validate_json(const json &json);
};

void message_from_json_str(const string &json_str, Message &message);

#endif // MESSAGE_HPP