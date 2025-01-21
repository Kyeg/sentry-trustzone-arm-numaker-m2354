#include <string>
#include "msg_verifier_message.hpp"

Message MessageVerifier::verify_json_schema(string arbitrary_json)
{
    string success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA";
    string fail_msg = "-> FAIL: VERIFY_JSON_SCHEMA";

    Message message_in;
    try
    {
        message_in = message_from_json_str(arbitrary_json);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(fail_msg + " : " + e.what());
    }

    return message_in;
}

Message MessageVerifier::verify_message_operation(Message message_in)
{
    string success_msg = "-> SUCCESS: VERIFY_MESSAGE_OPERATION";
    string fail_msg = "-> FAIL: VERIFY_MESSAGE_OPERATION";

    if (message_in.message_operation == message::MESSAGE_RECV_AND_STORE || message_in.message_operation == message::MESSAGE_VERIFY_AND_EXECUTE)
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }

    return message_in;
}

Message MessageVerifier::verify_message_type(Message message_in)
{
    string success_msg = "-> SUCCESS: VERIFY_MESSAGE_TYPE";
    string fail_msg = "-> FAIL: VERIFY_MESSAGE_TYPE";

    if (message_in.message_type == "UTICKET" || message_in.message_type == "RTICKET")
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }

    return message_in;
}

Message MessageVerifier::verify_message_str(Message message_in)
{
    string success_msg = "-> SUCCESS: VERIFY_MESSAGE_STR";
    string fail_msg = "-> FAIL: VERIFY_MESSAGE_STR";

    if (message_in.message_str != "")
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }

    return message_in;
}