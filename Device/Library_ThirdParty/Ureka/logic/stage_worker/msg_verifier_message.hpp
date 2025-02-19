#ifndef MSG_VERIFIER_MESSAGE_HPP
#define MSG_VERIFIER_MESSAGE_HPP
#include "message.hpp"
#include "this_device.hpp"
#include <string>

class MessageVerifier {
  public:
    ThisDevice this_device;

    MessageVerifier(ThisDevice this_device) {
        this->this_device = this_device;
        printf("info: %s\n", "MessageVerifier is created");
    }

    Message verify_json_schema(const string &arbitrary_json);

    Message verify_message_operation(Message &message_in);

    Message verify_message_type(Message &message_in);

    Message verify_message_str(Message &message_in);
};

#endif // MSG_VERIFIER_MESSAGE_HPP