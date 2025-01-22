#include "msg_sender.hpp"

#include <stdexcept>

using namespace std;

MsgSender::MsgSender(SharedData *shared_data)
    : shared_data(shared_data) {}

void MsgSender::start_simulated_comm()
{
    shared_data->simulated_comm_completed_flag = false;
}

void MsgSender::complete_simulated_comm()
{
    shared_data->simulated_comm_completed_flag = true;
}

void MsgSender::wait_simulated_comm_completed()
{
    if (Environment::DEPLOYMENT_ENV == "TEST")
    {
        // while (!shared_data->simulated_comm_completed_flag) {
        //     std::this_thread::sleep_for(std::chrono::milliseconds(Environment::SIMULULATED_COMM_INTERRUPT_CYCLE_TIME));
        // }
    }
    else if (Environment::DEPLOYMENT_ENV == "PRODUCTION")
    {
        // shared_data->simulated_comm_receiver_thread.join();
    }
}

// void MsgSender::start_bluetooth_comm() {
//     shared_data->connection_socket.acceptConnection();
// }

// void MsgSender::complete_bluetooth_comm() {
//     shared_data->connection_socket.closeConnection();
// }

void MsgSender::send_xxx_message(const std::string &message_operation,
                                 const std::string &message_type,
                                 const std::string &sent_message_json)
{
    // 生成消息
    if ((message_operation == message::MESSAGE_RECV_AND_STORE || message_operation == message::MESSAGE_VERIFY_AND_EXECUTE) &&
        (message_type == u_ticket::MESSAGE_TYPE || message_type == r_ticket::MESSAGE_TYPE))
    {

        Message message_request;
        message_request.message_operation = message_operation;
        message_request.message_type = message_type;
        message_request.message_str = sent_message_json;

        try
        {
            std::string new_message_json = message_request.to_json_str();

            if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
            {
                // simpleLog("info", "+ " + shared_data->this_device.device_name + " is sending message to " +
                //           shared_data->simulated_comm_channel.end->shared_data->this_device.device_name + "...");
                // cout << "info: + " << shared_data->this_device.device_name << " is sending message to " << shared_data->simulated_comm_channel.end->shared_data->this_device.device_name << "..." << "\n";
                // 模拟网络延迟
                for (int i = 0; i < Environment::SIMULULATED_COMM_DELAY_COUNT; ++i)
                {
                    printf("info: Simulated Comm Delay\n");
                    // if (Environment::DEPLOYMENT_ENV == "PRODUCTION") {
                    //     std::this_thread::sleep_for(std::chrono::milliseconds(Environment::SIMULULATED_COMM_DELAY_DURATION));
                    // }
                }

                // shared_data->simulated_comm_channel.sender_queue.push(new_message_json);
                SIMULATED_GLOBAL_CHANNEL = new_message_json;
            }
            else
            {
                // simpleLog("info", "+ " + shared_data->this_device.device_name + " is sending message to BT_address or BT_name...");
                printf("shold not reach here\n");
                // shared_data->connection_socket.sendMessage(new_message_json);
            }
        }
        catch (const std::exception &error)
        {
            throw std::runtime_error("Weird M-Request: " + std::string(error.what()));
        }
    }
    else
    {
        throw std::runtime_error("Weird M-Request");
    }
}