#include "msg_receiver.hpp"

#include <stdexcept>

MsgReceiver::MsgReceiver(
    SharedData *shared_data,
    // measure_helper* measure_helper,
    MsgVerifier *msg_verifier,
    Executor *executor,
    MsgSender *msg_sender,
    FlowIssueUTicket *flow_issuer_issue_u_ticket,
    FlowApplyUTicket *flow_apply_u_ticket,
    FlowOpenSession *flow_open_session,
    FlowIssueUToken *flow_issue_u_token) : shared_data(shared_data),
                                           // measure_helper_(measure_helper),
                                           msg_verifier(msg_verifier),
                                           executor(executor),
                                           msg_sender(msg_sender),
                                           flow_issuer_issue_u_ticket(flow_issuer_issue_u_ticket),
                                           flow_apply_u_ticket(flow_apply_u_ticket),
                                           flow_open_session(flow_open_session),
                                           flow_issue_u_token(flow_issue_u_token) {};

void MsgReceiver::create_simulated_comm_connection()
{
    // shared_data_->simulated_comm_channel.end = end;
    // shared_data->simulated_comm_channel.sender_queue = end->shared_data->simulated_comm_channel.receiver_queue;

    // shared_data_->simulated_comm_receiver_thread = std::thread(&MsgReceiver::recv_xxx_message, this);
    // shared_data_->simulated_comm_receiver_thread.detach();
}

void MsgReceiver::accept_bluetooth_comm()
{
    // 实现蓝牙通信接受逻辑
}

void MsgReceiver::close_bluetooth_connection()
{
    // 实现关闭蓝牙连接逻辑
}

void MsgReceiver::close_bluetooth_acception()
{
    // 实现关闭蓝牙接受逻辑
}

void MsgReceiver::recv_xxx_message()
{
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
    {
        msg_sender->start_simulated_comm();
    }
    else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
    {
        // msg_sender->start_bluetooth_comm();
    }

    /* while (true) { */
    // 检查通信是否完成的逻辑

    try
    {
        std::string received_message_with_header;

        if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
        {
            if (shared_data->simulated_comm_completed_flag == true)
            {
                /* break; */
            }
        }
        else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
        {
            // 蓝牙通信接收消息逻辑
            /* break; */
        }

        // [STAGE (R)]

        if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
        {
            if (Environment::DEPLOYMENT_ENV == "TEST")
            {
                received_message_with_header = SIMULATED_GLOBAL_CHANNEL;
                SIMULATED_GLOBAL_CHANNEL = "";
                // shared_data->simulated_comm_channel.receiver_queue.pop();
            }
            else if (Environment::DEPLOYMENT_ENV == "PRODUCTION")
            {
                // received_message_with_header = shared_data->simulated_comm_channel.receiver_queue.front();
                // shared_data->simulated_comm_channel.receiver_queue.pop();
            }
        }
        else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
        {
            // received_message_with_header = shared_data->connection_socket.receiveMessage();
        }
        if (received_message_with_header == "")
        {
            throw std::runtime_error("Received message is empty");
        }
        // 消息大小测量
        // measure_helper_->measure_message_size("_recv_message", received_message_with_header);

        // 开始处理性能测量
        // measure_helper_->measure_process_perf_start();

        // 消息验证和分类
        pair<UTicket, RTicket> received_message = msg_verifier->self_classify_message_is_defined_type(received_message_with_header);

        if (received_message.first.u_ticket_type != "")
        {
            // [STAGE (U)]
            shared_data->received_message_json = received_message.first.to_json_str();
        }
        else if (received_message.second.r_ticket_type != "")
        {
            // [STAGE (R)]
            shared_data->received_message_json = received_message.second.to_json_str();
        }

        printf("cli Received Message: %s\n", received_message_with_header.c_str());
        // TODO:
        // IOT device
        printf("device_type: %s state: %s\n", shared_data->this_device.device_type.c_str(), shared_data->state.c_str());
        if (shared_data->state == this_device::STATE_DEVICE_WAIT_FOR_UT)
        {
            flow_apply_u_ticket->self_device_recv_u_ticket(received_message.first);
        }
        else if (shared_data->state == this_device::STATE_DEVICE_WAIT_FOR_CRKE2)
        {
            flow_open_session->self_device_recv_cr_ke_2(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_DEVICE_WAIT_FOR_CMD)
        {
            flow_issue_u_token->self_device_recv_cmd(received_message.first);
        }
        /*USER_AGENT_OR_CLOUD_SERVER */ else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT)
        {
            if (received_message.first.u_ticket_type != "")
            {
                printf("Received U Ticket\n");
                flow_issuer_issue_u_ticket->self_holder_recv_u_ticket(received_message.first);
            }
            else if (received_message.second.r_ticket_type != "")
            {
                flow_issuer_issue_u_ticket->self_issuer_recv_r_ticket(received_message.second);
            }
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_RT)
        {
            flow_apply_u_ticket->self_holder_recv_r_ticket(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_CRKE1)
        {
            flow_open_session->self_holder_recv_cr_ke_1(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_CRKE3)
        {
            flow_open_session->self_holder_recv_cr_ke_3(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_DATA)
        {
            flow_issue_u_token->self_holder_recv_data(received_message.second);
        }
        else
        {
            throw std::runtime_error("(MsgReceiver) Shouldn't Reach Here");
        }
    }
    catch (const std::runtime_error &error)
    {
        shared_data->result_message = error.what();
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
    /* } */
}