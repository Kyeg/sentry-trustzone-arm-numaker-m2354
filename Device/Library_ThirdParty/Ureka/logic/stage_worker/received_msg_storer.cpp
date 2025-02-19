#include "received_msg_storer.hpp"

// #include "../..simple_logger.hpp"
#include <stdexcept>

ReceivedMsgStorer::ReceivedMsgStorer(SharedData *shared_data,
                                     SimpleStorage *simple_storage)
    : shared_data(shared_data), simple_storage(simple_storage) {};

void ReceivedMsgStorer::store_received_xxx_u_ticket(const UTicket &received_u_ticket)
{
    try
    {
        std::string received_u_ticket_json = received_u_ticket.to_json_str();

        if (received_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
            received_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
        {
            shared_data->device_table[received_u_ticket.device_id] = OtherDevice(
                received_u_ticket.device_id,
                received_u_ticket_json);
        }
        else
        {
            throw std::runtime_error("Shouldn't Reach Here");
        }

        // Storage
        // simple_storage->storeStorage(
        //     shared_data->this_device,
        //     shared_data->device_table,
        //     shared_data->this_person,
        //     shared_data->current_session
        // );
    }
    catch (const std::exception &)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

void ReceivedMsgStorer::store_received_xxx_r_ticket(const RTicket &received_r_ticket)
{
    try
    {
        std::string received_r_ticket_json = received_r_ticket.to_json_str();

        if (received_r_ticket.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
        {
            std::string created_device_id = received_r_ticket.device_id;
            shared_data->device_table[created_device_id] = OtherDevice(
                created_device_id,
                shared_data->device_table["no_id"].device_u_ticket_for_owner,
                received_r_ticket_json);
        }
        else if (received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            if (shared_data->device_table[received_r_ticket.device_id].device_ownership_u_ticket_for_others.empty())
            {
                shared_data->device_table[received_r_ticket.device_id].device_r_ticket_for_owner = received_r_ticket_json;
            }
            else
            {
                shared_data->device_table[received_r_ticket.device_id].device_ownership_r_ticket_for_others = received_r_ticket_json;
            }
        }
        else if (received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            if (shared_data->device_table[received_r_ticket.device_id].device_access_u_ticket_for_others.empty())
            {
                shared_data->device_table[received_r_ticket.device_id].device_r_ticket_for_owner = received_r_ticket_json;
            }
            else
            {
                shared_data->device_table[received_r_ticket.device_id].device_access_end_r_ticket_for_others = received_r_ticket_json;
            }
        }
        else
        {
            throw std::runtime_error("Shouldn't Reach Here");
        }

        // Storage
        // simple_storage->storeStorage(
        //     shared_data->this_device,
        //     shared_data->device_table,
        //     shared_data->this_person,
        //     shared_data->current_session
        // );
    }
    catch (const std::exception &)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}