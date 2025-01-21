#include "generated_msg_storer.hpp"

#include <stdexcept>

using namespace std;

void GeneratedMsgStorer::store_generated_xxx_u_ticket(const string generated_u_ticket_json)
{
    try
    {
        // [STAGE: (VR)]
        // cout << "debug: " << "GeneratedMsgStorer::store_generated_xxx_u_ticket" << "\n";
        UTicket generated_u_ticket = uticket_from_json_str(generated_u_ticket_json);
        if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
        {
            // Holder (for Owner)
            string device_id_for_initialization_u_ticket = "no_id";
            // OtherDevice new_device(device_id_for_initialization_u_ticket, generated_u_ticket_json);
            shared_data->device_table[device_id_for_initialization_u_ticket] = OtherDevice(device_id_for_initialization_u_ticket, generated_u_ticket_json);
        }
        else if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // Issuer (for Others)
            string device_id_for_u_ticket = generated_u_ticket.device_id;
            shared_data->device_table[device_id_for_u_ticket].device_ownership_u_ticket_for_others = generated_u_ticket_json;
        }
        else if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // Holder (for Owner)
            string device_id_for_u_ticket = generated_u_ticket.device_id;
            shared_data->device_table[generated_u_ticket.device_id].device_u_ticket_for_owner = generated_u_ticket_json;
        }
        else if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
        {
            // Issuer (for Others)
            string device_id_for_u_ticket = generated_u_ticket.device_id;
            shared_data->device_table[device_id_for_u_ticket].device_access_u_ticket_for_others = generated_u_ticket_json;
        }
        else
        {
            throw runtime_error("Not implemented yet");
        }

        //////////////////////////////////////////////////////
        // Storage
        //////////////////////////////////////////////////////
        // simple_storage.store_storage(
        //     shared_data->this_device,
        //     shared_data->device_table,
        //     shared_data->this_person,
        //     shared_data->current_session
        // );
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
}