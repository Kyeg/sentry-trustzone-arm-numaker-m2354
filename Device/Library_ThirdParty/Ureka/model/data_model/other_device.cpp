
#include <string>
#include "other_device.hpp"

string OtherDevice::to_json()
{
    json j;
    j["device_id"] = device_id;
    j["ticket_order"] = ticket_order;
    // j["device_u_ticket_for_owner"] = device_u_ticket_for_owner;
    // j["device_ownership_u_ticket_for_others"] = device_ownership_u_ticket_for_others;
    // j["device_access_u_ticket_for_others"] = device_access_u_ticket_for_others;
    // j["device_r_ticket_for_owner"] = device_r_ticket_for_owner;
    // j["device_ownership_r_ticket_for_others"] = device_ownership_r_ticket_for_others;
    // j["device_access_end_r_ticket_for_others"] = device_access_end_r_ticket_for_others;
    return j.dump();
}

OtherDevice json_to_other_device(json j)
{
    OtherDevice device;
    device.device_id = j["device_id"];
    device.ticket_order = j["ticket_order"];
    device.device_u_ticket_for_owner = j["device_u_ticket_for_owner"];
    device.device_ownership_u_ticket_for_others = j["device_ownership_u_ticket_for_others"];
    device.device_access_u_ticket_for_others = j["device_access_u_ticket_for_others"];
    device.device_r_ticket_for_owner = j["device_r_ticket_for_owner"];
    device.device_ownership_r_ticket_for_others = j["device_ownership_r_ticket_for_others"];
    device.device_access_end_r_ticket_for_others = j["device_access_end_r_ticket_for_others"];
    return device;
}