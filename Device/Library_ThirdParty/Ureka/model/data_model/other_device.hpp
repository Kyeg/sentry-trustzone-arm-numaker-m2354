#ifndef OTHER_DEVICE_HPP
#define OTHER_DEVICE_HPP
#include <string>

using namespace std;

class OtherDevice
{
public:
    OtherDevice() {};

    OtherDevice(const OtherDevice &other_device)
    {
        device_id = other_device.device_id;
        ticket_order = other_device.ticket_order;
        device_u_ticket_for_owner = other_device.device_u_ticket_for_owner;
        device_ownership_u_ticket_for_others = other_device.device_ownership_u_ticket_for_others;
        device_access_u_ticket_for_others = other_device.device_access_u_ticket_for_others;
        device_r_ticket_for_owner = other_device.device_r_ticket_for_owner;
        device_ownership_r_ticket_for_others = other_device.device_ownership_r_ticket_for_others;
        device_access_end_r_ticket_for_others = other_device.device_access_end_r_ticket_for_others;
    }

    OtherDevice(const string device_id, const string device_u_ticket_for_owner)
    {
        this->device_id = device_id;
        this->device_u_ticket_for_owner = device_u_ticket_for_owner;
    }

    OtherDevice(const string device_id, const string device_u_ticket_for_owner, const string device_r_ticket_for_owner)
    {
        this->device_id = device_id;
        this->device_u_ticket_for_owner = device_u_ticket_for_owner;
        this->device_r_ticket_for_owner = device_r_ticket_for_owner;
    }
    OtherDevice(const string device_id, const string device_u_ticket_for_owner, const string device_r_ticket_for_owner, const int ticket_order)
    {
        this->device_id = device_id;
        this->device_u_ticket_for_owner = device_u_ticket_for_owner;
        this->device_r_ticket_for_owner = device_r_ticket_for_owner;
        this->ticket_order = ticket_order;
    }

    string device_id;

    int ticket_order = 0;

    string device_u_ticket_for_owner;
    string device_ownership_u_ticket_for_others;
    string device_access_u_ticket_for_others;

    string device_r_ticket_for_owner;
    string device_ownership_r_ticket_for_others;
    string device_access_end_r_ticket_for_others;

    string to_json();
};

// OtherDevice json_to_other_device(json j);

#endif