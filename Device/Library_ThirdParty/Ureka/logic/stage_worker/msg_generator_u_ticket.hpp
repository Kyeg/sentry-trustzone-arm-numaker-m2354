#ifndef MSG_GENERATOR_U_TICKET_HPP
#define MSG_GENERATOR_U_TICKET_HPP
#include "this_device.hpp"
#include "this_person.hpp"
#include "other_device.hpp"

#include <string>
#include <map>

using namespace std;

class UTicketGenerator
{
private:
    ThisDevice this_device;
    ThisPerson this_person;
    map<string, OtherDevice> device_table;

public:
    UTicketGenerator(ThisDevice this_device, ThisPerson this_person, map<string, OtherDevice> device_table)
    {
        this->this_device = this_device;
        this->this_person = this_person;
        this->device_table = device_table;
    }

    UTicket generate_arbitrary_u_ticket(const string &arbitrary_dict);

    UTicket self_add_issuer_signature_on_u_ticket(UTicket unsigned_r_ticket, const string &private_key);
};

#endif