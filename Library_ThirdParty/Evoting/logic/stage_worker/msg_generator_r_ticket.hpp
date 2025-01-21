#ifndef MSG_GENERATOR_R_TICKET_HPP
#define MSG_GENERATOR_R_TICKET_HPP
#include "current_session.hpp"

using namespace std;

class RTicketGenerator {
  public:
    ThisDevice this_device;
    ThisPerson this_person;
    map<string, OtherDevice> device_table;

    RTicketGenerator(ThisDevice this_device, ThisPerson this_person,
                     map<string, OtherDevice> device_table)
        : this_device(this_device), this_person(this_person),
          device_table(device_table) {}

    RTicket generate_arbitrary_r_ticket(const string &arbitrary_dict);

    void self_add_device_signature_on_r_ticket(RTicket &unsigned_r_ticket,
                                               const string &private_key,
                                               const string &r_ticket_str);
};

#endif