#ifndef RECEIVED_MSG_STORER_HPP
#define RECEIVED_MSG_STORER_HPP

#include "shared_data.hpp"
#include "u_ticket.hpp"
#include "r_ticket.hpp"
#include "other_device.hpp"

#include "storage/simple_storage.hpp"

class ReceivedMsgStorer
{
public:
    ReceivedMsgStorer(SharedData *shared_data,
                      SimpleStorage *simple_storage);

    void store_received_xxx_u_ticket(UTicket &received_u_ticket);
    void store_received_xxx_r_ticket(RTicket &received_r_ticket);

private:
    SharedData *shared_data;
    // MeasureHelper measure_helper;
    SimpleStorage *simple_storage;
};

#endif // RECEIVED_MSG_STORER_HPP
