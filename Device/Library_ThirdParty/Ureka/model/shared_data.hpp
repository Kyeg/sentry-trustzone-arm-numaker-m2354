#ifndef SHARED_DATA_HPP
#define SHARED_DATA_HPP

#include "communication/simulated_comm_channel.hpp"
#include "current_session.hpp"
#include "other_device.hpp"
#include "this_device.hpp"
#include "this_person.hpp"
#include <string>
// #include "simulated_comm_channel.hpp"

// #ifdef HAS_PYBLUEZ
// #include "bluetooth_service.hpp"
// #endif

using namespace std;

class SharedData {
  public:
    SharedData()
        : this_device(ThisDevice()), current_session(CurrentSession()),
          //   this_person(ThisPerson()),
          //    device_table(map<string, OtherDevice>()),
          state(""), result_message(""),
          //   measure_rec(map<string, string>()),
          simulated_comm_completed_flag(false) {};

    SharedData(const SharedData &shared_data)
        : this_device(shared_data.this_device),
          current_session(shared_data.current_session),
          state(shared_data.state), result_message(shared_data.result_message),
          simulated_comm_completed_flag(
              shared_data.simulated_comm_completed_flag) {};
    ThisDevice this_device;
    CurrentSession current_session;
    string state;

    // CLI 输出
    // string received_message_json;
    string result_message;

    bool simulated_comm_completed_flag;
};

#endif // SHARED_DATA_HPP