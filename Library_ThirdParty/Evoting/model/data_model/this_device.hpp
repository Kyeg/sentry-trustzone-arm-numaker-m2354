#ifndef THIS_DEVICE_HPP
#define THIS_DEVICE_HPP
#include <string>

using namespace std;

namespace this_device
{
    const string IOT_DEVICE = "IOT_DEVICE";
    const string USER_AGENT_OR_CLOUD_SERVER = "USER_AGENT_OR_CLOUD_SERVER";

    /*####################################################
    # Device State
    ####################################################*/
    // IOD_DEVICE
    const string STATE_DEVICE_WAIT_FOR_UT = "STATE_DEVICE_WAIT_FOR_UT";
    const string STATE_DEVICE_WAIT_FOR_CRKE2 = "STATE_DEVICE_WAIT_FOR_CRKE2";
    const string STATE_DEVICE_WAIT_FOR_CMD = "STATE_DEVICE_WAIT_FOR_CMD";
    // USER_AGENT_OR_CLOUD_SERVER
    const string STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT = "STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT";
    const string STATE_AGENT_WAIT_FOR_RT = "STATE_AGENT_WAIT_FOR_RT";
    const string STATE_AGENT_WAIT_FOR_CRKE1 = "STATE_AGENT_WAIT_FOR_CRKE1";
    const string STATE_AGENT_WAIT_FOR_CRKE3 = "STATE_AGENT_WAIT_FOR_CRKE3";
    const string STATE_AGENT_WAIT_FOR_DATA = "STATE_AGENT_WAIT_FOR_DATA";
}

class ThisDevice
{
public:
    // mbedtls_ecdsa_context pp_keys;

    ThisDevice() {};

    ThisDevice(const ThisDevice &this_device)
    {
        device_type = this_device.device_type;
        device_name = this_device.device_name;
        has_device_type = this_device.has_device_type;
        ticket_order = this_device.ticket_order;
        device_priv_key = this_device.device_priv_key;
        device_pub_key = this_device.device_pub_key;
        owner_pub_key = this_device.owner_pub_key;
    }

    string device_priv_key;
    string device_pub_key;

    string owner_pub_key;

    string device_type;
    string device_name;
    bool has_device_type = false;
    int ticket_order;

    string get_device_pub_x();
    string get_device_pub_y();

    string to_json();
};

// ThisDevice json_to_this_device(json j);

#endif