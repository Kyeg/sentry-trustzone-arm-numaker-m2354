
#include <string>
#include "this_device.hpp"
#include "ecdsa.h"

#include "resource/crypto/myecdh.hpp"

mbedtls_ecdsa_context ThisDevice::strings_to_pp_keys()
{
    return turn_string_to_key(device_priv_key, device_pub_key);
}

string ThisDevice::to_json()
{
    json j;
    j["device_priv_key"] = device_priv_key;
    j["device_pub_key"] = device_pub_key;
    j["owner_pub_key"] = owner_pub_key;
    j["device_type"] = device_type;
    j["device_name"] = device_name;
    j["has_device_type"] = has_device_type;
    j["ticket_order"] = ticket_order;
    return j.dump();
}

ThisDevice json_to_this_device(json j)
{
    ThisDevice device;
    device.device_priv_key = j["device_priv_key"];
    device.device_pub_key = j["device_pub_key"];
    device.owner_pub_key = j["owner_pub_key"];
    device.device_type = j["device_type"];
    device.device_name = j["device_name"];
    device.has_device_type = j["has_device_type"];
    device.ticket_order = j["ticket_order"];
    return device;
}
