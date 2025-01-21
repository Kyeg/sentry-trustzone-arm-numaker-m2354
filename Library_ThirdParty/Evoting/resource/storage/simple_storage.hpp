#ifndef SIMPLE_STORAGE_HPP
#define SIMPLE_STORAGE_HPP

#include <string>
#include <map>
#include "this_device.hpp"
#include "other_device.hpp"
#include "this_person.hpp"
#include "current_session.hpp"

// Namespace for filesystem operations (C++17 and later)

class SimpleStorage
{
private:
public:
    SimpleStorage(const string device_name)
    {
        // path_storage = fs::current_path() / "SimpleStorage";
        // path_device_controller = path_storage / device_name;

        // path_this_device = path_device_controller / "this_device.json";
        // path_device_table = path_device_controller / "device_table.json";
        // path_u_ticket_table = path_device_controller / "u_ticket_table.json";
        // path_this_person = path_device_controller / "this_person.json";
        // path_current_session = path_device_controller / "current_session.json";

        // create_root_directory_for_each_device_controller();
    }

    void store_storage(ThisDevice this_device, map<string, OtherDevice> device_table, ThisPerson this_person, CurrentSession current_session)
    {
        // ofstream ofs_this_device(path_this_device);
        // ofstream ofs_device_table(path_device_table);
        // ofstream ofs_this_person(path_this_person);
        // ofstream ofs_current_session(path_current_session);

        // json device_table_json;
        // for (auto& [key, value] : device_table) {
        //     device_table_json[key] = value.to_json();
        // }

        // nlohmann::json j_this_device = this_device.to_json();
        // nlohmann::json j_device_table = device_table_json;
        // nlohmann::json j_this_person = this_person.to_json();
        // nlohmann::json j_current_session = current_session.to_json();

        // ofs_this_device << j_this_device.dump(4);
        // ofs_device_table << j_device_table.dump(4);
        // ofs_this_person << j_this_person.dump(4);
        // ofs_current_session << j_current_session.dump(4);
    }

    void load_storage(ThisDevice &this_device, map<string, OtherDevice> &device_table, ThisPerson &this_person, CurrentSession &current_session)
    {
        // ifstream ifs_this_device(path_this_device);
        // ifstream ifs_device_table(path_device_table);
        // ifstream ifs_this_person(path_this_person);
        // ifstream ifs_current_session(path_current_session);

        // nlohmann::json j_this_device;
        // nlohmann::json j_device_table;
        // nlohmann::json j_this_person;
        // nlohmann::json j_current_session;

        // ifs_this_device >> j_this_device;
        // ifs_device_table >> j_device_table;
        // ifs_this_person >> j_this_person;
        // ifs_current_session >> j_current_session;

        // for (auto& [key, value] : j_device_table.items()) {
        //     device_table[key] = json_to_other_device(value);
        // }

        // this_device = json_to_this_device(j_this_device);

        // this_person = json_to_this_person(j_this_person);
        // current_session = json_to_current_session(j_current_session);
    }
};

#endif