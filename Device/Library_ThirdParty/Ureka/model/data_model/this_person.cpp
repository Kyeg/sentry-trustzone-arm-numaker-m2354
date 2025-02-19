#include "myecdh.hpp"
#include "this_person.hpp"
#include <pk.h>
#include <pem.h>
#define endl "\n"


mbedtls_ecdsa_context ThisPerson::strings_to_pp_keys()
{
    return turn_string_to_key(person_priv_key, person_pub_key);
}

// turn class into json
string ThisPerson::to_json()
{
    // use nlohmann json library
    json j;
    j["person_priv_key"] = person_priv_key;
    j["person_pub_key"] = person_pub_key;
    string json_str = j.dump();
    return json_str;
}

ThisPerson json_to_this_person(json j)
{
    ThisPerson person;
    person.person_priv_key = j["person_priv_key"];
    person.person_pub_key = j["person_pub_key"];
    return person;
}
