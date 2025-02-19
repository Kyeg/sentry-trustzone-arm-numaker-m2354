#ifndef THIS_PERSON_HPP
#define THIS_PERSON_HPP
#include <string>

using namespace std;

class ThisPerson
{
public:
    ThisPerson() {};

    ThisPerson(const ThisPerson &this_person) : person_priv_key(this_person.person_priv_key), person_pub_key(this_person.person_pub_key) {}

    string person_priv_key;
    string person_pub_key;

    string get_person_pub_x();
    string get_person_pub_y();

    /*##############################################################################
    #                                < Person_obj >                                #
    #                                       | self-defined serilaization           #
    #                                       | (including ECC_Key_obj, bytes, etc.) #
    #                                       v                                      #
    #         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
    #                                       |                                      #
    #                                       v                                      #
    #                       < JSON_str (Printable Characters) >                    #
    ##############################################################################*/

    string to_json();
};

// ThisPerson json_to_this_person(json j);

#endif