// json.hpp
#ifndef json_HPP
#define json_HPP

// #include "u_ticket.hpp"
#include <string>
#include <vector>

using namespace std;

class json {
  public:
    // Methods to add int and string values
    void addValueInt(const string &key, int value);
    void addValueString(const string &key, const string &value);
    void addValueBool(const string &key, bool value);
    // Method to generate the JSON string
    string dump() const;

    int find(const string &key) const;
    void parse(const string &jsonString);
    string get_string(int index) const;
    int get_int(int index) const;
    bool get_bool(int index) const;

  private:
    // Private method to escape strings for JSON
    string escapeString(const string &input) const;
    string reverseEscape(const string &input) const;

    // Internal storage for key-value pairs as strings
    vector<pair<string, string>> data;
};

#endif // json_HPP
