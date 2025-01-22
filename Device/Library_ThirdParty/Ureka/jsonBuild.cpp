// json.cpp
#include "jsonBuild.hpp"
// #include <iostream>

// Method to add an integer value
void json::addValueInt(const string &key, int value) {
    // data[key] = to_string(value); // Convert int to string
    data.push_back(make_pair(key, to_string(value)));
}

// Method to add a string value
void json::addValueString(const string &key, const string &value) {
    // data[key] =
    //     "\"" + escapeString(value) + "\""; // Add quotes and escape the
    //     string
    data.push_back(make_pair(key, "\"" + escapeString(value) + "\""));
}

void json::addValueBool(const string &key, bool value) {
    // data[key] = value ? "true" : "false"; // Add "true" or "false" to the
    // JSON
    data.push_back(make_pair(key, value ? "true" : "false"));
}

int json::find(const string &key) const {
    for (int i = 0; i < data.size(); ++i) {
        if (data[i].first == key) {
            return i;
        }
    }
    return -1;
}

string json::get_string(int index) const {
    string temp_str = data[index].second;

    // remove the quotes
    return reverseEscape(temp_str.substr(1, temp_str.size() - 2));
}

int json::get_int(int index) const { return stoi(data[index].second); }

bool json::get_bool(int index) const { return data[index].second == "true"; }

// Method to escape special characters in strings for JSON
string json::escapeString(const string &input) const {
    string escaped;
    for (char c : input) {
        switch (c) {
        case '\"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        default:
            escaped += c;
            break;
        }
    }
    return escaped;
}

string json::reverseEscape(const string &input) const {
    string reversed;
    for (int i = 0; i < input.size(); ++i) {
        if (input[i] == '\\') {
            switch (input[i + 1]) {
            case '\"':
                reversed += '\"';
                break;
            case '\\':
                reversed += '\\';
                break;
            case 'b':
                reversed += '\b';
                break;
            case 'f':
                reversed += '\f';
                break;
            case 'n':
                reversed += '\n';
                break;
            default:
                reversed += input[i + 1];
                break;
            }
            i++;
        } else {
            reversed += input[i];
        }
    }
    return reversed;
}

// Method to generate the JSON string
string json::dump() const {
    string json = "{";
    bool first = true;
    for (const auto &pair : data) {
        if (!first) {
            json += ",";
        }
        // check if the value is a string or not
        json += "\"" + escapeString(pair.first) + "\":" + pair.second;
        first = false;
    }
    json += "}";
    return json;
}

#include <stdexcept> // For throwing exceptions

// Method to parse JSON string character by character, handling errors for
// invalid strings
void json::parse(const string &jsonString) {
    // printf("Parsing JSON string: %s\n", jsonString.c_str());
    data.clear(); // Clear existing data
    string key, value;
    bool isKey = true, inString = false, isEscaping = false, isBool = false,
         isInt = false;
    int braceCount = 1;

    // Check if the input is a valid JSON object starting with '{' and ending
    // with '}'
    if (jsonString.empty() || jsonString[0] != '{' ||
        jsonString.back() != '}') {
        printf("Invalid JSON format: JSON object must start with '{' and end "
               "with '}'.\n");
        throw std::runtime_error("Invalid JSON format: JSON object must start "
                                 "with '{' and end with '}'.");
    }

    // for (int i = 0; i < jsonString.size(); ++i)
    // {
    //     cout << jsonString[i];
    // }
    // cout << "now start\n";

    for (int i = 1; i < jsonString.size(); ++i) {
        char c = jsonString[i];
        // cout << c;

        // Handle escape sequences
        if (isEscaping) {
            if (c == '\\' || c == '\"') {
                (isKey) ? (key += c)
                        : (value += c); // Add the character directly if it's a
                                        // valid escape sequence
            } else {
                // Handle other escaped characters
                switch (c) {
                case 'n':
                    (isKey) ? (key += '\n') : (value += '\n');
                    break;
                default:
                    printf("Invalid escape sequence\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Invalid escape sequence.");
                    break;
                }
            }
            isEscaping = false; // Reset escaping state
            continue;
        }

        // Start escape sequence when encountering a backslash
        if (c == '\\') {
            isEscaping = true;
            continue;
        }

        // Handle string delimiters
        if (c == '\"') {
            inString = !inString; // Toggle inString state
            continue;
        }

        if (c >= '0' && c <= '9' && !isKey && !inString) {
            if (c == '0' && jsonString[i + 1] >= '0' &&
                jsonString[i + 1] <= '9') {
                printf("Invalid JSON format: Leading zeros are not allowed.\n");
                throw std::runtime_error(
                    "Invalid JSON format: Leading zeros are not allowed.");
            }
            int j = i + 1;
            int num = c - '0';
            while (j < jsonString.size() && jsonString[j] >= '0' &&
                   jsonString[j] <= '9') {
                num = num * 10 + (jsonString[j] - '0');
                j++;
            }
            while (jsonString[j] != ',' && jsonString[j] != '}' &&
                   j < jsonString.size())
                j++;

            if (j >= jsonString.size()) {
                printf(
                    "Invalid JSON format: Missing comma or closing brace.\n");
                throw std::runtime_error(
                    "Invalid JSON format: Missing comma or closing brace.");
            }
            i = j;
            addValueInt(key, num);
            key.clear();
            value.clear();
            isKey = true;

            if (jsonString[j] == '}') {
                braceCount--;
                if (braceCount < 0) {
                    printf("Invalid JSON format: Unmatched closing brace.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Unmatched closing brace.");
                }
            }
            continue;
        }

        // Handle boolean values
        if ((c == 't' || c == 'f') && !inString && !isKey) {
            if (c == 't') {
                if (jsonString.substr(i, 4) == "true") {
                    addValueBool(key, true);
                    i += 4;
                } else {
                    printf("Invalid JSON format: Invalid boolean value.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Invalid boolean value.");
                }
            } else {
                if (jsonString.substr(i, 5) == "false") {
                    addValueBool(key, false);
                    i += 5;
                } else {
                    printf("Invalid JSON format: Invalid boolean value.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Invalid boolean value.");
                }
            }
            key.clear();
            value.clear();
            isKey = true;
            continue;
        }

        if (inString) {
            (isKey) ? (key += c) : (value += c);
        } else {
            if (isspace(c)) {
                continue;
            }
            if (c == ':') {
                if (!isKey || key.empty()) {
                    printf("Invalid JSON format: Missing key or misplaced "
                           "colon.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Missing key or misplaced colon.");
                }
                isKey = false;
                continue;
            }

            // Handle entry separator or end of JSON object
            if (c == ',' || c == '}') {
                if (!key.empty() && !value.empty()) {
                    addValueString(key, value);
                } else if (!key.empty() && value.empty() &&
                           (c == '}' || c == ',')) {
                    // Valid case of an empty object or the end of JSON
                    addValueString(key, value);
                } else if (key.empty() && value.empty() && c == '}') {
                    // Handle the case when encountering only the closing brace
                    // at the top level
                    break;
                } else {
                    printf("Invalid JSON format: Missing key or value.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Missing key or value.");
                }

                key.clear();
                value.clear();
                isKey = true;

                if (c == '}') {
                    braceCount--;
                    if (braceCount < 0) {
                        printf(
                            "Invalid JSON format: Unmatched closing brace.\n");
                        throw std::runtime_error(
                            "Invalid JSON format: Unmatched closing brace.");
                    }
                }
                continue;
            }
        }
    }

    // Check if all opened braces were properly closed
    if (braceCount != 0) {
        printf("Invalid JSON format: Unmatched opening brace.\n");
        throw std::runtime_error(
            "Invalid JSON format: Unmatched opening brace.");
    }

    // Check if there are any unclosed strings
    if (inString) {
        printf("Invalid JSON format: Unclosed string.\n");
        throw std::runtime_error("Invalid JSON format: Unclosed string.");
    }

    // Final check: JSON string should be properly parsed into key-value pairs
    if (!key.empty() || !value.empty()) {
        data.push_back(make_pair(key, value));
    }

    // print the data
    // for (const auto &pair : data) {
    //     printf("%s: %s\n", pair.first.c_str(), pair.second.c_str());
    // }
}
