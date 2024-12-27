#include "../includes.h"


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