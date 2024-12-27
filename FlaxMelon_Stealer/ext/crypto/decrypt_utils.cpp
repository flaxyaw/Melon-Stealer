#include "../includes.h"

namespace decrypt_utils {

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

    // Store decrypted data in a vector for later use.
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


// AES decryption function using OpenSSL --chatgpt
std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& encryptedData, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    if (encryptedData.size() < 16) {
        logger::log(logger::error, "Encrypted data is too short.");

    }
    std::vector<unsigned char> tag(encryptedData.end() - 16, encryptedData.end());

    std::vector<unsigned char> actualEncryptedData(encryptedData.begin(), encryptedData.end() - 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        logger::log(logger::error, "Failed to create cipher context.");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        logger::log(logger::error, "Failed to initialize decryption.");

    }

    std::vector<unsigned char> decryptedData(actualEncryptedData.size());
    int decryptedLen = 0;

    if (EVP_DecryptUpdate(ctx, decryptedData.data(), &decryptedLen, actualEncryptedData.data(), actualEncryptedData.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        logger::log(logger::error, "Failed to decrypt data.");

    }

    // Set the expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        logger::log(logger::error, "Failed to set GCM tag.");

    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + decryptedLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        logger::log(logger::error, "Failed to finalize decryption.");

    }

    decryptedData.resize(decryptedLen + finalLen);
    EVP_CIPHER_CTX_free(ctx);

    return decryptedData;
    }
}