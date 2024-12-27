#pragma once
#include "../includes.h"

namespace decrypt_utils {

	//Function to unprotect using wincrypt
	std::vector<BYTE> unprotectData(const std::string& decoded_key_str);

	//Base64 decode function
	std::vector<BYTE> decode_key(const std::string& encoded_key_str);


	//AES decryption
	std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& encryptedData,
		const std::vector<unsigned char>& key,
		const std::vector<unsigned char>& iv);
}