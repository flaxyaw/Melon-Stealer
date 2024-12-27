#pragma once

//Win + General includes
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <wincrypt.h>
#include <vector>
#include <filesystem>

//external includes etc.
#include <curl/curl.h>
#include "../ext/base64/base64.h"
#include "../ext/json/json.hpp"
#include "../ext/logger/logger.h"
#include "../ext/sqlite/sqlite3pp.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
using json = nlohmann::json;


//Internals
#include "../ext/crypto/decrypt_utils.h"
#include "../ext/definitions/definitions.h"
#include "../ext/misc/json_operations.h"
#include "../ext/misc/db_operations.h"