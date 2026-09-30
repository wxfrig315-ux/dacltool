#pragma once
#include <map>
#include <iostream>
#include <string>
#include <Windows.h>
#include <vector>
#include <sddl.h>
#include <aclapi.h>
#include "table.h"
#include <sstream>
#include <set>
#include "lnk-check.h"
#include "utils.h"

BOOL list_files(std::wstring file_path_wstr, std::vector<std::wstring>& file_lists);
std::wstring access_mask_to_string(DWORD mask);
std::wstring sid_to_wstring(PSID sid);
void analyze_dac_with_token(const std::wstring& args);
std::wstringstream get_dac(std::wstring folderPath);
std::map<std::wstring, std::wstring> parse_arg(const std::wstring& input);
