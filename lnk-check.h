#pragma once
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <shobjidl.h>
#include <shlguid.h>
#include <strsafe.h>
#include <string>
#include <algorithm>
#include <AclAPI.h>

BOOL is_lnk_file(std::wstring file_path);
std::wstring resolve_lnk_path(std::wstring lnk_path);
