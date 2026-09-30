#pragma once
#include <Windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <iostream>
#include <stdio.h>
#include <regex>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "utils.h"
#include <shellapi.h>

DWORD AddSidAce(const std::wstring& args);
std::pair<std::wstring, DWORD> ParseICaclsEntry(std::wstring input, std::wstring& err);
