#pragma once
#include <Windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <iostream>
#include <vector>
#include <sstream>
#include "dacl-enum.h"

BOOL RemoveSidAce(const std::wstring& args);
std::wstring get_sid_string(std::wstring name);
