#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <windows.h>  // For OutputDebugString

// Function to split a wstring into words
std::vector<std::wstring> split_into_words(const std::wstring& str);

// Function to wrap wstring text to fit within a specified width
std::vector<std::wstring> wrap_text(const std::wstring& text, size_t width);

// Function to return the table as a wstringstream
std::wstringstream generate_table(const std::vector<std::vector<std::wstring>>& table, const std::vector<size_t>& col_widths);


