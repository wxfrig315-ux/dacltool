#include <iostream>
#include <string>
#include <io.h>
#include <fcntl.h>

#include "dacl-enum.h"
#include "add-per.h"
#include "remove-per.h"

static void print_banner()
{
    std::wcout << L"==============================================\n";
    std::wcout << L"          dacltool - DACL Tool\n";
    std::wcout << L"==============================================\n";
    std::wcout << L"Select mode:\n";
    std::wcout << L"  1) enum    - enumerate DACL entries of a file/folder that match the current token\n";
    std::wcout << L"  2) add     - grant a user new permissions on a file/folder\n";
    std::wcout << L"  3) remove  - remove a user's ACEs from a file/folder\n";
    std::wcout << L"  0) exit\n";
    std::wcout << L"> ";
    std::wcout.flush();
}

static void run_enum()
{
    std::wcout << L"Arguments (e.g. -r C:\\folder | C:\\file.txt | target.lnk): ";
    std::wcout.flush();
    std::wstring args;
    if (!std::getline(std::wcin, args))
    {
        return;
    }
    analyze_dac_with_token(args);
}

static void run_add()
{
    std::wcout << L"Arguments (e.g. C:\\folder -g user:(F,M)): ";
    std::wcout.flush();
    std::wstring args;
    if (!std::getline(std::wcin, args))
    {
        return;
    }
    DWORD rc = AddSidAce(args);
    if (rc != ERROR_SUCCESS)
    {
        std::wcout << L"[-] Add failed. Error code: " << rc << L"\n";
    }
}

static void run_remove()
{
    std::wcout << L"Arguments (e.g. -d user1 C:\\folder -r): ";
    std::wcout.flush();
    std::wstring args;
    if (!std::getline(std::wcin, args))
    {
        return;
    }
    if (!RemoveSidAce(args))
    {
        std::wcout << L"[-] Remove failed.\n";
    }
}

int main()
{
    // Enable wide (UTF-16) console mode so Unicode output prints correctly.
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    for (;;)
    {
        print_banner();
        std::wstring line;
        if (!std::getline(std::wcin, line))
        {
            break;
        }

        if (line == L"1")
        {
            run_enum();
        }
        else if (line == L"2")
        {
            run_add();
        }
        else if (line == L"3")
        {
            run_remove();
        }
        else if (line == L"0" || line == L"q" || line == L"quit" || line == L"exit")
        {
            break;
        }
        else if (!line.empty())
        {
            std::wcout << L"[-] Unknown option: " << line << L"\n";
        }
    }
    return 0;
}
