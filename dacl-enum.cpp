#include "dacl-enum.h"
#include <shellapi.h>



BOOL list_files(std::wstring file_path_wstr, std::vector<std::wstring> &file_lists)
{
    HANDLE handle_find;
    WIN32_FIND_DATA ffd_this;
	std::wstring this_spec_wstr = file_path_wstr + L"\\*.*";

    handle_find = FindFirstFile(this_spec_wstr.c_str(), &ffd_this);
    if (handle_find == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
	do {
		if (wcscmp(ffd_this.cFileName, L".") != 0 && wcscmp(ffd_this.cFileName, L"..") != 0)
		{
			if (ffd_this.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				std::wstring temp_path_wstr = file_path_wstr + L"\\" + ffd_this.cFileName;
                file_lists.push_back(temp_path_wstr);
				list_files(temp_path_wstr, file_lists);
			}
			else
			{
				std::wstring temp_path_wstr = file_path_wstr + L"\\" + ffd_this.cFileName;
                file_lists.push_back(temp_path_wstr);
			}
		}
	} while (FindNextFile(handle_find, &ffd_this) != 0);

	if (GetLastError() != ERROR_NO_MORE_FILES)
	{
		FindClose(handle_find);
		return false;
	}

	FindClose(handle_find);
	handle_find = INVALID_HANDLE_VALUE;


	return true;
}



// Convert a SID to its readable string form.
std::wstring sid_to_wstring(PSID sid)
{
    LPWSTR sidStr = nullptr;
    if (ConvertSidToStringSid(sid, &sidStr))
    {
        std::wstring result(sidStr);
        LocalFree(sidStr);
        return result;
    }
    return L"<Invalid SID>";
}

// Print an access mask in human-readable form.
std::wstring access_mask_to_string(DWORD mask)
{
    struct AccessEntry { DWORD flag; const wchar_t* name; };
    AccessEntry accessRights[] = {
        { FILE_READ_DATA,       L"FILE_READ_DATA" },
        { FILE_WRITE_DATA,      L"FILE_WRITE_DATA" },
        { FILE_APPEND_DATA,     L"FILE_APPEND_DATA" },
        { FILE_EXECUTE,         L"FILE_EXECUTE" },
        { FILE_READ_ATTRIBUTES, L"FILE_READ_ATTRIBUTES" },
        { FILE_WRITE_ATTRIBUTES,L"FILE_WRITE_ATTRIBUTES" },
        { FILE_READ_EA,         L"FILE_READ_EA" },
        { FILE_WRITE_EA,        L"FILE_WRITE_EA" },
        { DELETE,               L"DELETE" },
        { READ_CONTROL,         L"READ_CONTROL" },
        { WRITE_DAC,            L"WRITE_DAC" },
        { WRITE_OWNER,          L"WRITE_OWNER" },
        { SYNCHRONIZE,          L"SYNCHRONIZE" },
        { GENERIC_READ,         L"GENERIC_READ" },
        { GENERIC_WRITE,        L"GENERIC_WRITE" },
        { GENERIC_EXECUTE,      L"GENERIC_EXECUTE" },
        { GENERIC_ALL,          L"GENERIC_ALL" },
        { ACCESS_SYSTEM_SECURITY , L"ACCESS_SYSTEM_SECURITY" },
        { FILE_DELETE_CHILD , L"FILE_DELETE_CHILD" },
        { FILE_ALL_ACCESS	,L"FILE_ALL_ACCESS"},
        { STANDARD_RIGHTS_ALL, L"STANDARD_RIGHTS_ALL"}

    };

    std::wstring access_mask;
    bool first = true;
    for (const AccessEntry& entry : accessRights)
    {
        if (mask & entry.flag)
        {
            if (!first)
            {
                access_mask += L", ";
            }
            access_mask += entry.name;
            first = false;
        }
    }
    return access_mask;
}

std::wstringstream get_dac(std::wstring folderPath)
{
    std::wstringstream logger;
    std::vector<size_t> col_widths = { 60, 30, 30, 30 };
    std::vector<std::vector<std::wstring>> table_data;
    table_data.push_back(
        {
              {L"SID" ,L"Name",L"Type" ,L"AccessMask"}
        });

    HANDLE hImpersonationToken = GetCurrentThreadEffectiveToken();

    if (hImpersonationToken == INVALID_HANDLE_VALUE)
    {
        logger << L"INVALID HANDLE VALUE";
        print_line(logger.str());
        logger.str(L"");
        return std::wstringstream();
    }

    std::wstring resolve_dir = folderPath;
    // Resolve the path when the input is a shortcut file.
    if (is_lnk_file(folderPath))
    {
        resolve_dir = resolve_lnk_path(folderPath);
        logger << L"Resolve lnk path: " << resolve_dir;
        print_line(logger.str());
        logger.str(L"");
    }


    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDACL = NULL;
    DWORD result = GetNamedSecurityInfoW(
        resolve_dir.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
        NULL, NULL, &pDACL, NULL, &pSD
    );

    if (result != ERROR_SUCCESS || !pDACL)
    {
        logger << L"GetNamedSecurityInfo failed. Error: " << result << std::endl;
        print_line(logger.str());
        logger.str(L"");

        return std::wstringstream();
    }

    logger << L"\n--- DACL for: " << resolve_dir << L" ---" << std::endl;
    print_line(logger.str());
    logger.str(L"");


    for (DWORD i = 0; i < pDACL->AceCount; ++i)
    {

        LPVOID pAce = nullptr;
        if (!GetAce(pDACL, i, &pAce))
        {
            continue;
        }

        ACE_HEADER* header = (ACE_HEADER*)pAce;
        std::wstring aceType;
        ACCESS_MASK mask = 0;
        PSID aceSid = nullptr;

        // Handle only standard ALLOW/DENY ACEs.
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE)
        {
            ACCESS_ALLOWED_ACE* ace = (ACCESS_ALLOWED_ACE*)pAce;
            aceType = L"ACCESS_ALLOWED_ACE_TYPE";
            mask = ace->Mask;
            aceSid = (PSID)&ace->SidStart;
        }
        else if (header->AceType == ACCESS_DENIED_ACE_TYPE)
        {
            ACCESS_DENIED_ACE* ace = (ACCESS_DENIED_ACE*)pAce;
            aceType = L"ACCESS_DENIED_ACE_TYPE";
            mask = ace->Mask;
            aceSid = (PSID)&ace->SidStart;
        }
        else
        {
            logger << L"ACE " << i << L": Unsupported ACE type. Skipping." << std::endl;
            print_line(logger.str());
            logger.str(L"");
            continue;
        }

        // Validate the SID before checking token membership.
        BOOL isMatch = FALSE;
        if (IsValidSid(aceSid))
        {
            if (!CheckTokenMembership(hImpersonationToken, aceSid, &isMatch))
            {
                logger << L"CheckTokenMembership failed for ACE " << i << L". Error: " << GetLastError() << std::endl;
                print_line(logger.str());
                logger.str(L"");
            }
        }
        else
        {
            logger << L"ACE " << i << L": Invalid SID. Skipping." << std::endl;
            print_line(logger.str());
            logger.str(L"");
            continue;
        }

        if (isMatch)
        {
            std::vector<std::wstring> row{};
            WCHAR lpName[2048]{ 0 };
            WCHAR lpDomain[2048]{ 0 };
            SID_NAME_USE SNU{};
            DWORD dwSize = 2048;
            LookupAccountSid(NULL, aceSid, lpName, &dwSize, lpDomain, &dwSize, &SNU);
            std::wstring name = lpName;
            std::wstring domain = lpDomain;

            row.push_back(sid_to_wstring(aceSid));
            row.push_back(domain + L"\\" + name);
            row.push_back(aceType);
            row.push_back(access_mask_to_string(mask));
            table_data.push_back(row);
        }

    }
    if (pSD)
    {
        LocalFree(pSD);
    }

    CloseHandle(hImpersonationToken);
    return generate_table(table_data, col_widths);
}


// Check whether each ACE holds a valid SID and matches the current token.
void analyze_dac_with_token(const std::wstring& args)
{

    std::wstringstream logger;
    std::wstring dir_path;
    std::wstring file_path;
    bool check_recursive = FALSE;
    std::map<std::wstring, std::wstring> otp = parse_arg(args);

    if (otp.empty())
    {
        logger << L"Empty parameter";
        print_line(logger.str());
        logger.str(L"");
        goto END_LABEL;
    }

    if (otp.find(L"dir") != otp.end())
    {
        dir_path = otp[L"dir"];
    }

    if (otp.find(L"file") != otp.end())
    {
        file_path = otp[L"file"];
    }

    if (otp.find(L"recursive") != otp.end())
    {
        check_recursive = TRUE;
    }


    if (dir_path.empty() && file_path.empty())
    {
        logger << L"Error: Missing dir argument";
        print_line(logger.str());
        logger.str(L"");
        goto END_LABEL;
    }

    if (!dir_path.empty())
    {
        if (check_recursive == TRUE)
        {
            std::vector<std::wstring> lf;
            list_files(dir_path, lf);
            for (size_t i = 0; i < lf.size(); i++)
            {
                logger = get_dac(lf[i]);
                print_line(logger.str());
                logger.str(L"");
            }
        }
        else
        {
            logger = get_dac(dir_path);
            print_line(logger.str());
            logger.str(L"");
        }

    }
    else if (!file_path.empty())
    {
        if (check_recursive == TRUE)
        {
            logger << L"Error: Don't use option -r for file path";
            print_line(logger.str());
            logger.str(L"");
            goto END_LABEL;
        }
        else
        {
            logger = get_dac(file_path);
            print_line(logger.str());
            logger.str(L"");
        }

    }
END_LABEL:
    print_line(L"--------- END PROCCESSING ENUM DACLS --------");
}

std::map<std::wstring, std::wstring> parse_arg(const std::wstring& input)
{
    std::wstringstream logger;
    std::map<std::wstring, std::wstring> options;
    std::vector<std::wstring> args;

    LPWSTR* szArglist;
    int nArgs;
    DWORD attr;
    // Parse the argument line.
    szArglist = CommandLineToArgvW(input.c_str(), &nArgs);

    if (NULL == szArglist)
    {
        logger << L"CommandLineToArgvW failed\n";
        print_line(logger.str());
        return std::map<std::wstring, std::wstring>();
    }

    args.assign(szArglist, szArglist + nArgs);

    for (int i = 0; i < nArgs; ++i)
    {
        std::wstring arg = args[i];
        if (arg == L"-r")
        {
            options[L"recursive"] = L"TRUE";
        }
        else
        {
            attr = GetFileAttributesW(arg.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES)
            {
                logger << L"Invalid file path: " << arg << L" " << GetLastError();
                print_line(logger.str());
                logger.str(L"");
                return std::map<std::wstring, std::wstring>();
            }
            else if (attr & FILE_ATTRIBUTE_DIRECTORY)
            {
                options[L"dir"] = arg;
            }
            else
            {
                options[L"file"] = arg;
            }
        }
    }
    LocalFree(szArglist);
    return options;
}
