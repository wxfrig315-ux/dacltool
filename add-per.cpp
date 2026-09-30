#include "add-per.h"


std::map<std::wstring, DWORD> permissionMappings
{
    { L"F",  GENERIC_ALL },                          // Full control
    { L"M",  FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE },  // Modify
    { L"RX", FILE_GENERIC_READ | FILE_GENERIC_EXECUTE }, // Read & execute
    { L"R",  FILE_GENERIC_READ },                    // Read-only
    { L"W",  FILE_GENERIC_WRITE } ,
     { L"D", DELETE },
    { L"RC", READ_CONTROL },
    { L"WDAC", WRITE_DAC },
    { L"WO", WRITE_OWNER },
    { L"S", SYNCHRONIZE },
    { L"AS", ACCESS_SYSTEM_SECURITY },
    { L"MA", MAXIMUM_ALLOWED },
    { L"GR", GENERIC_READ },
    { L"GW", GENERIC_WRITE },
    { L"GE", GENERIC_EXECUTE },
    { L"GA", GENERIC_ALL },
    { L"RD", FILE_READ_DATA },
    { L"WD", FILE_WRITE_DATA },
    { L"AD", FILE_APPEND_DATA },
    { L"REA", FILE_READ_EA },
    { L"WEA", FILE_WRITE_EA },
    { L"X", FILE_EXECUTE },
    { L"DC", FILE_DELETE_CHILD },
    { L"RA", FILE_READ_ATTRIBUTES },
    { L"WA", FILE_WRITE_ATTRIBUTES }// Write-only
};

DWORD AddSidAce(const std::wstring& args)
{
    std::wstring pszObjName;         // name of object
    std::wstring pszTrustee;         // trustee for the new ACE
    DWORD dwAccessRights{};          // access mask for the new ACE
    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    std::wstringstream logger;
    std::wstring err;
    std::vector<std::wstring> argsVec;

    LPWSTR* szArglist;
    int nArgs;
    // Parse the argument line.
    szArglist = CommandLineToArgvW(args.c_str(), &nArgs);

    if (NULL == szArglist)
    {
        logger << L"CommandLineToArgvW failed\n";
        print_line(logger.str());
        logger.str(L"");
        return ERROR_INVALID_PARAMETER;
    }
    argsVec.assign(szArglist, szArglist + nArgs);
    LocalFree(szArglist);

    for (int i = 0; i < nArgs; i++)
    {
        if (argsVec[i] == L"-g" && i + 1 < nArgs)
        {
            err.clear();
            std::pair<std::wstring, DWORD> tmp = ParseICaclsEntry(argsVec[++i], err);
            if (!err.empty())
            {
                print_line(err);
            }
            pszTrustee = tmp.first;
            dwAccessRights = tmp.second;
        }
        else
        {
            pszObjName = argsVec[i];
        }
    }
    if (pszObjName.empty())
    {
        logger << L"Empty FilePath \n";
        print_line(logger.str());
        logger.str(L"");
        return ERROR_INVALID_PARAMETER;
    }

    // Get a pointer to the existing DACL.
    dwRes = GetNamedSecurityInfoW(
        pszObjName.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &pOldDACL, NULL, &pSD);

    if (ERROR_SUCCESS != dwRes)
    {
        logger << L"GetNamedSecurityInfo Error " << dwRes << std::endl;
        print_line(logger.str());
        logger.str(L"");
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for the new ACE.
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.ptstrName = (LPWCH)pszTrustee.c_str();

    // Create a new ACL that merges the new ACE
    // into the existing DACL.
    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes)
    {
        logger << L"SetEntriesInAcl Error " << dwRes << std::endl;
        print_line(logger.str());
        logger.str(L"");
        goto Cleanup;
    }

    // Attach the new ACL as the object's DACL.
    dwRes = SetNamedSecurityInfo((LPWSTR)pszObjName.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes)
    {
        logger << L"SetNamedSecurityInfo Error " << dwRes << std::endl;
        print_line(logger.str());
        logger.str(L"");
        goto Cleanup;
    }

Cleanup:

    if (pSD != NULL)
    {
        LocalFree((HLOCAL)pSD);
    }
    if (pNewDACL != NULL)
    {
        LocalFree((HLOCAL)pNewDACL);
    }
    print_line(L"Final Added DACL for user");
    return dwRes;
}

std::pair<std::wstring, DWORD> ParseICaclsEntry(std::wstring input, std::wstring& err)
{
    if (input.empty())
    {
        err = L"Empty Parameter\n";
        return std::pair<std::wstring, DWORD>();
    }

    size_t colonPos = input.find(L':');
    if (colonPos == std::wstring::npos)
    {
        err = L"Invalid input missing \":\"\n";
        return std::pair<std::wstring, DWORD>();
    }
    std::pair<std::wstring, DWORD> result;
    result.first = input.substr(0, colonPos);

    size_t openParen = input.find(L"(", colonPos);
    size_t closeParen = input.find(L")", openParen);

    std::wstring perBlock = input.substr(openParen + 1, closeParen - openParen - 1);
    std::wstringstream ss(perBlock);

    std::wstring token;
    while (std::getline(ss, token, L','))
    {
        if (permissionMappings.find(token) != permissionMappings.end())
        {
            result.second |= permissionMappings[token];
        }
        else
        {
            err = L"Failed extract permission: " + token + L"\n";
            return std::pair<std::wstring, DWORD>();
        }
    }
    return result;
}
