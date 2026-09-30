#include "remove-per.h"
#include "utils.h"
#include <shellapi.h>


BOOL RemoveSidAce(const std::wstring& args)
{
    std::wstring filePath;
    std::wstring username;
    BOOL recursive = FALSE;
    std::wstringstream logger;
    // Get the existing DACL
    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    LPWSTR* szArglist;
    int nArgs;
    // Parse the argument line.
    szArglist = CommandLineToArgvW(args.c_str(), &nArgs);

    if (NULL == szArglist)
    {
        logger << L"CommandLineToArgvW failed\n";
        print_line(logger.str());
        logger.str(L"");
        return FALSE;
    }
    std::vector<std::wstring> argsVec(szArglist, szArglist + nArgs);
    LocalFree(szArglist);

    for (int i = 0; i < nArgs; i++)
    {
        if (argsVec[i] == L"-d" && i + 1 < nArgs)
        {
            username = argsVec[++i];
        }
        else if (argsVec[i] == L"-r")
        {
            recursive = TRUE;
        }
        else
        {
            filePath = argsVec[i];
        }
    }

    if (filePath.empty())
    {
        logger << L"Empty FilePath\n";
        print_line(logger.str());
        logger.str(L"");
        return FALSE;
    }

    if (username.empty())
    {
        logger << L"Empty Username (use -d <user>)\n";
        print_line(logger.str());
        logger.str(L"");
        return FALSE;
    }

    DWORD attrs = GetFileAttributesW(filePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        logger << L"Failed to get file attributes. Error: " << GetLastError() << std::endl;
        print_line(logger.str());
        logger.str(L"");
        return FALSE;
    }

    std::vector<std::wstring>fileList;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY && recursive == TRUE)
    {
        list_files(filePath, fileList);
    }
    else
    {
        fileList.push_back(filePath);
    }

    // Resolve the username to a SID string once, outside the file loop.
    std::wstring userSidString = get_sid_string(username);
    if (userSidString.empty())
    {
        logger << L"LookupAccountName failed for user: " << username << std::endl;
        print_line(logger.str());
        logger.str(L"");
        return FALSE;
    }

    PSID userSid = NULL;
    if (!ConvertStringSidToSidW(userSidString.c_str(), &userSid))
    {
        logger << L"ConvertStringSidToSid failed.\n";
        print_line(logger.str());
        logger.str(L"");
        return FALSE;
    }

    for (size_t i = 0; i < fileList.size(); i++)
    {
        DWORD result = GetNamedSecurityInfoW(
            fileList[i].c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            &pOldDacl,
            NULL,
            &pSD
        );

        if (result != ERROR_SUCCESS)
        {
            logger << L"GetNamedSecurityInfo failed: " << result << std::endl;
            print_line(logger.str());
            logger.str(L"");
            LocalFree(userSid);
            return false;
        }

        // Initialize a new ACL with enough space
        ACL_SIZE_INFORMATION aclSizeInfo;
        if (!GetAclInformation(pOldDacl, &aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
        {
            logger << L"GetAclInformation failed\n";
            print_line(logger.str());
            logger.str(L"");
            LocalFree(pSD);
            LocalFree(userSid);
            return false;
        }

        // Allocate memory for the new ACL
        DWORD newAclSize = aclSizeInfo.AclBytesInUse;
        PACL pNewDacl = (PACL)LocalAlloc(LPTR, newAclSize);
        if (!InitializeAcl(pNewDacl, newAclSize, ACL_REVISION))
        {
            logger << L"InitializeAcl failed\n";
            print_line(logger.str());
            logger.str(L"");
            LocalFree(pSD);
            LocalFree(pNewDacl);
            LocalFree(userSid);
            return false;
        }

        // Iterate over each ACE in the old ACL, copy if it does not match userSid
        for (DWORD j = 0; j < aclSizeInfo.AceCount; j++)
        {
            LPVOID pAce = NULL;
            if (!GetAce(pOldDacl, j, &pAce))
            {
                logger << L"GetAce failed\n";
                print_line(logger.str());
                logger.str(L"");
                LocalFree(pSD);
                LocalFree(pNewDacl);
                LocalFree(userSid);
                return false;
            }

            // Get the SID from the ACE
            PSID pAceSid = NULL;
            ACE_HEADER* aceHeader = (ACE_HEADER*)pAce;

            if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
            {
                ACCESS_ALLOWED_ACE* accessAce = (ACCESS_ALLOWED_ACE*)pAce;
                pAceSid = (PSID) & (accessAce->SidStart);
            }
            else if (aceHeader->AceType == ACCESS_DENIED_ACE_TYPE)
            {
                ACCESS_DENIED_ACE* deniedAce = (ACCESS_DENIED_ACE*)pAce;
                pAceSid = (PSID) & (deniedAce->SidStart);
            }
            else
            {
                // For other ACE types, copy them anyway
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAce, ((PACE_HEADER)pAce)->AceSize))
                {
                    logger << L"AddAce failed\n";
                    print_line(logger.str());
                    logger.str(L"");
                    LocalFree(pSD);
                    LocalFree(pNewDacl);
                    LocalFree(userSid);
                    return false;
                }
                continue;
            }

            // Compare the ACE SID to userSid
            if (!EqualSid(pAceSid, userSid))
            {
                // Copy the ACE when the SID does not match
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAce, aceHeader->AceSize))
                {
                    logger << L"AddAce failed\n";
                    print_line(logger.str());
                    logger.str(L"");
                    LocalFree(pSD);
                    LocalFree(pNewDacl);
                    LocalFree(userSid);
                    return false;
                }
            }
        }


        // Set the new DACL back on the file
        result = SetNamedSecurityInfoW(
            (LPWSTR)fileList[i].c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            pNewDacl,
            NULL
        );

        LocalFree(pSD);
        LocalFree(pNewDacl);
        pSD = NULL;
        pOldDacl = NULL;

        if (result != ERROR_SUCCESS)
        {
            logger << L"SetNamedSecurityInfo failed " << fileList[i] << L" " << result << std::endl;
            print_line(logger.str());
            logger.str(L"");
        }
    }

    LocalFree(userSid);
    print_line(L"Final Removed DACL for user");
    return true;
}

std::wstring get_sid_string(std::wstring name)
{
    if (name.empty())
    {
        return std::wstring();
    }

    std::vector<BYTE> bSID(SECURITY_MAX_SID_SIZE, 0);
    WCHAR szDomainName[256];
    DWORD dwDomainSize = sizeof(WCHAR) * 256;
    BOOL bRVal;
    DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
    LPTSTR szSID = NULL;
    SID_NAME_USE snu = SidTypeInvalid;


    bRVal = LookupAccountNameW(
        NULL,
        name.c_str(),
        bSID.data(),
        &dwSidSize,
        szDomainName,
        &dwDomainSize,
        &snu
    );
    bRVal = ConvertSidToStringSid(bSID.data(), &szSID);
    if (bRVal)
    {
        std::wstring result(szSID);
        LocalFree(szSID);
        return result;
    }
    return std::wstring();
}
