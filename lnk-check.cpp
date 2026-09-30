#include "lnk-check.h"
#include "utils.h"

BOOL is_lnk_file(std::wstring file_path)
{
	std::wstring ext = file_path.substr(file_path.find_last_of(L'.') + 1);
	std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
	return (ext == L"lnk");
}

std::wstring resolve_lnk_path(std::wstring lnk_path)
{
	std::wstringstream logger;
	IShellLink* psl;
	WCHAR szGotPath[MAX_PATH]{ 0 };
	WIN32_FIND_DATA wfd;
	HRESULT hr = CoInitialize(NULL);
	HRESULT hres;
	std::wstring outputPath = lnk_path;
	if (FAILED(hr))
	{
		logger << L"Failed to initialize COM." << std::endl;
		print_line(logger.str());
		logger.str(L"");
		return std::wstring();
	}

	hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
	if (SUCCEEDED(hres))
	{
		IPersistFile* ppf;

		// Get a pointer to the IPersistFile interface.
		hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
		if (SUCCEEDED(hres))
		{
			// Load the shortcut.
			hres = ppf->Load(lnk_path.c_str(), STGM_READ);

			if (SUCCEEDED(hres))
			{
				// Resolve the shortcut.
				hres = psl->Resolve(NULL, 0);
				if (SUCCEEDED(hres))
				{
					// Get the path of the shortcut target.
					hres = psl->GetPath(szGotPath, MAX_PATH, (WIN32_FIND_DATA*)&wfd, SLGP_RAWPATH);
					if (SUCCEEDED(hres))
					{
						outputPath.assign(szGotPath);
					}
				}
			}
			// Release the pointer to the IPersistFile interface.
			ppf->Release();
		}
		// Release the pointer to the IShellLink interface.
		psl->Release();
	}
	CoUninitialize();
	return outputPath;
}
