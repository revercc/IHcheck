#include "inline_hook_check.h"
int main(int argc, char* argv[], char* envp[])
{
    // get wegame directory
    DWORD dwLen = MAX_PATH;
    TCHAR wegame_directory[MAX_PATH] = { 0 };
    if (!RegGetValue(
        HKEY_CURRENT_USER,
        L"wegame\\DefaultIcon",
        NULL, RRF_RT_ANY,
        NULL,
        wegame_directory,
        &dwLen)) {
        wchar_t* sub_str = wcsrchr(wegame_directory, L'\\');
        *sub_str = 0;
    }
    //get wegame path
    TCHAR wegame_path[MAX_PATH] = { 0 };
    wcscpy(wegame_path, wegame_directory);
    wcscat(wegame_path, L"\\wegame.exe");

    //init check list
    std::list<std::wstring> wegame_inline_check_list = {};
    TCHAR WGLogin_path[MAX_PATH] = { 0 };
    wcscpy(WGLogin_path, wegame_directory);
    wcscat(WGLogin_path, L"\\WGLogin.dll");
    wegame_inline_check_list.insert(wegame_inline_check_list.begin(), { WGLogin_path });
    TCHAR SSOPlatform_path[MAX_PATH] = { 0 };
    wcsnset(SSOPlatform_path, 0, MAX_PATH);
    wcscpy(SSOPlatform_path, wegame_directory);
    wcscat(SSOPlatform_path, L"\\txsso\\Bin\\SSOPlatform.dll");
    wegame_inline_check_list.insert(wegame_inline_check_list.begin(), { SSOPlatform_path });

    // init white addr mark list
    std::list<IHcheck::WHITE_MARK> wegame_white_addr_mark_list = {};
    IHcheck::WHITE_MARK white_mark_tmp;
    white_mark_tmp.mark_string = "8B45E48B008B4DF064890D00000000595f5e5bc9";
    white_mark_tmp.module_name = SSOPlatform_path;
    white_mark_tmp.offset = -0x4;
    white_mark_tmp.size = 4;
    wegame_white_addr_mark_list.insert(wegame_white_addr_mark_list.begin(), { white_mark_tmp });
    
    // create wegame.exe process
    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    PROCESS_INFORMATION pi = { 0 };
    CreateProcess(
        wegame_path,
        NULL,
        NULL,
        NULL,
        FALSE,
        NULL,
        NULL,
        NULL,
        &si,
        &pi);
    Sleep(1000);
    // inline hook check
    IHcheck::CInlineHookCheck inline_check(
        pi.dwProcessId, 
        wegame_inline_check_list, 
        wegame_white_addr_mark_list);
    system("pause");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}