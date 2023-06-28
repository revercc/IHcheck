# IHcheck
It can detect if another process's dll module is inline hook, provided that the dll module is not shell, currently only supports x86 architecture
# use
Import inline_hook_check.cpp and inline_hook_check.h into your project. See how to use them in the demo.cpp file.

① You can set which modules of the third-party process you want to detect. The WGLogin.dll and SSOPlatform.dll that detect the wegame.exe process are set in demo.cpp
```
//init check list
std::list<std::wstring> wegame_inline_check_list = {};
TCHAR WGLogin_path[MAX_PATH] = { 0 };
wcscpy(WGLogin_path, wegame_directory);
wcscat(WGLogin_path, L"\\WGLogin.dll");
wegame_inline_check_list.insert(wegame_inline_check_list.begin(), { WGLogin_path });
TCHAR SSOPlatform_path[MAX_PATH] = { 0 };
wcscpy(SSOPlatform_path, wegame_directory);
wcscat(SSOPlatform_path, L"\\txsso\\Bin\\SSOPlatform.dll");
wegame_inline_check_list.insert(wegame_inline_check_list.begin(), { SSOPlatform_path });
```
② You can set the inline hook check to scan the address whitelist by setting the feature code.For example, the address whitelist of SSOPlatform.dll is set in demo.cpp. This address is the data, and it will change during the program running, so that the inline hook check will generate false positives.

```
// init white addr mark list
std::list<IHcheck::WHITE_MARK> wegame_white_addr_mark_list = {};
IHcheck::WHITE_MARK white_mark_tmp;
white_mark_tmp.mark_string = "8B45E48B008B4DF064890D00000000595f5e5bc9";
white_mark_tmp.module_name = SSOPlatform_path;
white_mark_tmp.offset = -0x4;
white_mark_tmp.size = 4;
wegame_white_addr_mark_list.insert(wegame_white_addr_mark_list.begin(), { white_mark_tmp });
```
③ Finally, create the CInlineHookCheck object and pass in the process pid, inline_check_list, and white_addr_mark_list。If the last parameter is set to true, all modules are detected by default。
```
// inline hook check
IHcheck::CInlineHookCheck inline_check(
    pi.dwProcessId, 
    wegame_inline_check_list, 
    wegame_white_addr_mark_list,
    true);
```