#pragma once
/*
#define UNICODE
#define _UNICODE
*/
#include <list>
#include <string>
#include <Windows.h>

namespace IHcheck {
    typedef struct _WHITE_MARK {
        std::wstring module_name;
        std::string mark_string;
        int offset;
    }WHITE_MARK, * PWHITE_MARK;
    
    class CInlineHookCheck
    {
    public:
        CInlineHookCheck(unsigned int pid, std::list<std::wstring> check_list, std::list<IHcheck::WHITE_MARK> white_addr_mark_list);
        ~CInlineHookCheck();

        void inline_hook_check();
        static unsigned int __stdcall check_thread(void* lpThreadParameter);
        static void __stdcall timer_call_back(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime);
        static bool set_debug_privilege();
        static ULONG rva_to_va(PVOID buffer, ULONG rva);
        static PVOID CopyTargetModule(HANDLE hProcess, HMODULE old_module, DWORD size_of_image);
        static int AddReloc(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module, PVOID file_buffer);
        static int StripReloc(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module);
        static bool DeleteInlineHook(HANDLE hProcess, PVOID old_module, PVOID file_text_section, DWORD size);
        static int CmpTextSegment(HANDLE hProcess, PVOID old_module, PVOID new_module, PVOID file_buffer, std::list<ULONG_PTR>& white_addr_list);
    private:
        static unsigned int timer_id;
        static unsigned int target_pid;
        static std::list<std::wstring> inline_check_list;
        static std::list<IHcheck::WHITE_MARK> white_mark_list;
    };
}