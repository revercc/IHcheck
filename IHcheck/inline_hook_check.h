#pragma once
/*
#define UNICODE
#define _UNICODE
*/
#include <list>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

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

        void start_hook_check();
        bool set_debug_privilege();
        ULONG rva_to_va(PVOID buffer, ULONG rva);
        PVOID copy_module(HANDLE hProcess, PVOID file_buffer, size_t file_size, HMODULE old_module, DWORD size_of_image);
        int do_reloc_import_table(HANDLE hProcess, DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module, PVOID file_buffer);
        int do_reloc_table(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module, PVOID file_buffer);
        int strip_reloc(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module);
        bool delete_inline_hook(HANDLE hProcess, PVOID old_module, PVOID file_text_section, DWORD size);
        int cmp_text_segment(HANDLE hProcess, PVOID old_module, PVOID new_module, PVOID file_buffer, std::list<ULONG_PTR>& white_addr_list);
        PVOID find_export_address(PVOID new_module, DWORD function_ordinal, MODULEENTRY32 module_info, char* function_name);
        MODULEENTRY32 get_target_process_module(std::wstring module_name);
        int is_window10();

    private:
        PVOID FsRedirection_old_value;
        unsigned int timer_id;
        unsigned int target_pid;
        std::list<std::wstring> inline_check_list;
        std::list<IHcheck::WHITE_MARK> white_mark_list;
    };
}