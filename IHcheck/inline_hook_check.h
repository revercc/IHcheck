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
        size_t size;
    }WHITE_MARK, * PWHITE_MARK;
    
    typedef struct _WHITE_ADDRESS {
        ULONG_PTR address;
        size_t size;
    }WHITE_ADDRESS, * PWHITE_ADDRESS;

    class CInlineHookCheck
    {
    public:
        CInlineHookCheck(unsigned int pid, std::list<std::wstring> check_list, std::list<IHcheck::WHITE_MARK> white_addr_mark_list, bool is_all);
        ~CInlineHookCheck();

        void start_hook_check();
        bool set_debug_privilege();
        ULONG rva_to_va(PVOID buffer, ULONG rva);
        PVOID copy_module(HANDLE hProcess, PVOID file_buffer, size_t file_size, HMODULE old_module, DWORD size_of_image);
        int strip_function_forward(PVOID file_buffer, PVOID new_module);
        int do_reloc_import_table(HANDLE hProcess, DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module, PVOID file_buffer);
        int do_reloc_table(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module, PVOID file_buffer);
        int strip_reloc(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module);
        void init_white_addr_list(PVOID new_module, DWORD size_of_image, MODULEENTRY32 module32_info);
        bool delete_inline_hook(HANDLE hProcess, PVOID old_module, PVOID file_text_section, DWORD size);
        int cmp_text_segment(HANDLE hProcess, PVOID old_module, PVOID new_module, PVOID file_buffer, std::list<WHITE_ADDRESS>& white_addr_list);
        std::wstring parse_opcode(void* base, unsigned char *address, size_t size, size_t* parsed_size, uint64_t* module_offset);
        int is_window10();

    private:
        //PVOID FsRedirection_old_value;
        unsigned int timer_id;
        unsigned int target_pid;
        bool is_check_all_module;
        std::list<std::wstring> inline_check_list;
        std::list<IHcheck::WHITE_MARK> white_mark_list;
        std::list<WHITE_ADDRESS> white_addr_list;
    };
}