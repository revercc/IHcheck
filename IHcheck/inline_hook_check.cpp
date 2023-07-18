#include "inline_hook_check.h"
#include <capstone/capstone/capstone.h>
#include <Windows.h>
#include <WinBase.h>
#include <Psapi.h>
#include <tchar.h>
#include <Locale.h>
#include <tlhelp32.h>

#ifdef _X86_
#pragma comment(lib, "../sysroot/lib/capstone.lib")
#else
#endif
#pragma warning(disable : 4996)
using namespace IHcheck;
PVOID ReadFileToMemoryW(const wchar_t* file_path, size_t* p_file_size)
{
    PVOID pfile_buffer = NULL;
    if (file_path == NULL) {
        return 0;
    }
    FILE* pFile = NULL;
    pFile = _tfopen(file_path, L"rb");
    if (NULL != pFile) {
        if (0 == fseek(pFile, 0, SEEK_END)) {
            int file_size = ftell(pFile);
            if (-1 != file_size) {
                *p_file_size = file_size;
                pfile_buffer = malloc(file_size);
                if (pfile_buffer != NULL) {
                    memset(pfile_buffer, 0, file_size);
                    if (0 == fseek(pFile, 0, SEEK_SET) &&
                        1 == fread(pfile_buffer, file_size, 1, pFile)) {
                        fclose(pFile);
                        return pfile_buffer;
                    }
                    free(pfile_buffer);
                }
            }
        }
        fclose(pFile);
    }
    return 0;
}

PVOID ReadFileToMemory(const char* file_path, size_t* p_file_size)
{
    PVOID pfile_buffer = NULL;
    if (file_path == NULL) {
        return 0;
    }
    FILE* pFile = NULL;
    pFile = fopen(file_path, "rb");
    if (NULL != pFile) {
        if (0 == fseek(pFile, 0, SEEK_END)) {
            int file_size = ftell(pFile);
            if (-1 != file_size) {
                *p_file_size = file_size;
                pfile_buffer = malloc(file_size);
                if (pfile_buffer != NULL) {
                    memset(pfile_buffer, 0, file_size);
                    if (0 == fseek(pFile, 0, SEEK_SET) &&
                        1 == fread(pfile_buffer, file_size, 1, pFile)) {
                        fclose(pFile);
                        return pfile_buffer;
                    }
                    free(pfile_buffer);
                }
            }
        }
        fclose(pFile);
    }
    return 0;
}

size_t HexStrToByteArr(const char* pHexStr, BYTE*& pOutBytePtr)
{
    pOutBytePtr = nullptr;
    size_t nRt = 0;
    if (pHexStr) {
        size_t nLen = strlen(pHexStr);
        if (nLen % 2 == 0) {
            nRt = nLen / 2;
            pOutBytePtr = new BYTE[nRt + 1];
            pOutBytePtr[nRt] = 0;
            for (size_t i = 0; i < nLen; i += 2) {
                char ctemp = pHexStr[i];
                char cPost = 0;
                if (ctemp >= '0' && ctemp <= '9') {
                    cPost = (ctemp - '0') << 4 & 0xf0;
                }
                else if (ctemp >= 'a' && ctemp <= 'f') {
                    cPost = (ctemp - 'a' + 10) << 4 & 0xf0;
                }
                else if (ctemp >= 'A' && ctemp <= 'F') {
                    cPost = (ctemp - 'A' + 10) << 4 & 0xf0;
                }
                else {
                    nLen = 0;
                    delete[] pOutBytePtr;
                    pOutBytePtr = nullptr;
                    break;
                }
                ctemp = pHexStr[i + 1];
                if (ctemp >= '0' && ctemp <= '9') {
                    cPost += (ctemp - '0');
                }
                else if (ctemp >= 'a' && ctemp <= 'f') {
                    cPost += (ctemp - 'a' + 10);
                }
                else if (ctemp >= 'A' && ctemp <= 'F') {
                    cPost += (ctemp - 'A' + 10);
                }
                else {
                    nLen = 0;
                    delete[] pOutBytePtr;
                    pOutBytePtr = nullptr;
                    break;
                }
                pOutBytePtr[i / 2] = cPost;
            }
        }
    }
    return nRt;
}

std::string HexStrToHex(std::string strHex)
{
    std::string strRt = "";
    size_t nLen = strHex.length();
    if (nLen % 2 == 0) {
        for (size_t i = 0; i < nLen; i += 2) {
            char ctemp = strHex.at(i);
            char cPost = 0;
            if (ctemp >= '0' && ctemp <= '9') {
                cPost = (ctemp - '0') << 4 & 0xf0;
            }
            else if (ctemp >= 'a' && ctemp <= 'f') {
                cPost = (ctemp - 'a' + 10) << 4 & 0xf0;
            }
            else if (ctemp >= 'A' && ctemp <= 'F') {
                cPost = (ctemp - 'A' + 10) << 4 & 0xf0;
            }
            else {
                strRt = "";
                break;
            }
            ctemp = strHex.at(i + 1);
            if (ctemp >= '0' && ctemp <= '9') {
                cPost += (ctemp - '0');
            }
            else if (ctemp >= 'a' && ctemp <= 'f') {
                cPost += (ctemp - 'a' + 10);
            }
            else if (ctemp >= 'A' && ctemp <= 'F') {
                cPost += (ctemp - 'A' + 10);
            }
            else {
                strRt = "";
                break;
            }
            strRt += cPost;
        }
    }
    return strRt;
}

ULONG_PTR 
ScanMarkCode(
    HANDLE hProcess, 
    const char* strMarkCode,
    ULONG_PTR pStartAddr,
    size_t nScanSize,
    int nOffset,
    int nCount = 1)
{
    ULONG_PTR pRt = 0;
    PBYTE pCode = NULL;
    size_t nLen = HexStrToByteArr(strMarkCode, pCode);
    if (nLen > 0) {
        size_t nPageSize = 1024 * 1024;
        PBYTE pReadPage = new BYTE[nPageSize];
        ULONG_PTR pTmpAddr = pStartAddr;
        size_t compare_i = 0;
        size_t nAlRead = 0;
        size_t nLocalCount = 0;
        while (pTmpAddr <= pStartAddr + nScanSize) {
            if (!ReadProcessMemory(hProcess, (LPCVOID)pTmpAddr, pReadPage, nPageSize, (SIZE_T*)&nAlRead) || nAlRead < nLen) {
                break;
            }
            for (size_t i = 0; i < nAlRead; i++) {
                if (pCode[0] == pReadPage[i]) {
                    for (size_t j = 0; j < nLen - 1 && i + j + 1 < nAlRead; j++) {
                        if (pCode[j + 1] == pReadPage[i + j + 1]) {
                            compare_i++;
                        }
                        else {
                            compare_i = 0;
                            break;
                        }
                    }
                    if ((compare_i + 1) == nLen) {
                        pRt = pTmpAddr + i + nOffset;
                        nLocalCount++;
                        break;
                    }
                }
            }
            if (nLocalCount == nCount)
                break;
            pTmpAddr = pTmpAddr + nPageSize - nLen;
        }
        delete[] pReadPage;
        if (nLocalCount != nCount)
            pRt = 0;
    }
    if (pCode)
        delete[] pCode;
    return pRt;
}

bool CInlineHookCheck::set_debug_privilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

ULONG CInlineHookCheck::rva_to_va(PVOID buffer, ULONG rva)
{
    if (NULL == buffer) {
        return -1;
    }
    PIMAGE_DOS_HEADER p_dos_header = NULL;
    PIMAGE_NT_HEADERS p_nt_header = NULL;
    PIMAGE_FILE_HEADER p_pe_header = NULL;
    PIMAGE_OPTIONAL_HEADER32 p_option_header = NULL;
    PIMAGE_SECTION_HEADER p_section_header = NULL;
    int section_num = 0;
    if (buffer == NULL) {
        return 0;
    }
    if (*((PWORD)buffer) != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    p_dos_header = (PIMAGE_DOS_HEADER)buffer;
    if (*((PWORD)((PBYTE)p_dos_header + p_dos_header->e_lfanew)) != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    p_pe_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
    section_num = p_pe_header->NumberOfSections;
    p_option_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_pe_header + IMAGE_SIZEOF_FILE_HEADER);
    p_section_header = (PIMAGE_SECTION_HEADER)((PBYTE)p_option_header + p_pe_header->SizeOfOptionalHeader);
    if (rva <= p_option_header->SizeOfHeaders) {
        return rva;
    }
    else {
        for (int i = 0; i < section_num; i++) {
            if (rva >= p_section_header->VirtualAddress &&
                rva <= p_section_header->VirtualAddress + p_section_header->Misc.VirtualSize) {
                return rva - p_section_header->VirtualAddress + p_section_header->PointerToRawData;
            }
            p_section_header++;
        }
    }
    return 0;
}

int IHcheck::CInlineHookCheck::is_window10()
{
    typedef void(__stdcall* NTPROC)(DWORD*, DWORD*, DWORD*);
    HINSTANCE hInstance = LoadLibraryA("ntdll.dll");
    if (NULL != hInstance) {
        DWORD major, minor, build_num;
        NTPROC _RtlGetNtVersionNumbers = (NTPROC)GetProcAddress(hInstance, "RtlGetNtVersionNumbers");
        if (NULL != _RtlGetNtVersionNumbers) {
            _RtlGetNtVersionNumbers(&major, &minor, &build_num);
            if (major == 10 && minor == 0) {
                return 1;
            }
            else {
                return 0;
            }
        }
    }
    return -1;
}

PVOID CInlineHookCheck::copy_module(
    HANDLE hProcess, 
    PVOID file_buffer, 
    size_t file_size, 
    HMODULE old_module, 
    DWORD size_of_image)
{
    if (file_buffer == NULL ||
        old_module == NULL) {
        return NULL;
    }
    void* module_image = (UCHAR*)malloc(size_of_image);
    if (NULL != module_image) {
        memset(module_image, 0, size_of_image);
        // copy pe file header
        memcpy_s(module_image, size_of_image, file_buffer, (file_size < USN_PAGE_SIZE) ? file_size : USN_PAGE_SIZE);
        PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)file_buffer;
        PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
        PIMAGE_OPTIONAL_HEADER32 p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
        PIMAGE_SECTION_HEADER p_section_start = (PIMAGE_SECTION_HEADER)((PBYTE)p_optional_header + p_file_header->SizeOfOptionalHeader);
        // copy all section
        for (int i = 0; i < p_file_header->NumberOfSections; i++) {
            DWORD old_protect = 0;
            if (VirtualProtectEx(
                hProcess, 
                (PBYTE)old_module + p_section_start->VirtualAddress, 
                p_section_start->SizeOfRawData, 
                PAGE_EXECUTE_READ, 
                &old_protect)) {
                if (!ReadProcessMemory(
                    hProcess,
                    (PBYTE)old_module + p_section_start->VirtualAddress,
                    (PBYTE)module_image + p_section_start->VirtualAddress,
                    p_section_start->Misc.VirtualSize,
                    NULL)) {
                    free(module_image);
                    module_image = NULL;
                }
                VirtualProtectEx(
                    hProcess, 
                    (PBYTE)old_module + p_section_start->VirtualAddress,
                    p_section_start->SizeOfRawData, 
                    old_protect, 
                    &old_protect);
            }
            else{
                // windows7 kernel.dll cannot modify memory properties, Memory can be read directly
                if (!ReadProcessMemory(
                    hProcess,
                    (PBYTE)old_module + p_section_start->VirtualAddress,
                    (PBYTE)module_image + p_section_start->VirtualAddress,
                    p_section_start->Misc.VirtualSize,
                    NULL)) {
                    free(module_image);
                    module_image = NULL;
                }
            }
            p_section_start++;
        }
    }
    return module_image;
}

int CInlineHookCheck::strip_function_forward(PVOID file_buffer, PVOID new_module)
{
    if (NULL == file_buffer || NULL == new_module) {
        return -1;
    }

    PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
    PIMAGE_OPTIONAL_HEADER32 p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
    PIMAGE_DATA_DIRECTORY p_data_directory = (PIMAGE_DATA_DIRECTORY)p_optional_header->DataDirectory;
    PIMAGE_DATA_DIRECTORY p_data_directory_export = &p_data_directory[0];
    DWORD export_rva = p_data_directory_export->VirtualAddress;
    // map export descriptor
    PIMAGE_EXPORT_DIRECTORY p_map_export_descriptor = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)new_module + export_rva);
    PDWORD map_export_address_rva_array = (PDWORD)((PBYTE)new_module + p_map_export_descriptor->AddressOfFunctions);
    // file export descriptor
    PIMAGE_EXPORT_DIRECTORY p_file_export_descriptor = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)file_buffer + rva_to_va(new_module, export_rva));
    PDWORD file_export_address_rva_array = (PDWORD)((PBYTE)file_buffer + rva_to_va(new_module, p_file_export_descriptor->AddressOfFunctions));

    // enum all export function
    for (DWORD i = 0; i < p_file_export_descriptor->NumberOfFunctions; i++) {
        //PVOID p_forward_name = (PVOID)((PBYTE)file_buffer + rva_to_va(new_module, file_export_address_rva_array[i]));
        file_export_address_rva_array[i] = map_export_address_rva_array[i];
    }
    return 0;
}


int CInlineHookCheck::do_reloc_import_table(
    HANDLE hProcess, 
    DWORD entry_address, 
    PIMAGE_DATA_DIRECTORY p_data_directory_import, 
    PVOID old_module, 
    PVOID new_module, 
    PVOID file_buffer)
{
    if (new_module == NULL ||
        file_buffer == NULL ||
        entry_address == NULL ||
        p_data_directory_import == NULL ||
        (p_data_directory_import != NULL && p_data_directory_import->Size == 0)) {
        return -1;
    }
    DWORD import_rva = p_data_directory_import->VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* p_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)new_module + import_rva);
    while (p_import_descriptor->Name) {
        PIMAGE_THUNK_DATA p_file_thunk_data_INT = (PIMAGE_THUNK_DATA)((PBYTE)file_buffer + rva_to_va(new_module, p_import_descriptor->OriginalFirstThunk));
        PIMAGE_THUNK_DATA p_file_thunk_data_IAT = (PIMAGE_THUNK_DATA)((PBYTE)file_buffer + rva_to_va(new_module, p_import_descriptor->FirstThunk));
        PIMAGE_THUNK_DATA p_map_thunk_data_INT = (PIMAGE_THUNK_DATA)((PBYTE)new_module +  p_import_descriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA p_map_thunk_data_IAT = (PIMAGE_THUNK_DATA)((PBYTE)new_module + p_import_descriptor->FirstThunk);

        while (p_file_thunk_data_INT->u1.AddressOfData) {
            // change import address table
            p_file_thunk_data_IAT->u1.Function = p_map_thunk_data_IAT->u1.Function;
            // next function
            p_file_thunk_data_INT++;
            p_file_thunk_data_IAT++;
            p_map_thunk_data_INT++;
            p_map_thunk_data_IAT++;
        }
        // next dll
        p_import_descriptor++;
    }
    return 0;
}

int 
CInlineHookCheck::do_reloc_table(
    DWORD entry_address, 
    PIMAGE_DATA_DIRECTORY p_data_directory_reloc, 
    PVOID old_module, 
    PVOID new_module, 
    PVOID file_buffer) 
{
    if (new_module == NULL ||
        file_buffer == NULL ||
        entry_address == NULL ||
        p_data_directory_reloc == NULL ||
        (p_data_directory_reloc != NULL && p_data_directory_reloc->Size == 0)) {
        return -1;
    }
    DWORD relocate_rva = p_data_directory_reloc->VirtualAddress;
    PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((PBYTE)new_module + relocate_rva);
    while (p_relocate->SizeOfBlock != 0 && p_relocate->VirtualAddress != 0) {
        for (ULONG i = 0; i < p_relocate->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION); i = i + sizeof(WORD)) {
            WORD TypeOffset = *((PWORD)((PBYTE)p_relocate + sizeof(IMAGE_BASE_RELOCATION) + i));
            WORD _offset = WORD(WORD(TypeOffset << 4) >> 4);
            WORD _type = TypeOffset >> 12;
            if (0 != TypeOffset && IMAGE_REL_BASED_ABSOLUTE != _type) {
                DWORD relocate_item_rva = p_relocate->VirtualAddress + _offset;
                DWORD relocate_item_va = rva_to_va(new_module, relocate_item_rva);
                PVOID pTargetAddress = (PBYTE)file_buffer + relocate_item_va;
                *(PDWORD)pTargetAddress = *(PDWORD)pTargetAddress - entry_address + (DWORD)old_module;
            }
        }
        p_relocate = (PIMAGE_BASE_RELOCATION)((BYTE*)p_relocate + p_relocate->SizeOfBlock);
    }
    return 0;
}

int 
CInlineHookCheck::strip_reloc(
    DWORD entry_address, 
    PIMAGE_DATA_DIRECTORY p_data_directory_reloc, 
    PVOID old_module, 
    PVOID new_module) 
{
    if (new_module == NULL ||
        entry_address == NULL ||
        p_data_directory_reloc == NULL ||
        (p_data_directory_reloc != NULL && p_data_directory_reloc->Size == 0)) {
        return -1;
    }
    DWORD relocate_rva = p_data_directory_reloc->VirtualAddress;
    PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((PBYTE)new_module + relocate_rva);
    while (p_relocate->SizeOfBlock != 0 && p_relocate->VirtualAddress != 0) {
        for (ULONG i = 0; i < p_relocate->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION); i = i + sizeof(WORD)) {
            WORD TypeOffset = *((PWORD)((PBYTE)p_relocate + sizeof(IMAGE_BASE_RELOCATION) + i));
            WORD _offset = WORD(WORD(TypeOffset << 4) >> 4);
            WORD _type = TypeOffset >> 12;
            if (0 != TypeOffset && IMAGE_REL_BASED_ABSOLUTE != _type) {
                DWORD relocate_item_rva = p_relocate->VirtualAddress + _offset;
                PVOID pTargetAddress = (PBYTE)new_module + relocate_item_rva;
                *(PDWORD)pTargetAddress = *(PDWORD)pTargetAddress - (DWORD)old_module + entry_address;
            }
        }
        p_relocate = (PIMAGE_BASE_RELOCATION)((BYTE*)p_relocate + p_relocate->SizeOfBlock);
    }
    return 0;
}

void 
CInlineHookCheck::init_white_addr_list(
    PVOID new_module, 
    DWORD size_of_image,
    MODULEENTRY32 module32_info)
{
    if (new_module == NULL) {
        return;
    }
    // init white addr list
    white_addr_list.clear();
    // kernel32.dll 's SetUnhandledExceptionFilter function header machine code is modified by the system
    if (!_wcsicmp(module32_info.szModule, L"kernel32.dll")) {
        HMODULE kernel_module = LoadLibrary(module32_info.szExePath);
        if (kernel_module) {
            WHITE_ADDRESS white_address_info = { 0 };
            white_address_info.address = (ULONG_PTR)((PBYTE)GetProcAddress(kernel_module, "SetUnhandledExceptionFilter") -
                (DWORD)kernel_module + (DWORD)new_module);
            white_address_info.size = 5;
            white_addr_list.insert(white_addr_list.begin(), white_address_info);
        }
    }
    // init user define white addr
    for (std::list<WHITE_MARK>::iterator it = white_mark_list.begin(); it != white_mark_list.end(); it++) {
        WHITE_MARK white_mark = *it;
        if (!_wcsicmp(white_mark.module_name.c_str(), module32_info.szExePath)) {
            ULONG_PTR white_addr = ScanMarkCode(
                GetCurrentProcess(),
                white_mark.mark_string.c_str(),
                (ULONG_PTR)new_module, size_of_image, white_mark.offset);
            if (0 != white_addr) {
                WHITE_ADDRESS white_address_info = { 0 };
                white_address_info.address = white_addr;
                white_address_info.size = white_mark.size;
                white_addr_list.insert(white_addr_list.begin(), white_address_info);
            }
        }

    }
}

bool 
CInlineHookCheck::delete_inline_hook(
    HANDLE hProcess,
    PVOID old_module, 
    PVOID file_text_section,
    DWORD size)
{
    bool ret = 0;
    if (old_module == NULL ||
        file_text_section == NULL) {
        return ret;
    }

    bool is_delete = true;
    // pause all thread
    HANDLE snapHandele = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (INVALID_HANDLE_VALUE != snapHandele) {
        THREADENTRY32 entry = { 0 };
        entry.dwSize = sizeof(entry);
        BOOL bRet = Thread32First(snapHandele, &entry);
        while (bRet) {
            if (entry.th32OwnerProcessID == target_pid) {
                HANDLE current_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, entry.th32ThreadID);
                if (current_thread != NULL) {
                    if (-1 == SuspendThread(current_thread)) {
                        is_delete = false;
                    }
                    CloseHandle(current_thread);
                }
            }
            bRet = Thread32Next(snapHandele, &entry);
        }
        CloseHandle(snapHandele);
    }

    // restore opcode
    if (true == is_delete) {
        DWORD old_protect = 0;
        if (VirtualProtectEx(hProcess, old_module, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
            SIZE_T retSize = 0;
            ret = WriteProcessMemory(hProcess, old_module, file_text_section, size, &retSize);
            VirtualProtectEx(hProcess, old_module, size, old_protect, &old_protect);
        }
    }

    // resume all thread
    snapHandele = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (INVALID_HANDLE_VALUE != snapHandele) {
        THREADENTRY32 entry = { 0 };
        entry.dwSize = sizeof(entry);
        BOOL bRet = Thread32First(snapHandele, &entry);
        while (bRet) {
            if (entry.th32OwnerProcessID == target_pid) {
                HANDLE current_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, entry.th32ThreadID);
                if (current_thread != NULL) {
                    ResumeThread(current_thread);
                    CloseHandle(current_thread);
                }
            }
            bRet = Thread32Next(snapHandele, &entry);
        }
        CloseHandle(snapHandele);
    }
    return ret;
}

std::wstring
CInlineHookCheck::parse_opcode(
    void* base, 
    unsigned char* address, 
    size_t size, 
    size_t* parsed_size, 
    uint64_t* module_offset)
{
    if (base == NULL ||
        address == NULL ||
        parsed_size == NULL ||
        module_offset == NULL) {
        return L"";
    }
    csh handle;
    cs_insn* insn;
    size_t insn_count;
    uint64_t address_offset = 0;
    if (CS_ERR_OK == cs_open(CS_ARCH_X86, CS_MODE_32, &handle)){
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        insn_count = cs_disasm(handle, address, size, (uint64_t)base, 0, &insn);
        if (insn_count > 0) {
            //printf("0x%" PRIx64 ":\t%s\t\t%s",insn->address, insn->mnemonic, insn->op_str);
            // jmp address
            if (cs_insn_group(handle, insn, X86_GRP_JUMP)) {
                cs_x86* x86 = &(insn->detail->x86);
                size_t op_count = cs_op_count(handle, insn, X86_OP_IMM);
                if (op_count == 1) {
                    int op_index = cs_op_index(handle, insn, X86_OP_IMM, 1);
                    address_offset = x86->operands[op_index].imm;
                    *parsed_size = insn->size;
                }
            }
            // call address
            else if (cs_insn_group(handle, insn, X86_GRP_CALL)) {
                cs_x86* x86 = &(insn->detail->x86);
                size_t op_count = cs_op_count(handle, insn, X86_OP_IMM);
                if (op_count == 1) {
                    int op_index = cs_op_index(handle, insn, X86_OP_IMM, 1);
                    address_offset = x86->operands[op_index].imm;
                    *parsed_size = insn->size;
                }
            }
            // push address, ret
            else if (insn[0].id == X86_INS_PUSH) {
                if (insn_count >= 2 &&
                    insn[1].id == X86_INS_RET) {
                    cs_x86* x86 = &(insn->detail->x86);
                    size_t op_count = cs_op_count(handle, insn, X86_OP_IMM);
                    if (op_count == 1) {
                        int op_index = cs_op_index(handle, insn, X86_OP_IMM, 1);
                        address_offset = x86->operands[op_index].imm;
                        *parsed_size = insn[0].size + insn[1].size;
                    }
                }
            }
            // mov eax(reg), address
            else if (insn[0].id == X86_INS_MOV) {
                cs_x86* x86 = &(insn->detail->x86);
                size_t op_count = cs_op_count(handle, insn, X86_OP_IMM);
                if (op_count == 1) {
                    int op_index = cs_op_index(handle, insn, X86_OP_IMM, 1);
                    address_offset = x86->operands[op_index].imm;
                    *parsed_size = insn->size;
                }
            }
            cs_free(insn, insn_count);
        }
        cs_close(&handle);
    }
    
    std::wstring module_name = L"";
    if (address_offset) {
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
        if (hModuleSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(hModuleSnap, &me32)) {
                do {
                    if (address_offset >= (uint64_t)me32.modBaseAddr &&
                        address_offset <= (uint64_t)me32.modBaseAddr + me32.modBaseSize) {
                        module_name.append(me32.szModule);
                        *module_offset = address_offset - (uint64_t)me32.modBaseAddr;
                    }
                } while (Module32Next(hModuleSnap, &me32));
            }
            CloseHandle(hModuleSnap);
        }
    }
    return module_name;
}


// ret 0: not check inline hook
// ret -1: delete inline hook is error
// ret -2: delete inline hook is success
int 
CInlineHookCheck::cmp_text_segment(
    HANDLE hProcess, 
    PVOID old_module, 
    PVOID new_module, 
    PVOID file_buffer, 
    std::list<WHITE_ADDRESS>& white_addr_list)
{
    if (NULL == hProcess ||
        NULL == old_module ||
        NULL == new_module ||
        NULL == file_buffer) {
        return 0;
    }

    PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)new_module;
    PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
    PIMAGE_OPTIONAL_HEADER32 p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
    PIMAGE_SECTION_HEADER p_section_start = (PIMAGE_SECTION_HEADER)((PBYTE)p_optional_header + p_file_header->SizeOfOptionalHeader);
    // get ".text" section index
    int text_index = -1;
    for (int i = 0; i < p_file_header->NumberOfSections; i++) {
        if (!strncmp((const char*)p_section_start->Name, ".text", strlen(".text"))) {
            text_index = i;
            break;
        }
        p_section_start++;
    }
    if (text_index == -1) {
        return 0;
    }
    PIMAGE_SECTION_HEADER p_new_module_text_section = p_section_start + text_index;
    PVOID p_new_module_text = (PVOID)((PBYTE)new_module + p_new_module_text_section->VirtualAddress);
    p_dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
    p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
    PIMAGE_SECTION_HEADER p_file_text_section = (PIMAGE_SECTION_HEADER)((PBYTE)p_optional_header + p_file_header->SizeOfOptionalHeader) + text_index;
    PVOID p_file_text = (PVOID)((PBYTE)file_buffer + rva_to_va(new_module, p_file_text_section->VirtualAddress));
    
    bool is_white_addr;
    bool is_delete_inline = false;
    for (ULONG i = 0; i < p_new_module_text_section->SizeOfRawData; i++) {
        if (*((BYTE*)p_new_module_text + i) != *((BYTE*)p_file_text + i)) {
            // filter white addr list
            is_white_addr = false;
            std::list<WHITE_ADDRESS>::iterator it;
            for (it = white_addr_list.begin(); it != white_addr_list.end(); it++) {
                if ((ULONG_PTR)((PBYTE)p_new_module_text + i) >= (*it).address &&
                    (ULONG_PTR)((PBYTE)p_new_module_text + i - (*it).size) <= (*it).address) {
                    i = i + (*it).size - 1;
                    is_white_addr = true;
 
                    break;
                }
            }
            
            if (!is_white_addr) {
                // parse opcode
                is_delete_inline = true;
                void* opcode_base = (PBYTE)old_module + p_new_module_text_section->VirtualAddress + i;
                size_t parsed_size = 0;
                uint64_t module_offset = 0;
                std::wstring module_name;
                module_name = parse_opcode(opcode_base, (PBYTE)p_new_module_text + i, p_new_module_text_section->SizeOfRawData - i, &parsed_size, &module_offset);
                if (module_name.length()) {
                    i = i + parsed_size - 1;
                    printf("\n    0x%p: goto %ls->0x%x\n", opcode_base, module_name.c_str(), (unsigned int)module_offset);
                }
            }
        }
    }
    // delete inline hook
    if (is_delete_inline) {
        PVOID p_old_module_text = (PVOID)((PBYTE)old_module + p_new_module_text_section->VirtualAddress);
        if (!delete_inline_hook(hProcess, p_old_module_text, p_file_text, p_new_module_text_section->SizeOfRawData)) {
            return -2;
        }
        return -1;
    }
    return 0;
}

void CInlineHookCheck::start_hook_check()
{
    int ret = 0;
    if (FALSE == set_debug_privilege()) {
        return;
    }
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        target_pid);
    if (NULL == hProcess) {
        ExitThread(0);
        return;
    }

    // enum module list
    bool isPass = false;
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
    if (hModuleSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hModuleSnap, &me32)) {
            do {
                // filter check list
                isPass = true;
                std::list<std::wstring>::iterator it;
                for (it = inline_check_list.begin(); it != inline_check_list.end(); it++) {
                    std::wstring white_file_path = *it;
                    if (!_wcsicmp(me32.szExePath, white_file_path.c_str())) {
                        isPass = false;
                        break;
                    }
                }
                if (true == isPass &&
                    false == is_check_all_module) {
                    continue;
                }
                // do check
                PVOID new_module = NULL;
                HMODULE old_module = (HMODULE)me32.modBaseAddr;
                PVOID file_buffer = NULL;
                size_t file_size = 0;
                file_buffer = ReadFileToMemoryW(me32.szExePath, &file_size);
                if (file_buffer == NULL) {
                    continue;
                }
                PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)file_buffer;
                PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
                PIMAGE_OPTIONAL_HEADER32 p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
                PIMAGE_DATA_DIRECTORY p_data_directory = (PIMAGE_DATA_DIRECTORY)p_optional_header->DataDirectory;
                PIMAGE_DATA_DIRECTORY p_data_directory_import = &p_data_directory[1];
                PIMAGE_DATA_DIRECTORY p_data_directory_reloc = &p_data_directory[5];
                DWORD size_of_image = p_optional_header->SizeOfImage;
                // filter 32 bit module
                if (p_file_header->Machine == IMAGE_FILE_MACHINE_I386) {

                    new_module = copy_module(hProcess, file_buffer, file_size, old_module, size_of_image);
                    if (new_module != NULL) {
                        // init white addr list
                        init_white_addr_list(new_module, size_of_image, me32);
                        // .text to reloc
                        do_reloc_table(p_optional_header->ImageBase, p_data_directory_reloc, old_module, new_module, file_buffer);
                        // strip function forward
                        strip_function_forward(file_buffer, new_module);
                        // windows 7's import table to reloc
                        if (!is_window10()) {
                            // import table to reloc
                            do_reloc_import_table(hProcess, p_optional_header->ImageBase, p_data_directory_import, old_module, new_module, file_buffer);
                        }
                        // check text segment
                        int ret = cmp_text_segment(hProcess, old_module, new_module, file_buffer, white_addr_list);
                        if (0 == ret) {
                            printf("[+] %ls : not find inline hook\n", me32.szModule);
                        }
                        else if (-1 == ret) {
                            printf("[-] %ls : delete inline hook is success\n", me32.szModule);
                        }
                        else {
                            printf("[-] %ls : delete inline hook is error\n", me32.szModule);
                        }
                        free(new_module);
                    }
                }
                free(file_buffer);
            } while (Module32Next(hModuleSnap, &me32));
        }
        CloseHandle(hModuleSnap);
    }
    CloseHandle(hProcess);
}

CInlineHookCheck::CInlineHookCheck(
    unsigned int pid, 
    std::list<std::wstring> check_list, 
    std::list<IHcheck::WHITE_MARK> white_addr_mark_list,
    bool is_all)
{
    //Wow64DisableWow64FsRedirection(&FsRedirection_old_value);
    is_check_all_module = is_all;
    target_pid = pid;
    inline_check_list = check_list;
    white_mark_list = white_addr_mark_list;
    //start inline hook check
    start_hook_check();
}

CInlineHookCheck::~CInlineHookCheck() 
{
    //Wow64RevertWow64FsRedirection(FsRedirection_old_value);
}