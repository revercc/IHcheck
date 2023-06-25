#include "inline_hook_check.h"
#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>
#include <tlhelp32.h>
using namespace IHcheck;

unsigned int CInlineHookCheck::timer_id = 0;
unsigned int CInlineHookCheck::target_pid = 0;
std::list<std::wstring> CInlineHookCheck::inline_check_list;
std::list<IHcheck::WHITE_MARK> CInlineHookCheck::white_mark_list;
PVOID ReadFileToMemoryW(const wchar_t* file_path)
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

PVOID ReadFileToMemory(const char* file_path)
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

//�ַ���ת16����
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

ULONG_PTR ScanMarkCode(HANDLE hProcess, const char* strMarkCode, ULONG_PTR pStartAddr, size_t nScanSize, int nOffset, int nCount = 1)
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

PVOID CInlineHookCheck::CopyTargetModule(HANDLE hProcess, HMODULE old_module, DWORD size_of_image) {
    void* module_image = (UCHAR*)malloc(size_of_image);
    if (NULL != module_image) {
        memset(module_image, 0, size_of_image);
        if (!ReadProcessMemory(hProcess, old_module, module_image, size_of_image, NULL)) {
            free(module_image);
            module_image = NULL;
        }
    }
    return module_image;
}

int CInlineHookCheck::AddReloc(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module, PVOID file_buffer) {
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
        for (ULONG i = 0; i < p_relocate->SizeOfBlock - 8; i = i + 2) {
            if (0 != *((WORD*)((BYTE*)p_relocate + 8 + i))) {
                DWORD relocate_item_rva = *(DWORD*)p_relocate + WORD(WORD((*((WORD*)((BYTE*)p_relocate + 8 + i))) << 4) >> 4);
                DWORD relocate_item_va = rva_to_va(new_module, relocate_item_rva);
                PVOID pTargetAddress = (PBYTE)file_buffer + relocate_item_va;
                // �ض�λ
                *(DWORD*)pTargetAddress = *(DWORD*)pTargetAddress - entry_address + (DWORD)old_module;
            }
        }
        p_relocate = (PIMAGE_BASE_RELOCATION)((BYTE*)p_relocate + p_relocate->SizeOfBlock);
    }
    return 0;
}

int CInlineHookCheck::StripReloc(DWORD entry_address, PIMAGE_DATA_DIRECTORY p_data_directory_reloc, PVOID old_module, PVOID new_module) {
    if (new_module == NULL ||
        entry_address == NULL ||
        p_data_directory_reloc == NULL ||
        (p_data_directory_reloc != NULL && p_data_directory_reloc->Size == 0)) {
        return -1;
    }
    DWORD relocate_rva = p_data_directory_reloc->VirtualAddress;
    PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((PBYTE)new_module + relocate_rva);
    while (p_relocate->SizeOfBlock != 0 && p_relocate->VirtualAddress != 0) {
        for (ULONG i = 0; i < p_relocate->SizeOfBlock - 8; i = i + 2) {
            if (0 != *((WORD*)((BYTE*)p_relocate + 8 + i))) {
                PVOID pTargetAddress = (PBYTE)new_module + *(DWORD*)p_relocate + WORD(WORD((*((WORD*)((BYTE*)p_relocate + 8 + i))) << 4) >> 4);
                // ȥ���ض�λ
                *(DWORD*)pTargetAddress = *(DWORD*)pTargetAddress - (DWORD)old_module + entry_address;
            }
        }
        p_relocate = (PIMAGE_BASE_RELOCATION)((BYTE*)p_relocate + p_relocate->SizeOfBlock);
    }
    return 0;
}

bool CInlineHookCheck::DeleteInlineHook(HANDLE hProcess, PVOID old_module, PVOID file_text_section, DWORD size)
{
    bool ret = 0;
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

// ret -1: not check inline hook
// ret -2: delete inline hook is error
// ret  0: delete inline hook is success
int CInlineHookCheck::CmpTextSegment(HANDLE hProcess, PVOID old_module, PVOID new_module, PVOID file_buffer, std::list<ULONG_PTR>& white_addr_list) {
    if (NULL == hProcess ||
        NULL == old_module ||
        NULL == new_module ||
        NULL == file_buffer) {
        return -1;
    }

    PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)new_module;
    PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
    PIMAGE_OPTIONAL_HEADER32 p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
    PIMAGE_SECTION_HEADER p_section_start = (PIMAGE_SECTION_HEADER)((PBYTE)p_optional_header + p_file_header->SizeOfOptionalHeader);
    // get ".text" section index
    int text_index = -1;
    for (int i = 0; i < p_file_header->NumberOfSections; i++) {
        if (!strcmp((const char*)p_section_start->Name, ".text")) {
            text_index = i;
            break;
        }
        p_section_start++;
    }
    if (text_index == -1) {
        return -1;
    }
    PIMAGE_SECTION_HEADER p_new_module_text_section = p_section_start + text_index;
    PVOID p_new_module_text = (PVOID)((PBYTE)new_module + p_new_module_text_section->VirtualAddress);
    //DWORD p_current_entry_offset = (p_optional_header->AddressOfEntryPoint - p_new_module_text_section->VirtualAddress);
    p_dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
    p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
    PIMAGE_SECTION_HEADER p_file_text_section = (PIMAGE_SECTION_HEADER)((PBYTE)p_optional_header + p_file_header->SizeOfOptionalHeader) + text_index;
    PVOID p_file_text = (PVOID)((PBYTE)file_buffer + rva_to_va(new_module, p_file_text_section->VirtualAddress));
    
    // The starting position of the text segment of win7 part of the system library contains the import table,
    // which requires special processing
    /*
    for (ULONG i = p_current_entry_offset; i < p_new_module_text_section->SizeOfRawData; i++) {
        if (*((BYTE*)p_new_module_text + i) != *((BYTE*)p_file_text + i)) {
            printf("offset is %x\n", i);
            return -1;
        }
    }
    */
    // filter white addr list
    int ret = -1;
    for (ULONG i = 0; i < p_new_module_text_section->SizeOfRawData; i++) {
        if (*((BYTE*)p_new_module_text + i) != *((BYTE*)p_file_text + i)) {
            ret = 0;
            std::list<ULONG_PTR>::iterator it;
            for (it = white_addr_list.begin(); it != white_addr_list.end(); it++) {
                if ((ULONG_PTR)((PBYTE)p_new_module_text + i) >= *it &&
                    (ULONG_PTR)((PBYTE)p_new_module_text + i - 4) <= *it) {
                    ret = -1;
                    break;
                }
            }
            if (-1 == ret) {
                continue;
            }
        }
    }

    // delete inline hook
    if (0 == ret) {
        PVOID p_old_module_text = (PVOID)((PBYTE)old_module + p_new_module_text_section->VirtualAddress);
        if (!DeleteInlineHook(hProcess, p_old_module_text, p_file_text, p_new_module_text_section->SizeOfRawData)) {
            ret = -2;
        }
    }
    return ret;
}
void __stdcall CInlineHookCheck::timer_call_back(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
    int ret = 0;
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        target_pid);
    if (NULL == hProcess)
        return;

    // enum module list
    bool isPass = FALSE;
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
    if (hModuleSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(hModuleSnap, &me32)) {
            CloseHandle(hModuleSnap);
            return;
        }

        do {
            // filter check list
            isPass = TRUE;
            std::list<std::wstring>::iterator it;
            for (it = inline_check_list.begin(); it != inline_check_list.end(); it++) {
                std::wstring white_file_path = *it;
                if (!_wcsicmp(me32.szExePath, white_file_path.c_str())) {
                    isPass = FALSE;
                    break;
                }
            }
            if (TRUE == isPass) {
                continue;
            }

            // do check
            PVOID new_module = NULL;
            HMODULE old_module = (HMODULE)me32.modBaseAddr;
            PVOID file_buffer = NULL;
            file_buffer = ReadFileToMemoryW(me32.szExePath);
            if (file_buffer == NULL) {
                continue;
            }
            PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)file_buffer;
            PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)((PBYTE)p_dos_header + p_dos_header->e_lfanew + 0x4);
            PIMAGE_OPTIONAL_HEADER32 p_optional_header = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)p_file_header + 0x14);
            PIMAGE_DATA_DIRECTORY p_data_directory = (PIMAGE_DATA_DIRECTORY)p_optional_header->DataDirectory;
            PIMAGE_DATA_DIRECTORY p_data_directory_reloc = &p_data_directory[5];
            DWORD size_of_image = p_optional_header->SizeOfImage;
            if (p_file_header->Machine == IMAGE_FILE_MACHINE_I386) {
                new_module = CopyTargetModule(hProcess, old_module, size_of_image);
                if (new_module != NULL) {
                    // init white addr list
                    std::list<ULONG_PTR> white_addr_list = { 0 };
                    for (std::list<WHITE_MARK>::iterator it = white_mark_list.begin(); it != white_mark_list.end(); it++) {
                        WHITE_MARK white_mark = *it;
                        if (!_wcsicmp(white_mark.module_name.c_str(), me32.szExePath)) {
                            ULONG_PTR white_addr = ScanMarkCode(
                                GetCurrentProcess(), 
                                white_mark.mark_string.c_str(), 
                                (ULONG_PTR)new_module, size_of_image, white_mark.offset);
                            if (0 != white_addr) {
                                white_addr_list.insert(white_addr_list.begin(), white_addr);
                            }
                        }

                    }

                    // do reloc
                    AddReloc(p_optional_header->ImageBase, p_data_directory_reloc, old_module, new_module, file_buffer);
                    // check text segment
                    int ret = CmpTextSegment(hProcess, old_module, new_module, file_buffer, white_addr_list);
                    printf("\n%ls :", me32.szModule);
                    if (0 == ret) {
                        //KillTimer(NULL, timer_id);
                        printf("delete inline hook is success\n");
                    }
                    else if (-2 == ret) {
                        printf("delete inline hook is error\n");
                    }
                    else {
                        printf("not find inline hook\n");
                    }
                    free(new_module);
                }
            }
            free(file_buffer);
        } while (Module32Next(hModuleSnap, &me32));
        CloseHandle(hModuleSnap);
    }
    CloseHandle(hProcess);
}

unsigned int __stdcall CInlineHookCheck::check_thread(void* lpThreadParameter) {
    MSG msg;
    timer_id = SetTimer(NULL, 0, 3000, (TIMERPROC)timer_call_back);
    if (NULL != timer_id) {
        while (GetMessage(&msg, NULL, NULL, NULL)) {
            if (msg.message == WM_TIMER) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }
    return 0;
}

void CInlineHookCheck::inline_hook_check()
{
    HANDLE hThread = CreateThread(
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE)check_thread,
        NULL,
        NULL,
        NULL);
    if (NULL != hThread) {
        CloseHandle(hThread);
    }
}

CInlineHookCheck::CInlineHookCheck(unsigned int pid, std::list<std::wstring> check_list, std::list<IHcheck::WHITE_MARK> white_addr_mark_list)
{
    target_pid = pid;
    inline_check_list = check_list;
    white_mark_list = white_addr_mark_list;
    //start inline hook check
    inline_hook_check();
}

CInlineHookCheck::~CInlineHookCheck() 
{
}
