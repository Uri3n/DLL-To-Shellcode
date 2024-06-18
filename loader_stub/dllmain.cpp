#include "dllmain.hpp"

#define STATIC_SEED (unsigned long)24785


//////////////////////////////////////////////////////////////////////////////////
//
// Position independant code that loads a DLL given it's base address in memory.
// Relevant compiler flags:
// - optimization: disabled
// - whole program optimization: disabled
// - SDL checks: off
// - security check (/GS): off
//
// The code for this loader is intentionally kept inside of a single function
// in order to guarantee it's position independent nature.
//
// You can extract the bytes from this function using a tool such as Ghidra or IDA (any disassembler really).
//

extern __declspec(dllexport) bool reflective_stub(byte* module_base) {

    PE_INFO                   image_info           = { 0 };

    unsigned long             hash_kernel32        = 1120224149UL;
    unsigned long             hash_ntdll           = 2298634647UL;
    unsigned long             hash_getprocaddress  = 3539982071UL;

    HMODULE                   hkernel32            = nullptr;
    HMODULE                   hntdll               = nullptr;

    fnVirtualProtect          pvirtual_protect     = nullptr;
    fnVirtualAlloc            pvirtual_alloc       = nullptr;
    fnNtFlushInstructionCache pflush_instruction_cache = nullptr;
    fnLoadLibraryA            ploadlibrarya        = nullptr;
    fnGetProcAddress          pgetprocaddress      = nullptr;



    // GetModuleHandleH() 
    //-----------------------------------------------------------------------------------------------------------------------------//

    for (size_t i = 0; i < 2; i++) {

        HMODULE* current_hmod = nullptr;
        unsigned long current_hash = 0;

        if (i == 0) {
            current_hmod = &hntdll;
            current_hash = hash_ntdll;
        }

        else if (i == 1) {
            current_hmod = &hkernel32;
            current_hash = hash_kernel32;
        }


        PPEB pPeb = (PPEB)__readgsqword(0x60);

        PLDR_DATA_TABLE_ENTRY pdata_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pPeb->Ldr->InMemoryOrderModuleList.Flink);
        PLIST_ENTRY plist_head = reinterpret_cast<PLIST_ENTRY>(&(pPeb->Ldr->InMemoryOrderModuleList));
        PLIST_ENTRY p_itr = reinterpret_cast<PLIST_ENTRY>(plist_head->Flink);


        do {

            if (pdata_entry->FullDllName.Length) {

                // JenkinsHash()
                //-----------------------------------------------------------------------------------------------------------------------------//

                unsigned long HASH = STATIC_SEED;

                char* ascii_string = nullptr;
                wchar_t* wide_string = pdata_entry->FullDllName.Buffer;


                //str_len()
                //---------------------------------------------------------------------------------------------------------------------//

                wchar_t* string = wide_string;

                size_t str_len = 0;
                while (*string != (wchar_t)0) {

                    ++str_len;
                    ++string;
                }

                //---------------------------------------------------------------------------------------------------------------------//


                for (size_t qq = 0; qq < str_len; qq++) {

                    if (ascii_string) {
                        if (ascii_string[qq] == '.') {
                            break;
                        }
                    }

                    else {
                        if (wide_string[qq] == L'.') {
                            break;
                        }
                    }


                    ascii_string ? HASH += ascii_string[qq] : HASH += wide_string[qq];
                    HASH += (HASH << 10);
                    HASH ^= (HASH >> 6);
                }


                HASH += (HASH << 3);
                HASH ^= (HASH >> 11);
                HASH += (HASH << 15);


                //---------------------------------------------------------------------------------------------------------------------//

                if (HASH == current_hash) {
                    *current_hmod = static_cast<HMODULE>(pdata_entry->Reserved2[0]);
                    break;
                }

                //-----------------------------------------------------------------------------------------------------------------------------//

            }

            pdata_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(p_itr->Flink);
            p_itr = (PLIST_ENTRY)(p_itr->Flink);


        } while (p_itr != plist_head);

    }


    if (hkernel32 == nullptr || hntdll == nullptr) {
        return false;
    }




    // GetProcAddressH()
    //-----------------------------------------------------------------------------------------------------------------------------//

    byte* base = reinterpret_cast<byte*>(hkernel32);

    PIMAGE_NT_HEADERS pnt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    if (pnt_hdrs->Signature != IMAGE_NT_SIGNATURE)
        return false;


    PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY> \
        (base + pnt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    uint32_t* names     = reinterpret_cast<uint32_t*>(base + pImgExportDirectory->AddressOfNames);
    uint32_t* addresses = reinterpret_cast<uint32_t*>(base + pImgExportDirectory->AddressOfFunctions);
    uint16_t* ordinals  = reinterpret_cast<uint16_t*>(base + pImgExportDirectory->AddressOfNameOrdinals);

        
    for (size_t i = 0; i < pImgExportDirectory->NumberOfFunctions; i++) {

        char* name    = (char*)(base + names[i]);
        void* address = (void*)(base + addresses[ordinals[i]]);


        // JenkinsHash()
        //-----------------------------------------------------------------------------------------------------------------------------//

        unsigned long HASH = STATIC_SEED;

        char* ascii_string = name;
        wchar_t* wide_string = nullptr;


        //str_len()
        //---------------------------------------------------------------------------------------------------------------------//

        char* string = ascii_string;

        size_t str_len = 0;
        while (*string != (char)0) {

            ++str_len;
            ++string;
        }

        //---------------------------------------------------------------------------------------------------------------------//


        for (size_t qq = 0; qq < str_len; qq++) {

            if (ascii_string) {
                if (ascii_string[qq] == '.') {
                    break;
                }
            }

            else {
                if (wide_string[qq] == L'.') {
                    break;
                }
            }


            ascii_string ? HASH += ascii_string[qq] : HASH += wide_string[qq];
            HASH += (HASH << 10);
            HASH ^= (HASH >> 6);
        }


        HASH += (HASH << 3);
        HASH ^= (HASH >> 11);
        HASH += (HASH << 15);


        //---------------------------------------------------------------------------------------------------------------------//

        if (HASH == hash_getprocaddress) {
            pgetprocaddress = (fnGetProcAddress)address;
            break;
        }
    }

    //-----------------------------------------------------------------------------------------------------------------------------//

    if (pgetprocaddress == nullptr) {
        return false;
    }




    // Initializeimage_information()
    //-----------------------------------------------------------------------------------------------------------------------------//

    if (((PIMAGE_DOS_HEADER)module_base)->e_magic != IMAGE_DOS_SIGNATURE)
        return false;


    image_info.pnt_hdrs = (PIMAGE_NT_HEADERS)(module_base + (((PIMAGE_DOS_HEADER)module_base)->e_lfanew));
    if (image_info.pnt_hdrs->Signature != IMAGE_NT_SIGNATURE)
        return false;


    image_info.img_size             = image_info.pnt_hdrs->OptionalHeader.SizeOfImage;
    image_info.psec_hdrs            = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(image_info.pnt_hdrs));

    image_info.preloc_directory     = (PIMAGE_DATA_DIRECTORY)(&(image_info.pnt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]));
    image_info.pexception_directory = (PIMAGE_DATA_DIRECTORY)(&(image_info.pnt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]));
    image_info.pexport_directory    = (PIMAGE_DATA_DIRECTORY)(&(image_info.pnt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
    image_info.pimport_directory    = (PIMAGE_DATA_DIRECTORY)(&(image_info.pnt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
    image_info.pTLS_directory       = (PIMAGE_DATA_DIRECTORY)(&(image_info.pnt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]));

    image_info.init_complete = true;


    if (!image_info.img_size || !image_info.psec_hdrs || !image_info.preloc_directory || !image_info.pexception_directory ||
        !image_info.pexport_directory || !image_info.pimport_directory || !image_info.pTLS_directory || !image_info.pnt_hdrs) {

        return false;
    }

    //-----------------------------------------------------------------------------------------------------------------------------//



    // RelocateSections()
    //-----------------------------------------------------------------------------------------------------------------------------// 

    if (pgetprocaddress == nullptr) {
        return false;
    }

    char virtual_alloc_str[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
    pvirtual_alloc = (fnVirtualAlloc)pgetprocaddress(hkernel32, virtual_alloc_str);

    if (pvirtual_alloc == nullptr) {
        return false;
    }


    image_info.pmapped = static_cast<byte*>(pvirtual_alloc(
        nullptr,
        image_info.img_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ));

    if (image_info.pmapped == nullptr)
        return false;



    //
    // Iterate through each image section and copy it to its virtual address.
    //

    for (size_t i = 0; i < image_info.pnt_hdrs->FileHeader.NumberOfSections; i++) {

        unsigned char* destination  = (unsigned char*)(image_info.pmapped + image_info.psec_hdrs[i].VirtualAddress);
        unsigned char* source       = (unsigned char*)(module_base + image_info.psec_hdrs[i].PointerToRawData);

        for (volatile DWORD j = 0; j < image_info.psec_hdrs[i].SizeOfRawData; j++) {
            destination[j] = source[j];
        }
    }

    //-----------------------------------------------------------------------------------------------------------------------------//



    // ResolveImports()
    //-----------------------------------------------------------------------------------------------------------------------------//

    char loadlib_str[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
    ploadlibrarya = (fnLoadLibraryA)pgetprocaddress(hkernel32, loadlib_str);

    if (ploadlibrarya == nullptr) {
        return false;
    }


    PIMAGE_IMPORT_DESCRIPTOR pimport_descriptor = nullptr;

    //
    // Iterate Through Each Import Descriptor. Each one
    // Corresponds to a DLL.
    //

    for (size_t i = 0; i < image_info.pimport_directory->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

        pimport_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>\
            (image_info.pmapped + (image_info.pimport_directory->VirtualAddress + i));


        //
        // NULL thunks indicate the end of the import descriptors
        //

        if (pimport_descriptor->FirstThunk == NULL &&
            pimport_descriptor->OriginalFirstThunk == NULL) {

            break;
        }


        //
        // Resolve all imports from the DLL
        //

        char*    module_name              = reinterpret_cast<char*>(image_info.pmapped + (pimport_descriptor->Name));
        uint64_t name_table_offset        = static_cast<uint64_t>(pimport_descriptor->OriginalFirstThunk);
        uint64_t address_table_offset     = static_cast<uint64_t>(pimport_descriptor->FirstThunk);
        size_t   thunk_array_index_offset = 0; 

        HMODULE hmod = ploadlibrarya(module_name);
        if (hmod == nullptr)
            return false;



        while (true) {


            PIMAGE_THUNK_DATA poriginal_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>\
                (image_info.pmapped + (name_table_offset + thunk_array_index_offset));

            PIMAGE_THUNK_DATA pfirst_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>\
                (image_info.pmapped + (address_table_offset + thunk_array_index_offset));


            PIMAGE_IMPORT_BY_NAME pimg_import_by_name   = nullptr; //Used when import is not done via Ordinal
            uint64_t              function_address      = 0x00;



            //
            // Null thunks indicate the end of the array.
            //

            if (poriginal_first_thunk->u1.Function == NULL && pfirst_thunk->u1.Function == NULL)
                break;


            if (IMAGE_SNAP_BY_ORDINAL(poriginal_first_thunk->u1.Ordinal)) {


                //
                // If function is imported by ordinal we need to manually determine it ourselves.
                //

                PIMAGE_NT_HEADERS temp_nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>\
                    ((uint64_t)hmod + ((PIMAGE_DOS_HEADER)hmod)->e_lfanew);

                if (temp_nt_hdrs->Signature != IMAGE_NT_SIGNATURE)
                    break;


                PIMAGE_EXPORT_DIRECTORY temp_export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>\
                    (((uint64_t)hmod) + (temp_nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));


                uint32_t* temp_address_array = reinterpret_cast<uint32_t*>\
                    (((uint64_t)hmod) + (temp_export_directory->AddressOfFunctions));

                function_address = (uint64_t)(((uint64_t)hmod) + (temp_address_array[poriginal_first_thunk->u1.Ordinal]));
            }


            else {

                //
                // Function is imported by name.
                //

                pimg_import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>\
                    (image_info.pmapped + (poriginal_first_thunk->u1.AddressOfData));

                function_address = (uint64_t)pgetprocaddress(hmod, pimg_import_by_name->Name);
            }



            //
            // Resolve function address via Import Address Table
            //

            if (!function_address)
                return false;

            pfirst_thunk->u1.Function = (ULONGLONG)function_address;
            thunk_array_index_offset += sizeof(IMAGE_THUNK_DATA);
        }
    }

    //-----------------------------------------------------------------------------------------------------------------------------//





    // HandleRelocations()
    //-----------------------------------------------------------------------------------------------------------------------------//


    //
    // Each Image base relocation struct describes a singular section.
    //

    PIMAGE_BASE_RELOCATION pimg_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>\
        (image_info.pmapped + (image_info.preloc_directory->VirtualAddress));

    uint64_t DeltaOffset = static_cast<uint64_t>\
        (((uint64_t)(image_info.pmapped)) - (image_info.pnt_hdrs->OptionalHeader.ImageBase));


    PBASE_RELOCATION_ENTRY prelocation_entry = nullptr;


    //
    // Iterate through all sections that must be adjusted,
    // as well as each relocation entry within these sections.
    //

    while (pimg_base_relocation->VirtualAddress) {

        prelocation_entry = (PBASE_RELOCATION_ENTRY)(pimg_base_relocation + 1);

        while ((byte*)prelocation_entry != (byte*)pimg_base_relocation + pimg_base_relocation->SizeOfBlock) {


            //
            // Each relocation entry field must be adjusted depending on it's Type member.
            //


            if (prelocation_entry->Type == IMAGE_REL_BASED_DIR64) {
                *((uint64_t*)(image_info.pmapped + (pimg_base_relocation->VirtualAddress + prelocation_entry->Offset))) += DeltaOffset;
            }

            else if (prelocation_entry->Type == IMAGE_REL_BASED_HIGHLOW) {
                *((uint32_t*)(image_info.pmapped + (pimg_base_relocation->VirtualAddress + prelocation_entry->Offset))) += (uint32_t)DeltaOffset;
            }

            else if (prelocation_entry->Type == IMAGE_REL_BASED_HIGH) {
                *((uint16_t*)(image_info.pmapped + (pimg_base_relocation->VirtualAddress + prelocation_entry->Offset))) += HIWORD(DeltaOffset);
            }

            else if (prelocation_entry->Type == IMAGE_REL_BASED_LOW) {
                *((uint16_t*)(image_info.pmapped + (pimg_base_relocation->VirtualAddress + prelocation_entry->Offset))) += LOWORD(DeltaOffset);
            }


            prelocation_entry++;
        }

        pimg_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(prelocation_entry);
    }

    //-----------------------------------------------------------------------------------------------------------------------------//





    // ResolveMemoryProtections()
    //-----------------------------------------------------------------------------------------------------------------------------//

    char vp_str[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };
    pvirtual_protect = (fnVirtualProtect)pgetprocaddress(hkernel32, vp_str);

    if (pvirtual_protect == nullptr) {
        return false;
    }


    PIMAGE_SECTION_HEADER pimg_section_hdr = image_info.psec_hdrs;


    for (size_t i = 0; i < image_info.pnt_hdrs->FileHeader.NumberOfSections; i++) {

        if (!pimg_section_hdr[i].VirtualAddress || !pimg_section_hdr[i].SizeOfRawData)
            continue;


        uint32_t new_protect = 0;
        uint32_t old_protect = 0;

        //
        // Compare the bitmask in each section header against existing values
        // to determine the correct memory permissions
        //

        if (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            new_protect = PAGE_WRITECOPY;
        }

        if (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_READ) {

            new_protect = PAGE_READONLY;
        }

        if ((pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_READ)) {

            new_protect = PAGE_READWRITE;
        }

        if (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {

            new_protect = PAGE_EXECUTE;
        }

        if ((pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {

            new_protect = PAGE_EXECUTE_WRITECOPY;
        }

        if ((pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_READ)) {

            new_protect = PAGE_EXECUTE_READ;
        }

        if ((pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pimg_section_hdr[i].Characteristics & IMAGE_SCN_MEM_READ)) {

            new_protect = PAGE_EXECUTE_READWRITE;
        }


        //
        // Apply the new memory protection
        //

        if (!pvirtual_protect(
            (LPVOID)(image_info.pmapped + (pimg_section_hdr[i].VirtualAddress)),
            pimg_section_hdr[i].SizeOfRawData,
            new_protect,
            (PDWORD)&old_protect)) {

            return false;
        }
    }

    //-----------------------------------------------------------------------------------------------------------------------------//

    //
    // Flush instruction cache
    //

    char flushcache_str[] = { 'N','t','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e','\0' };
    pflush_instruction_cache = (fnNtFlushInstructionCache)pgetprocaddress(hntdll, flushcache_str);
    if (!pflush_instruction_cache) {
        return false;
    }


    pflush_instruction_cache((HANDLE)-1, nullptr, 0x00);


    //
    // Call DllMain
    //

    fnDllMain pDllMain = (fnDllMain)(image_info.pmapped + (image_info.pnt_hdrs->OptionalHeader.AddressOfEntryPoint));
    pDllMain((HMODULE)(image_info.pmapped), DLL_PROCESS_ATTACH, module_base);
    
    return true;
}




// just keeping this here so the program compiles
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{   

    MessageBoxA(NULL, "poopoo", "caption", MB_OK);
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

