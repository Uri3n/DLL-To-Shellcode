#pragma once
#include <Windows.h>

struct PE_INFO {

	byte*                    pmapped              = nullptr;
	size_t                   img_size             = 0;

	PIMAGE_NT_HEADERS        pnt_hdrs             = nullptr;
	PIMAGE_SECTION_HEADER    psec_hdrs            = nullptr;

	PIMAGE_DATA_DIRECTORY    pimport_directory    = nullptr;
	PIMAGE_DATA_DIRECTORY    preloc_directory     = nullptr;
	PIMAGE_DATA_DIRECTORY    pTLS_directory       = nullptr;
	PIMAGE_DATA_DIRECTORY    pexception_directory = nullptr;
	PIMAGE_DATA_DIRECTORY    pexport_directory    = nullptr;

	bool                     init_complete        = false;
};

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
