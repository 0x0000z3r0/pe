#include <Windows.h>
#include <Winnt.h>

#include <time.h>
#include <stdio.h>

INT wmain(INT argc, WCHAR *argv[])
{
	if (argc < 2)
	{
		wprintf(L"ERR: specify the executable path\n");
		return 1;
	}

	wprintf(L"INF: opening the '%ls'\n", argv[1]);

	HANDLE hndFile;
	hndFile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hndFile == INVALID_HANDLE_VALUE)
	{
		wprintf(L"ERR: could not open the file\n");
		return 1;
	}

	BOOL status;

	wprintf(L"INF: opened the file, getting the size\n");

	LARGE_INTEGER fileSize;
	status = GetFileSizeEx(hndFile, &fileSize);
	if (!status)
	{
		wprintf(L"ERR: failed to get the file size\n");
		CloseHandle(hndFile);
		return 1;
	}

	wprintf(L"INF: got the file size, creating a file mapping\n");

	HANDLE hndMap;
	hndMap = CreateFileMapping(hndFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hndMap == NULL)
	{
		wprintf(L"ERR: failed to create a file mapping\n");
		CloseHandle(hndFile);
		return 1;
	}

	wprintf(L"INF: created the file mapping, mapping to an address\n");

	PVOID mapAddr;
	mapAddr = MapViewOfFile(hndMap, FILE_MAP_READ, 0, 0, 0);
	if (mapAddr == NULL)
	{
		wprintf(L"ERR: failed to map to an address\n");
		CloseHandle(hndMap);
		CloseHandle(hndFile);
		return 1;
	}

	PIMAGE_DOS_HEADER dosHeader;
	dosHeader = (PIMAGE_DOS_HEADER)mapAddr;
	wprintf(L"\n======= DOS Header [0x%08X] =======\n", (ULONG)((PBYTE)dosHeader - mapAddr));

	wprintf(L"Magic number: 0x%02X%02X, %c%c\n"
		L"Bytes on last page: 0x%04X, %u\n"
		L"Pages in file: %u\n"
		L"Relocations: %u\n"
		L"Size of header in paragraphs: %u\n"
		L"Minimum extra paragpraphs needed: %u\n"
		L"Maximum extra paragpraphs needed: %u\n"
		L"Initial SS value: %u\n"
		L"Initial SP value: %u\n"
		L"Checksum: %u\n"
		L"Initial IP value: %u\n"
		L"Initial CS value: %u\n"
		L"File address of relocation table: 0x%04X, %u\n"
		L"Overlay number: %u\n"
		L"Reserved words: 0x%04X.0x%04X.0x%04X.0x%04X\n"
		L"OEM identidier: %u\n"
		L"OEM information: %u\n"
		L"Reserved words: 0x%04X.0x%04X.0x%04X.0x%04X.0x%04X.0x%04X.0x%04X.0x%04X.0x%04X.0x%04X\n"
		L"File address of new EXE header: 0x%08X\n",
		dosHeader->e_magic & 0xFF, dosHeader->e_magic >> 8,
		dosHeader->e_magic & 0xFF, dosHeader->e_magic >> 8,
		dosHeader->e_cblp, dosHeader->e_cblp,
		dosHeader->e_cp,
		dosHeader->e_crlc,
		dosHeader->e_cparhdr,
		dosHeader->e_minalloc,
		dosHeader->e_maxalloc,
		dosHeader->e_ss,
		dosHeader->e_sp,
		dosHeader->e_csum,
		dosHeader->e_ip,
		dosHeader->e_cs,
		dosHeader->e_lfarlc, dosHeader->e_lfarlc,
		dosHeader->e_ovno,
		dosHeader->e_res[0], dosHeader->e_res[1],
		dosHeader->e_res[2], dosHeader->e_res[3],
		dosHeader->e_oemid,
		dosHeader->e_oeminfo,
		dosHeader->e_res2[0], dosHeader->e_res2[1],
		dosHeader->e_res2[2], dosHeader->e_res2[3],
		dosHeader->e_res2[4], dosHeader->e_res2[5],
		dosHeader->e_res2[6], dosHeader->e_res2[7],
		dosHeader->e_res2[8], dosHeader->e_res2[9],
		dosHeader->e_lfanew);

	PDWORD fileSignature;
	fileSignature = (PDWORD)((PBYTE)mapAddr + dosHeader->e_lfanew);

	PWCHAR fileSignatureStr;
	switch (*fileSignature)
	{
	case IMAGE_DOS_SIGNATURE:
		fileSignatureStr = L"DOS";
		break;
	case IMAGE_OS2_SIGNATURE:
		fileSignatureStr = L"OS2";
		break;
	case IMAGE_VXD_SIGNATURE:
		fileSignatureStr = L"VXD";
		break;
	case IMAGE_NT_SIGNATURE:
		fileSignatureStr = L"NT";
		break;
	default:
		fileSignatureStr = L"N/A";
		break;
	}

	wprintf(L"\n======= File Signature [0x%08X] =======\n", (ULONG)((PBYTE)fileSignature - mapAddr));
	wprintf(L"Signature: %ls\n", fileSignatureStr);

	PIMAGE_FILE_HEADER fileHeader;
	fileHeader = (PIMAGE_FILE_HEADER)((PBYTE)fileSignature + sizeof(*fileSignature));

	wprintf(L"\n======= File Header [0x%08X] =======\n", (ULONG)((PBYTE)fileHeader - mapAddr));

	PWCHAR fileHeaderMachineStr;
	switch (fileHeader->Machine)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN:
		fileHeaderMachineStr = L"Unknown";
		break;
	case IMAGE_FILE_MACHINE_TARGET_HOST:
		fileHeaderMachineStr = L"Target Host";
		break;
	case IMAGE_FILE_MACHINE_I386:
		fileHeaderMachineStr = L"i386";
		break;
	case IMAGE_FILE_MACHINE_R3000:
		fileHeaderMachineStr = L"R3000";
		break;
	case IMAGE_FILE_MACHINE_R4000:
		fileHeaderMachineStr = L"R4000";
		break;
	case IMAGE_FILE_MACHINE_R10000:
		fileHeaderMachineStr = L"R10000";
		break;
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		fileHeaderMachineStr = L"WCE MIPS v2";
		break;
	case IMAGE_FILE_MACHINE_ALPHA:
		fileHeaderMachineStr = L"Alpha";
		break;
	case IMAGE_FILE_MACHINE_SH3:
		fileHeaderMachineStr = L"SH3";
		break;
	case IMAGE_FILE_MACHINE_SH3DSP:
		fileHeaderMachineStr = L"SH3 DSP";
		break;
	case IMAGE_FILE_MACHINE_SH3E:
		fileHeaderMachineStr = L"SH3E";
		break;
	case IMAGE_FILE_MACHINE_SH4:
		fileHeaderMachineStr = L"SH4";
		break;
	case IMAGE_FILE_MACHINE_SH5:
		fileHeaderMachineStr = L"SH5";
		break;
	case IMAGE_FILE_MACHINE_ARM:
		fileHeaderMachineStr = L"ARM";
		break;
	case IMAGE_FILE_MACHINE_THUMB:
		fileHeaderMachineStr = L"ARM Thumb";
		break;
	case IMAGE_FILE_MACHINE_ARMNT:
		fileHeaderMachineStr = L"ARM Thumb 2";
		break;
	case IMAGE_FILE_MACHINE_AM33:
		fileHeaderMachineStr = L"AM33";
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		fileHeaderMachineStr = L"IBM PowerPC";
		break;
	case IMAGE_FILE_MACHINE_POWERPCFP:
		fileHeaderMachineStr = L"IBM PowerPC FP";
		break;
	case IMAGE_FILE_MACHINE_IA64:
		fileHeaderMachineStr = L"Itanium";
		break;
	case IMAGE_FILE_MACHINE_MIPS16:
		fileHeaderMachineStr = L"MIPS";
		break;
	case IMAGE_FILE_MACHINE_ALPHA64:
		fileHeaderMachineStr = L"Alpha 64";
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		fileHeaderMachineStr = L"MIPS FPU";
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU16:
		fileHeaderMachineStr = L"MIPS FPU 16";
		break;
	case IMAGE_FILE_MACHINE_TRICORE:
		fileHeaderMachineStr = L"Infineon";
		break;
	case IMAGE_FILE_MACHINE_CEF:
		fileHeaderMachineStr = L"CEF";
		break;
	case IMAGE_FILE_MACHINE_EBC:
		fileHeaderMachineStr = L"EFI Byte Code";
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		fileHeaderMachineStr = L"AMD64 (K8)";
		break;
	case IMAGE_FILE_MACHINE_M32R:
		fileHeaderMachineStr = L"M32R";
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		fileHeaderMachineStr = L"ARM64";
		break;
	default:
		fileHeaderMachineStr = L"N/A";
		break;
	}

	static const PWSTR boolStrs[] = { L"False", L"True" };

	wprintf(L"Machine: 0x%04X, %ls\n"
			L"Number of sections: %u\n"
			L"Time stamp: 0x%04X, %ls"
			L"Pointer to symbol table: 0x%08X\n"
			L"Number of symbols: %u\n"
			L"Size of the optional header: %u\n"
			L"Characteristics: 0x%04X\n"
			L">\tRelocation info is stripped from the file: %ls\n"
			L">\tFile is executable: %ls\n"
			L">\tLine numbers are stripped from the file: %ls\n"
			L">\tLocal symbols are stripped from the file: %ls\n"
			L">\tAggressively trim working set: %ls\n"
			L">\tApp can handle >2GB addresses: %ls\n"
			L">\t<Not specified>: %ls\n"
			L">\tBytes of machine word are reversed: %ls\n"
			L">\t32 bit word machine: %ls\n"
			L">\tDebugging info stripped from the file in .DBG file: %ls\n"
			L">\tIf Image is on removable media, copy and run from the swap file: %ls\n"
			L">\tIf Image is on Net, copy and run from the swap file: %ls\n"
			L">\tSystem File: %ls\n"
			L">\tFile is a DLL: %ls\n"
			L">\tFile should only be run on a UP machine: %ls\n"
			L">\tBytes of machine word are reversed: %ls\n",
			fileHeader->Machine, fileHeaderMachineStr,
			fileHeader->NumberOfSections,
			fileHeader->TimeDateStamp, _wctime(&fileHeader->TimeDateStamp),
			fileHeader->PointerToSymbolTable,
			fileHeader->NumberOfSymbols,
			fileHeader->SizeOfOptionalHeader,
			fileHeader->Characteristics,
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_RELOCS_STRIPPED) >> 0],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) >> 1],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) >> 2],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) >> 3],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) >> 4],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) >> 5],
			boolStrs[(fileHeader->Characteristics & 0x0040) >> 6],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) >> 7],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_32BIT_MACHINE) >> 8], 
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_DEBUG_STRIPPED) >> 9],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) >> 10],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) >> 11],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_SYSTEM) >> 12],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_DLL) >> 13],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) >> 14],
			boolStrs[(fileHeader->Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) >> 15]);

	PIMAGE_OPTIONAL_HEADER optionalHeader;
	optionalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileHeader + IMAGE_SIZEOF_FILE_HEADER);

	wprintf(L"\n======= Optional Header [0x%08X] =======\n", (ULONG)((PBYTE)optionalHeader - mapAddr));

	BOOL is32;
	is32 = FALSE;

	PWSTR optionalHeaderMagicStr;
	switch (optionalHeader->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		optionalHeaderMagicStr = L"NT32";
		is32 = TRUE;
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		optionalHeaderMagicStr = L"NT64";
		break;
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		optionalHeaderMagicStr = L"ROM";
		break;
	default:
		optionalHeaderMagicStr = L"N/A";
		break;
	}

	PWSTR optionalHeaderSubsystemStr;
	switch (optionalHeader->Subsystem)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN:
		optionalHeaderSubsystemStr = L"Unknown";
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		optionalHeaderSubsystemStr = L"Native";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		optionalHeaderSubsystemStr = L"Windows GUI";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		optionalHeaderSubsystemStr = L"Windows CUI";
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		optionalHeaderSubsystemStr = L"OS2 CUI";
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		optionalHeaderSubsystemStr = L"Posix CUI";
		break;
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		optionalHeaderSubsystemStr = L"Native Windows";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		optionalHeaderSubsystemStr = L"Windows CE GUI";
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		optionalHeaderSubsystemStr = L"EFI Application";
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		optionalHeaderSubsystemStr = L"EFI Boot Service Driver";
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		optionalHeaderSubsystemStr = L"EFI Runtime Driver";
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		optionalHeaderSubsystemStr = L"EFI ROM";
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		optionalHeaderSubsystemStr = L"XBox";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		optionalHeaderSubsystemStr = L"Windows Boot Application";
		break;
	case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
		optionalHeaderSubsystemStr = L"XBox Code Catalog";
		break;
	default:
		optionalHeaderSubsystemStr = L"N/A";
		break;
	}

	wprintf(L"Magic: 0x%04X, %ls\n"
			L"Major Linker version: %u\n"
			L"Minor Linker version: %u\n"
			L"Size of code: %u, 0x%08X\n"
			L"Size of initialized data: %u, 0x%08X\n"
			L"Size of uninitialized data: %u, 0x%08X\n"
			L"Address of entry point: 0x%08X\n"
			L"Base of code: 0x%08X\n"
			L"Image base: 0x%016llX, (data: 0x%08X, base: 0x%08X)\n"
			L"Section alignment: %u\n"
			L"File alignment: %u\n"
			L"OS Major version: %u\n"
			L"OS Minor version: %u\n"
			L"Image Major version: %u\n"
			L"Image Minor version: %u\n"
			L"Subsystem Major version: %u\n"
			L"Subsystem Minor version: %u\n"
			L"Win32 version value: %u\n"
			L"Size of image: %u\n"
			L"Size of headers: %u\n"
			L"Checksum: %u, 0x%08X\n"
			L"Subsystem: %u, %ls\n"
			L"DLL Characteristics: 0x%04X\n"
			L">\tLibrary Process INIT: %ls\n"
			L">\tLibrary Process TERM: %ls\n"
			L">\tLibrary Thread INIT: %ls\n"
			L">\tLibrary Thread TERM: %ls\n"
			L">\t<Not specified by MS>: %ls\n"
			L">\tImage can handle a high entropy 64-bit virtual address space: %ls\n"
			L">\tDLL can move: %ls\n"
			L">\tCode Integrity Image: %ls\n"
			L">\tImage is NX compatible: %ls\n"
			L">\tImage understands isolation and doesn't want it: %ls\n"
			L">\tImage does not use SEH. No SE handler may reside in this image: %ls\n"
			L">\tDo not bind this image: %ls\n"
			L">\tImage should execute in an AppContainer: %ls\n"
			L">\tDriver uses WDM model: %ls\n"
			L">\tImage supports Control Flow Guard: %ls\n"
			L">\tTerminal Server aware: %ls\n"
			L"Size of stack reserve: %llu\n"
			L"Size of stack commit: %llu\n"
			L"Size of heap reserve: %llu\n"
			L"Size of heap commit: %llu\n"
			L"Loader flags: 0x%04X\n"
			L"Number of RVAs and Sizes: %u\n"
			L"Data directories: \n",
			optionalHeader->Magic, optionalHeaderMagicStr,
			optionalHeader->MajorLinkerVersion,
			optionalHeader->MinorLinkerVersion,
			optionalHeader->SizeOfCode, optionalHeader->SizeOfCode,
			optionalHeader->SizeOfInitializedData, optionalHeader->SizeOfInitializedData,
			optionalHeader->SizeOfUninitializedData, optionalHeader->SizeOfUninitializedData,
			optionalHeader->AddressOfEntryPoint,
			optionalHeader->BaseOfCode,
			optionalHeader->ImageBase, (DWORD)(optionalHeader->ImageBase & 0xFFFFFFFF), (DWORD)(optionalHeader->ImageBase >> 32),
			optionalHeader->SectionAlignment,
			optionalHeader->FileAlignment,
			optionalHeader->MajorOperatingSystemVersion,
			optionalHeader->MinorOperatingSystemVersion,
			optionalHeader->MajorImageVersion,
			optionalHeader->MinorImageVersion,
			optionalHeader->MajorSubsystemVersion,
			optionalHeader->MinorSubsystemVersion,
			optionalHeader->Win32VersionValue,
			optionalHeader->SizeOfImage,
			optionalHeader->SizeOfHeaders,
			optionalHeader->CheckSum, optionalHeader->CheckSum,
			optionalHeader->Subsystem, optionalHeaderSubsystemStr,
			optionalHeader->DllCharacteristics,
			boolStrs[(optionalHeader->DllCharacteristics & 0x01) >> 0],
			boolStrs[(optionalHeader->DllCharacteristics & 0x02) >> 1], 
			boolStrs[(optionalHeader->DllCharacteristics & 0x04) >> 2], 
			boolStrs[(optionalHeader->DllCharacteristics & 0x08) >> 3],
			boolStrs[(optionalHeader->DllCharacteristics & 0x10) >> 4],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) >> 5],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) >> 6],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) >> 7],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) >> 8],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) >> 9],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) >> 10],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) >> 11],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) >> 12],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) >> 13],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) >> 14],
			boolStrs[(optionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) >> 15],
		    !is32 ? optionalHeader->SizeOfStackReserve : ((PIMAGE_OPTIONAL_HEADER32)optionalHeader)->SizeOfStackReserve,
			!is32 ? optionalHeader->SizeOfStackCommit : ((PIMAGE_OPTIONAL_HEADER32)optionalHeader)->SizeOfStackCommit,
			!is32 ? optionalHeader->SizeOfHeapReserve : ((PIMAGE_OPTIONAL_HEADER32)optionalHeader)->SizeOfHeapReserve,
			!is32 ? optionalHeader->SizeOfHeapCommit : ((PIMAGE_OPTIONAL_HEADER32)optionalHeader)->SizeOfHeapCommit,
			!is32 ? optionalHeader->LoaderFlags : ((PIMAGE_OPTIONAL_HEADER32)optionalHeader)->LoaderFlags,
			!is32 ? optionalHeader->NumberOfRvaAndSizes : ((PIMAGE_OPTIONAL_HEADER32)optionalHeader)->NumberOfRvaAndSizes);

	static const WCHAR *dataDirectoryStrs[] =
	{
		L"Export",
		L"Import",
		L"Resource",
		L"Exception",
		L"Security",
		L"Base Relocation",
		L"Debug",
		L"Architecture",
		L"Global Pointer",
		L"TLS",
		L"Load Configuration",
		L"Bound Import",
		L"Import Address Tabl",
		L"Delay Import",
		L"COM Descriptor",
		L"<Not specified>"
	};

	PIMAGE_DATA_DIRECTORY dataDirStart;
	if (!is32)
	{
		dataDirStart = optionalHeader->DataDirectory;
	}
	else
	{
		dataDirStart = ((PIMAGE_OPTIONAL_HEADER32)optionalHeader)->DataDirectory;
	}

	for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
	{
		wprintf(L">\tIndex: %u\n"
				L">\tName: %ls\n"
				L">\tVirtual address: 0x%08X\n"
				L">\tSize: %u\n\n",
				i, 
				dataDirectoryStrs[i],
				(dataDirStart + i)->VirtualAddress,
				(dataDirStart + i)->Size);
	}

	PIMAGE_SECTION_HEADER sectionHeaderStart;
	sectionHeaderStart = (PIMAGE_SECTION_HEADER)((PBYTE)optionalHeader + fileHeader->SizeOfOptionalHeader);

	static const WCHAR sectionHeaderCharStrs[] = { L'-', L's', L'e', L'r', L'w' };

	for (WORD i = 0; i < fileHeader->NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER sectionHeader;
		sectionHeader = sectionHeaderStart + i;

		wprintf(L"\n======= Section [0x%08X] =======\n", (ULONG)((PBYTE)sectionHeader - mapAddr));

		wprintf(L"Name: %S\n"
				L"Virtual size/ Physical address: %u, 0x%08X\n"
				L"Virtual address: 0x%08X\n"
				L"Size of raw data: %u\n"
				L"Pointer to raw data: 0x%08X\n"
				L"Pointer to relocations: 0x%08X\n"
				L"Pointer to line numbers: 0x%08X\n"
				L"Number of relocations: %u\n"
				L"Number of line numbers: %u\n"
				L"Characteristics: 0x%08X, %lc%lc%lc%lc\n",
				sectionHeader->Name,
				sectionHeader->Misc.VirtualSize, sectionHeader->Misc.PhysicalAddress,
				sectionHeader->VirtualAddress,
				sectionHeader->SizeOfRawData,
				sectionHeader->PointerToRawData,
				sectionHeader->PointerToRelocations,
				sectionHeader->PointerToLinenumbers,
				sectionHeader->NumberOfRelocations,
				sectionHeader->NumberOfLinenumbers,
				sectionHeader->Characteristics,
				sectionHeaderCharStrs[((sectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) >> 28) * 1],
				sectionHeaderCharStrs[((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) >> 29) * 2],
				sectionHeaderCharStrs[((sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) >> 30) * 3],
				sectionHeaderCharStrs[((sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) >> 31) * 4]);
	}

	DWORD exportDirVA;
	exportDirVA = (dataDirStart + IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress;

	if (exportDirVA != NULL)
	{
		PIMAGE_SECTION_HEADER sectionHeader;
		sectionHeader = NULL;
		for (WORD i = 0; i < fileHeader->NumberOfSections; ++i)
		{
			sectionHeader = sectionHeaderStart + i;
			if (exportDirVA >= sectionHeader->VirtualAddress &&
				exportDirVA <= sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData)
				break;
		}

		if (sectionHeader != NULL)
		{
			DWORD exportDirRAW;
			exportDirRAW = exportDirVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

			PIMAGE_EXPORT_DIRECTORY exportDir;
			exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)mapAddr + exportDirRAW);

			wprintf(L"\n======= Export Directory [0x%08X] =======\n", exportDirRAW);

			DWORD exportDirNameRAW;
			exportDirNameRAW = exportDir->Name - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
			wprintf(L"Characteristics: 0x%08X\n"
					L"Time Stamp: 0x%08X, %ls\n"
					L"Major version: %u\n"
					L"Minor version: %u\n"
					L"Name: 0x%08X (Raw: 0x%08X) %S\n"
					L"Base: %u\n"
					L"Number of functions: %u\n"
					L"Number of names: %u\n"
					L"Address of functions: 0x%08X\n"
					L"Address of names: 0x%08X\n"
					L"Address of name ordinals: 0x%08X\n"
					L"Content: \n",
					exportDir->Characteristics,
					exportDir->TimeDateStamp, _wctime(&exportDir->TimeDateStamp),
					exportDir->MajorVersion,
					exportDir->MinorVersion,
					exportDir->Name, exportDirNameRAW, (PSTR)((PBYTE)mapAddr + exportDirNameRAW),
					exportDir->Base,
					exportDir->NumberOfFunctions,
					exportDir->NumberOfNames,
					exportDir->AddressOfFunctions,
					exportDir->AddressOfNames,
					exportDir->AddressOfNameOrdinals);

			for (DWORD j = 0; j < exportDir->NumberOfFunctions; ++j)
			{
				DWORD nameOffRVA;
				nameOffRVA = exportDir->AddressOfNames + j * sizeof (DWORD);
				
				DWORD nameOffRAW;
				nameOffRAW = nameOffRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
				
				DWORD nameRVA;
				nameRVA = *((PDWORD)((PBYTE)mapAddr + nameOffRAW));

				DWORD nameRAW;
				nameRAW = nameRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

				wprintf(L">\tName: 0x%08X (off: 0x%08X.0x%08X), %S\n",
						nameRAW, nameOffRVA, nameOffRAW, (PSTR)((PBYTE)mapAddr + nameRAW));

				DWORD addrOffRVA;
				addrOffRVA = exportDir->AddressOfFunctions + j * sizeof(DWORD);

				DWORD addrOffRAW;
				addrOffRAW = addrOffRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

				DWORD addrRVA;
				addrRVA = *((PDWORD)((PBYTE)mapAddr + addrOffRAW));

				DWORD addrRAW;
				addrRAW = addrRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

				wprintf(L">\tAddress: 0x%08X.0x%08X (off: 0x%08X.0x%08X)\n",
					addrRVA, addrRAW, addrOffRVA, addrOffRAW);

				DWORD ordOffRVA;
				ordOffRVA = exportDir->AddressOfNameOrdinals + j * sizeof(DWORD);

				DWORD ordOffRAW;
				ordOffRAW = ordOffRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

				DWORD ordRVA;
				ordRVA = *((PDWORD)((PBYTE)mapAddr + ordOffRAW));

				DWORD ordRAW;
				ordRAW = ordRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

				wprintf(L">\tOrdinal: 0x%08X.0x%08X (off: 0x%08X.0x%08X)\n\n",
					ordRVA, ordRAW, ordOffRVA, ordOffRAW);
			}
		}
	}

	DWORD importDirVA;
	importDirVA = (dataDirStart + IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;

	if (importDirVA != NULL)
	{
		PIMAGE_SECTION_HEADER sectionHeader;
		sectionHeader = NULL;
		for (WORD i = 0; i < fileHeader->NumberOfSections; ++i)
		{
			sectionHeader = sectionHeaderStart + i;
			if (importDirVA >= sectionHeader->VirtualAddress &&
				importDirVA <= sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData)
				break;
		}

		if (sectionHeader != NULL)
		{
			DWORD importDirRAW;
			importDirRAW = importDirVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

			PIMAGE_IMPORT_DESCRIPTOR importDescStart;
			importDescStart = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)mapAddr + importDirRAW);

			PWSTR importDescBoundStr;
			importDescBoundStr = L"N/A";

			PIMAGE_IMPORT_DESCRIPTOR importDesc;
			importDesc = importDescStart;
			while (importDesc->Characteristics)
			{
				wprintf(L"\n======= Import Descriptor [0x%08X] =======\n", (DWORD)(importDesc - mapAddr));

				if (importDesc->TimeDateStamp == 0)
				{
					importDescBoundStr = L"Not bound";
				}
				else if (importDesc->TimeDateStamp == -1)
				{
					importDescBoundStr = L"Bound";
				}

				DWORD nameRAW;
				nameRAW = importDesc->Name - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

				wprintf(L"Original first Thunk: 0x%08X\n"
						L"Time stamp: 0x%08X, %ls\n"
						L"Forwarder chain: %i %ls\n"
						L"Name: 0x%08X.0x%08X, %S\n"
						L"First thunk: 0x%08X\n"
						L"Content: \n",
						importDesc->OriginalFirstThunk,
						importDesc->TimeDateStamp, importDescBoundStr,
						importDesc->ForwarderChain, importDesc->ForwarderChain == -1 ? L"No forwarders" : L"",
						importDesc->Name, nameRAW, (PSTR)((PBYTE)mapAddr + nameRAW),
						importDesc->FirstThunk);

				DWORD thunkStart;
				thunkStart = importDesc->FirstThunk;

				while (TRUE)
				{
					DWORD thunkRAW;
					thunkRAW = thunkStart - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

					ULONGLONG dataRVA;
					if (!is32)
					{
						dataRVA = *((PULONGLONG)((PBYTE)mapAddr + thunkRAW));
					}
					else
					{
						dataRVA = *((PDWORD)((PBYTE)mapAddr + thunkRAW));
					}

					if (dataRVA == 0x0)
					{
						break;
					}

					DWORD dataRAW;
					WORD dataHint;
					PSTR dataName;
					DWORD dataOrd;

					if ((!is32 && dataRVA & 0x8000000000000000) 
						|| (is32 && dataRVA & 0x80000000))
					{
						dataRAW = 0x0;
						dataHint = 0x0;
						dataName = "Ordinal";
						dataOrd = dataRVA & 0xFFFFFFFF;
					}
					else 
					{
						dataRAW = dataRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;

						PIMAGE_IMPORT_BY_NAME dataByName;
						dataByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)mapAddr + dataRAW);
					
						dataHint = dataByName->Hint;
						dataName = dataByName->Name;
						dataOrd = 0x0;
					}

					wprintf(L">\tData address: 0x%08X.0x%08X\n"
							L">\tHint: 0x%04X\n"
							L">\tName: %S (ord: %u)\n\n",
							dataRVA, dataRAW,
							dataHint,
							dataName, dataOrd);

					if (!is32)
					{
						thunkStart += sizeof(ULONGLONG);
					}
					else
					{
						thunkStart += sizeof(DWORD);
					}
				}

				++importDesc;
			}
		}
	}


	UnmapViewOfFile(mapAddr);
	CloseHandle(hndMap);
	CloseHandle(hndFile);

	return 0;
}