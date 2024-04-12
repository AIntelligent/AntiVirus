/* pariteb.c
 *
 * Anti Parite-B
 *
 * 	Bu program, MS Windows 32bit işletim sitemlerinde çalışan ve bir dosya virüsü 
 *	olan Parite-B'nin temizleyicisidir. Belirtilen sürücüdeki tüm klasörler ve alt 
 * klasörlerdeki dosyaları tarar. Eğer virüslü bir dosya bulursa kullanıcıyı uyarır 
 * ve kullnıcı işlem onayı verirse virüsü temizler. Tamamlandığında kullanıcıya 
 * rapor görüntüler.
 *
 * Not(lar):
 *
 * 	>	İlk olarak Borland C++Builder 6.0 ile geliştirilmiştir. AIntelligent GitHub
 * 	hesabından yayımlamadan önce Dev-C++ için uyarlanmıştır. Bazı kişisel bilgiler
 * 	güncellenmiştir. 
 *
 * 	>	Günümüzde, MS Windows işletim sistemleri çok geliştiği ve Parite-B gibi zararlılar 
 *		için etkin çözümler bulunduğundan, artık eskisi gibi yayılamıyorlar. Dolayısıyla, Parite-B
 * 	temizleyicisinin güncel doğruluğu tespit edilememiştir.
 *
 * !!! Dikkat !!!: 
 *			
 *		>	Eğer bu temizleyiciyi bilgisayarınızda kullanmak isterseniz, oluşabilecek
 * 	tüm olumsuz durumlar için sorumluluk size aittir.
 *
 *		>	Uyarlamadan kaynaklı sorunlar bulunabilir.
 *
 * Tarihçe:
 *
 * 	> 10/04/2024
 *    		> Bazı kişisel bilgiler güncellendi.
 *    		> Dev-C++ ile yeniden derlendi.
 * 	> 01/02/2008
 *    		> Üretildi ve Borland C++Builder 6.0 ile derlendi.
 *
 * Hakan Emre KARTAL tarafından İskenderun/HATAY'da 01/02/2008 tarihinde
 * Borland C++Builder 6.0 ile geliştirildi.
 *
 * Hakan Emre KARTAL
 * hek@nula.com.tr 
 *
 * Anti Parite-B
 *
 * 	This program is an anti-virus against Parity-B, a file virus that runs on MS Windows 32bit 
 * operating systems. All folders and subfolders in the specified drive scans the files in the 
 * folders. If it finds an infected file, it warns the user and removes the virus if the user 
 * confirms the action. Once completed the user displays the report.
 *
 * Notes:
 *		
 * 	> 	Originally developed with Borland C++Builder 6.0. Updated for Dev-C++ before release 
 *		from @AIntellient's GitHub account.
 *
 * 	>	Some personal information has been updated.
 *
 *		>	Nowadays, MS Windows operating systems are quite advanced and malware like Parity-B 
 *		are no longer there as effective solutions have been found. Therefore, the current accuracy 
 *		of the Parity-B cleaner could not be determined.
 *
 * !!! Attention !!!:
 *
 *		>	If you want to use this cleaner on your computer, you are responsible for all negative 
 *		situations.
 *
 *		>	Compatibility issues may arise.
 *
 * History:
 *		
 *		> 10/04/2024
 *     	>	Some personal information has been updated.
 *       > 	Recompiled with Dev-C++.
 *		> 01/02/2008
 *      	> Produced and compiled with Borland C++Builder 6.0.
 *
 * Written by Hakan Emre KARTAL in Iskenderun/HATAY on 01/02/2008,
 * developed with Borland C++Builder 6.0
 *
 * Hakan Emre KARTAL
 * hek@nula.com.tr 
 *
 */
#include "pariteb.h"

const 																	\
	VIRUS_SIGNATURE													\
		PariteBSignature =											\
		{ 																	\
			0xB9, 0x78, 0x71, 0x7C, 0x00, 0xBE, 0x22, 0x90, \
			0x40, 0x00, 0xBF, 0x98, 0x05, 0x00, 0x00, 0xFF, \
			0x34, 0x3E, 0x31, 0x0C, 0x24, 0x8F, 0x04, 0x3E 	\
		};
		
const																		\
	VIRUS_SECTION_NAME												\
		PariteBSectionName = 										\
		{ 																	\
			0x2E, 0x70, 0x6D, 0x6A, 0x07, 0x00, 0x00, 0x00, \
			0x00, 0x00 													\
		};

int CheckIsFileInfected( const char *inFileFullPathName, struct infection_context_t *outInfectionContext )
{
	FILE 						\
		*l_ptrFileObject;
	int 						\
		l_iErrorCode = ERROR_SUCCESS;
	VIRUS_SIGNATURE 		\
		l_arrSignature;
	IMAGE_DOS_HEADER 		\
		l_varDOSHeader;	
	IMAGE_NT_HEADERS 		\
		l_varNTHeaders;	
	IMAGE_SECTION_HEADER	\
		l_arrSections[ MAXIMUM_SECTION_ENTRY ],
		*l_ptrInfectedSection;
	
	if ((l_ptrFileObject = fopen( inFileFullPathName, "r+b" )) == NULL)
	{
		l_iErrorCode = ERROR_FILE_NOT_OPENED;
		goto __ExitRoutine;
	}

	if (!__fread_s(l_ptrFileObject, &l_varDOSHeader, sizeof(IMAGE_DOS_HEADER)))
	{
		l_iErrorCode = ERROR_INSUFFICIENT_FILE_SIZE;
		goto __ExitRoutine;
	}
	
	if (!__is_valid_dos_header(l_varDOSHeader))
	{
		l_iErrorCode = ERROR_NOT_EXECUTABLE_FILE;
		goto __ExitRoutine;
	}
	
	fseek( l_ptrFileObject, l_varDOSHeader.e_lfanew, SEEK_SET );
	
	if (!__fread_s(l_ptrFileObject, &l_varNTHeaders, sizeof(IMAGE_NT_HEADERS)))
	{
		l_iErrorCode = ERROR_INSUFFICIENT_FILE_SIZE;
		goto __ExitRoutine;
	}
	
	if (!__is_valid_nt_headers(l_varNTHeaders))
	{
		l_iErrorCode = ERROR_NOT_EXECUTABLE_FILE;
		goto __ExitRoutine;
	}
	
	if (!__fread_s(l_ptrFileObject, &l_arrSections[ 0 ], 	\
						sizeof(IMAGE_SECTION_HEADER) * 			\
						l_varNTHeaders.FileHeader.NumberOfSections))
	{
		l_iErrorCode = ERROR_INSUFFICIENT_FILE_SIZE;
		goto __ExitRoutine;
	}
	
	if (!__is_valid_image(l_varNTHeaders))
	{
		l_iErrorCode = ERROR_INVALID_IMAGE;
		goto __ExitRoutine;
	}
	
	for (int i = 0; i < l_varNTHeaders.FileHeader.NumberOfSections; i++)
	{
		if (__is_pariteb_section(l_arrSections[ i ], PariteBSectionName))
		{
			fseek( l_ptrFileObject, l_arrSections[ i ].PointerToRawData, SEEK_SET );
			
			if (!__fread_s(l_ptrFileObject, &l_arrSignature[ 0 ], MAX_VIRUS_SIGNATURE))
			{
				l_iErrorCode = ERROR_INSUFFICIENT_FILE_SIZE;
				goto __ExitRoutine;
			}
			
			l_iErrorCode = __is_pariteb_sign(&l_arrSignature[ 0 ], &PariteBSignature[ 0 ]) 	\
											? ERROR_INFECTED 														\
											: ERROR_FILE_IS_CORRUPT;
											
			l_ptrInfectedSection = &l_arrSections[ i ];
			
			goto __ExitRoutine;
		}
	}
		
__ExitRoutine:
	
	if (l_ptrFileObject != NULL)
	{
		fclose( l_ptrFileObject );
	}
	
	if (l_iErrorCode == ERROR_INFECTED)
	{ 
		outInfectionContext->dos_header = l_varDOSHeader;
		outInfectionContext->nt_headers = l_varNTHeaders;
		
		for (int i = 0; i < l_varNTHeaders.FileHeader.NumberOfSections; i++)
		{
			outInfectionContext->sections[ i ] = l_arrSections[ i ];
			
			if (&l_arrSections[ i ] == l_ptrInfectedSection)
			{
				outInfectionContext->infected_section = &outInfectionContext->sections[ i ];
			}
		}
	}
	
	return l_iErrorCode;
}

int Disinfect( const char *inInfectedFileFullPathName, struct infection_context_t *inInfectionContext )
{
	char \
		*l_strTempFileFullPathName;
	FILE \
		*l_ptrInfectedFileObject = NULL;
	int \
		l_iErrorCode = ERROR_SUCCESS;
	void * \
		l_ptrData = NULL;
	char \
		l_cbNibble = 0;
		
	l_strTempFileFullPathName = strcat( strdup( inInfectedFileFullPathName ), ".$$$" );
	
	CopyFileA( inInfectedFileFullPathName, l_strTempFileFullPathName, FALSE );
	SetFileAttributesA( l_strTempFileFullPathName, FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN );
	
	if ((l_ptrInfectedFileObject = fopen( l_strTempFileFullPathName, "wb" )) == NULL)
	{
		l_iErrorCode = ERROR_FILE_NOT_OPENED;
		goto __ExitRoutine;
	}
	
	if ((l_ptrData = malloc( inInfectionContext->infected_section->SizeOfRawData )) == NULL)
	{
		l_iErrorCode = ERROR_INSUFFICIENT_MEMORY;
		goto __ExitRoutine;
	}
	
	fseek( l_ptrInfectedFileObject, inInfectionContext->infected_section->PointerToRawData, SEEK_SET );
	
	if (!__fread_s( l_ptrInfectedFileObject, l_ptrData, inInfectionContext->infected_section->SizeOfRawData ))
	{
		l_iErrorCode = ERROR_INSUFFICIENT_FILE_SIZE;
		goto __ExitRoutine;
	}
	
	for (int j = PARITEB_CYRPT_COUNT; j >=0; --j)
	{ ((PDWORD)l_ptrData)[ j ] = ((PDWORD)l_ptrData)[ j ] ^ PARITEB_KEY; }
	
	inInfectionContext->nt_headers.OptionalHeader.AddressOfEntryPoint = *((PDWORD)FPOFFS(l_ptrData, PARITEB_REAL_ENTRY_POS));
	
	free( l_ptrData );
	
	inInfectionContext->dos_header.e_lfanew += 0x0008;
	
	fseek( l_ptrInfectedFileObject, 0, SEEK_SET );
	
	if (!__fwrite_s(l_ptrInfectedFileObject, &inInfectionContext->dos_header, sizeof(IMAGE_DOS_HEADER)))
	{
		l_iErrorCode = ERROR_UNEXPECTED_ON_WRITE;
		goto __ExitRoutine;
	}
		
	inInfectionContext->nt_headers.FileHeader.NumberOfSections--;
	inInfectionContext->nt_headers.OptionalHeader.SizeOfImage -= 0x1000;
	inInfectionContext->nt_headers.OptionalHeader.AddressOfEntryPoint += 0x000AL;
	
	fseek( l_ptrInfectedFileObject, inInfectionContext->dos_header.e_lfanew - 0x0008, SEEK_SET );

	for (int i = 0; i < NIBBLE_BYTE_COUNT; i++)
	{
		if (!__fwrite_s( l_ptrInfectedFileObject, &l_cbNibble, sizeof(l_cbNibble) ))
		{
			l_iErrorCode = ERROR_UNEXPECTED_ON_WRITE;
			goto __ExitRoutine;
		}
	}
	
	if (!__fwrite_s(l_ptrInfectedFileObject, &inInfectionContext->nt_headers, sizeof(IMAGE_NT_HEADERS)))
	{
		l_iErrorCode = ERROR_UNEXPECTED_ON_WRITE;
		goto __ExitRoutine;
	}
	
	memset( inInfectionContext->infected_section, 0, sizeof(IMAGE_SECTION_HEADER) );
	
	if (!__fwrite_s(l_ptrInfectedFileObject, inInfectionContext->sections, 	\
						 sizeof(IMAGE_SECTION_HEADER) 									\
						 	* inInfectionContext												\
							 		->nt_headers												\
									.FileHeader													\
									.NumberOfSections + 1 ))
	{
		l_iErrorCode = ERROR_UNEXPECTED_ON_WRITE;
		goto __ExitRoutine;
	}
	
	fseek( l_ptrInfectedFileObject, inInfectionContext->infected_section->PointerToRawData, SEEK_SET );
	
	ftell( l_ptrInfectedFileObject );

__ExitRoutine:

	if (l_ptrInfectedFileObject != NULL)
	{
		fclose( l_ptrInfectedFileObject );
	}
	
	if (l_iErrorCode == ERROR_SUCCESS)
	{
		SetFileAttributesA( l_strTempFileFullPathName, GetFileAttributesA( inInfectedFileFullPathName ) );	
		CopyFileA( l_strTempFileFullPathName, inInfectedFileFullPathName, FALSE );
	}
	
	return l_iErrorCode;
}