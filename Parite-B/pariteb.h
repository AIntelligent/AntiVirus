/* pariteb.h
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
#ifndef __PARITEB_H
#define __PARITEB_H

#include <windows.h>
#include <stdio.h>

#define MAX_VIRUS_SIGNATURE			(24)
#define MAX_VIRUS_SECTION_NAME		(10)

typedef \
	unsigned char \
	VIRUS_SIGNATURE[ MAX_VIRUS_SIGNATURE ];
	
typedef \
	unsigned char \
	VIRUS_SECTION_NAME[ MAX_VIRUS_SECTION_NAME ];
	
#define VIRUS_SIGNATURE_SIZE				sizeof(VIRUS_SIGNATURE)

/// Crypted dwords count
#define PARITEB_CYRPT_COUNT				(0x0598)
	
/// Cyrpt count
#define PARITEB_SIZE							(PARITEB_CYRPT_COUNT * 0x0004)

/// XOR Key
#define PARITEB_KEY							((unsigned long)0x007C7178)

/// Entry point + 0x0022
#define PARITEB_CYRPT_START_POS			(0x0022)

/// Entry point + 0x0022 + 0x0010
#define PARITEB_REAL_ENTRY_POS			(0x0032)

#define MAXIMUM_SECTION_ENTRY 			(0x0060)

#define ERROR_NOT_INFECTED					(0)
#define ERROR_INFECTED						(+1)
#define ERROR_FILE_NOT_OPENED 			(-1)
#define ERROR_INSUFFICIENT_FILE_SIZE	(-2)
#define ERROR_INVALID_IMAGE				(-3)
#define ERROR_FILE_IS_CORRUPT				(-4)
#define ERROR_FILE_IS_NOT_ACCESSIBLE	(-5)
#define ERROR_UNEXPECTED_ON_WRITE		(-6)
#define ERROR_END_OF_QUEUE					(-7)
#define ERROR_INSUFFICIENT_MEMORY		(-8)
#define ERROR_NOT_EXECUTABLE_FILE		(-9)

#define NIBBLE_BYTE_COUNT					(8)

#define FPOFFS(p,o)((LPVOID)(((DWORD)(p))+((DWORD)(o))))

#define __is_valid_dos_header(d)((((IMAGE_DOS_HEADER)(d)).e_magic)==IMAGE_DOS_SIGNATURE)
#define __is_valid_nt_headers(n)((((IMAGE_NT_HEADERS)(n)).OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC)\
											&&(((IMAGE_NT_HEADERS)(n)).Signature==IMAGE_NT_SIGNATURE))
#define __is_valid_image(n)((((IMAGE_NT_HEADERS)(n)).FileHeader.Characteristics&0x2102)==0x0102)
#define __is_pariteb_section(s,n)(strnicmp((const char*)&((IMAGE_SECTION_HEADER)(s)).Name[0],\
											 (const char*)&(n),MAX_VIRUS_SECTION_NAME)==0)
#define __is_pariteb_sign(s,n)(memcmp(((const void *)(s)),((const void *)(n)),MAX_VIRUS_SIGNATURE)==0)
#define __sections_size(n)((((IMAGE_NT_HEADERS*)(n))->FileHeader.NumberOfSections)*(sizeof(IMAGE_SECTION_HEADER)))

#define __fread_s(f,p,l)(fread(((void*)(p)),1,((size_t)(l)),(f))==((size_t)(l)))
#define __fwrite_s(f,p,l)(fwrite(((void*)(p)),1,((size_t)(l)),(f))==((size_t)(l)))

struct infection_context_t
{
	IMAGE_DOS_HEADER 				dos_header;
	
	IMAGE_NT_HEADERS 				nt_headers;
	
	IMAGE_SECTION_HEADER			sections[ MAXIMUM_SECTION_ENTRY ];
	
	IMAGE_SECTION_HEADER			*infected_section;
};

#define infection_context_length ((size_t)sizeof(struct infection_context_t))

extern int CheckIsFileInfected( const char *inFileFullPathName, struct infection_context_t *outInfectionContext );
extern int Disinfect( const char *inInfectedFileFullPathName, struct infection_context_t *inInfectionContext );

#endif