/* main.c
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
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

#include "pariteb.h"

#define _strnew()((char*)malloc(2*MAX_PATH+1))
#define _strdup(s)strcpy(_strnew(),(const char*)(s))
#define _strdispose(s)free((void*)(s))

int 													\
	g_iTotalFileCount	 					= 0, 	\
	g_iTotalDirectoryCount 				= 0, 	\
	g_iTotalInfectedCount 				= 0, 	\
	g_iTotalDisinfectionCount			= 0, 	\
	g_iTotalSkippedByUser				= 0,	\
	g_iTotalDisinfectionFailedCount 	= 0;

char *IncludeTrailingPathDelimiter( char *inPath )
{
	char \
	  	*l_strResult = inPath;
	int \
		l_iLength = strlen( l_strResult );
		
	if ((l_iLength > 0) && (l_strResult[ l_iLength - 1 ] != '\\'))
	{
		l_strResult[ l_iLength     ] = '\\';
		l_strResult[ l_iLength + 1 ] = '\0';
	}
	
	return l_strResult;
}

int QueryDisinfection( void )
{
	char \
		l_cbChoice;
		
	printf( " <-- !!! INFECTED !!!, disinfect now [Y/N]?" );
	
	do
	{ l_cbChoice = (char)_toupper(getch()); }
	while ((l_cbChoice != 'Y') && (l_cbChoice != 'N'));
	
	printf( "%c", l_cbChoice );
	
	return (int)(l_cbChoice == 'Y');
}

void ClrEOL( void )
{
	HANDLE \
		l_hConsoleOutput;
	CONSOLE_SCREEN_BUFFER_INFO \
		l_varInfo;
	DWORD
		l_iReturnLength,
		l_iCmdLineLength;
		
	l_hConsoleOutput = GetStdHandle( STD_OUTPUT_HANDLE );
	GetConsoleScreenBufferInfo( l_hConsoleOutput, &l_varInfo );
	
	l_iCmdLineLength = l_varInfo.dwMaximumWindowSize.X - l_varInfo.dwCursorPosition.X;
	FillConsoleOutputCharacterA( l_hConsoleOutput, 0x0020, l_iCmdLineLength, l_varInfo.dwCursorPosition, &l_iReturnLength );
}

void PrintFileName( const char *inFileName )
{
	printf( "\t%s", inFileName );
	ClrEOL();
}

void PrintInfected( const char *inFileName )
{
	printf( "\r" );
	PrintFileName( inFileName );
	ClrEOL();
	printf( " <-- !!! INFECTED !!!" );
}

void PrintDisinfected( const char *inFileName )
{
	printf( "\r" );
	PrintFileName( inFileName );
	ClrEOL();
	printf( " --> DISINFECTED" );
}

void PrintDisinfectionFailed( const char *inFileName )
{
	printf( "\r" );
	PrintFileName( inFileName );
	ClrEOL();
	printf( " ---> !!!DISINFECTION FAILED!!!" );
}

void PrintSkippedByUser( const char *inFileName )
{
	printf( "\r" );
	PrintFileName( inFileName );
	ClrEOL();
	printf( " ---> !!!SKIPPED BY USER!!!" );
	
}

void ScanFile( const char *inPath, const char *inFileName )
{
	char \
		*l_strFileFullPathName;
	int
		l_iMaxConWinWidth,
		l_iErrorCode;
	struct infection_context_t \
		l_varInfectionContext;
	
	PrintFileName( inFileName );

	l_strFileFullPathName = strcat( strcpy( _strnew(), inPath ), inFileName );
	
	switch (CheckIsFileInfected( l_strFileFullPathName, &l_varInfectionContext ))
	{
		case ERROR_INFECTED:
			
			g_iTotalInfectedCount++;
			PrintInfected( inFileName ); 

			if (QueryDisinfection())
			{
				if (Disinfect( l_strFileFullPathName, &l_varInfectionContext ))
				{
					g_iTotalDisinfectionCount++;
					PrintDisinfected( inFileName );
				}
				else
				{
					g_iTotalDisinfectionFailedCount++;
					PrintDisinfectionFailed( inFileName );
				}
			}
			else
			{
				g_iTotalSkippedByUser++;
				PrintSkippedByUser( inFileName );
			}
			
			break;
			
		default:
			
			g_iTotalFileCount++;
			
			break;
	}
	
	_strdispose(l_strFileFullPathName);
	
	printf( "\r\n" );
}

void ExploreDirectory( const char *inPath )
{
	char 							\
		*l_strPath,				\
		*l_strSearchPattern,	\
		*l_strSubPath;
	HANDLE 						\
		l_hFind;
	WIN32_FIND_DATAA 			\
		l_varData;
		
	g_iTotalDirectoryCount++;
	
	printf( "\r\n%s\r\n", inPath );
	
	l_strPath = IncludeTrailingPathDelimiter( _strdup(inPath) );	
	l_strSearchPattern = strcat( _strdup(l_strPath), "*.*" );
	l_strSubPath = _strnew();
	
	if ((l_hFind = FindFirstFileA( l_strSearchPattern, &l_varData )) != INVALID_HANDLE_VALUE)
	{
		do 
		{
			if (l_varData.cFileName[ 0 ] != '.')
			{	
				if ((l_varData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
				{ ExploreDirectory( strcat( strcpy( l_strSubPath, l_strPath ), (const char *)&l_varData.cFileName[ 0 ] ) ); }
				else
				{ ScanFile( l_strPath, (const char *)&l_varData.cFileName[ 0 ] ); }
			}
		}
		while (FindNextFileA( l_hFind, &l_varData ));
		
		FindClose( l_hFind );
	}
	
	_strdispose(l_strSubPath);
	_strdispose(l_strSearchPattern);
	_strdispose(l_strPath);
}

int main( int inArgCount, char *inArgVector[] ) 
{	
	ExploreDirectory( "D:\\" );

	printf( "\r\n\r\n\r\n" );
	printf( "REPORT:\r\n\r\n" );
	printf( "\tTotal Directory:           %d\r\n", g_iTotalDirectoryCount );
	printf( "\tTotal File:                %d\r\n", g_iTotalFileCount );
	printf( "\tTotal Infected:            %d\r\n", g_iTotalInfectedCount );
	printf( "\tTotal Disinfection:        %d\r\n", g_iTotalDisinfectionCount );
	printf( "\tTotal Disinfection Failed: %d\r\n", g_iTotalDisinfectionFailedCount );
	printf( "\tTotal Skipped By User:     %d\r\n", g_iTotalSkippedByUser );

	return 0;
}