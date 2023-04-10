#include <Windows.h>
#include "ntos.h"
#include <TlHelp32.h>
#include <stdio.h>
#include <psapi.h>

HANDLE GetProcHandle( const char* name ) {

    HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    PROCESSENTRY32 entry;
    DWORD pid = 0;

    memset( &entry, 0, sizeof( entry ) );

    entry.dwSize = sizeof( entry );
    if( !Process32First( snapshot, &entry ) )
    {
        CloseHandle( snapshot );
        return NULL;
    }

    while( Process32Next( snapshot, &entry ) )
        if( !strcmp( entry.szExeFile, name ) )
        {
            pid = entry.th32ProcessID;
            break;
        }



    if( pid != 0 )
        return OpenProcess( PROCESS_ALL_ACCESS, 0, pid );


    return NULL;
}

typedef NTSTATUS ( WINAPI* fRtlInitUnicodeString)(
    PUNICODE_STRING target,
    PCWSTR source );

typedef NTSTATUS( WINAPI* fLdrLoadDll )
(
    IN PWCHAR PathToFile OPTIONAL,
    IN ULONG Flags OPTIONAL,
    IN PUNICODE_STRING ModuleFileName,
    OUT PHANDLE ModuleHandle
    );

typedef struct _ExternLoaderInformation
{
    fRtlInitUnicodeString RtlInitUnicodeString;
    fLdrLoadDll LdrLoadDll;

    PWSTR StringAddress;

    UNICODE_STRING usDllFile;
    HANDLE h;

}ExternLoaderInformation;



#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall  ExternLoader( LPVOID Memory ) {

   
    ExternLoaderInformation* pog = ( ExternLoaderInformation* )Memory;

    pog->RtlInitUnicodeString( &pog->usDllFile, pog->StringAddress );
    pog->LdrLoadDll( NULL, NULL, &pog->usDllFile, &pog->h );
}

DWORD __stdcall endstub( ) {
    return 0;
}

const wchar_t uDllPath[ ] = L"F:\\PreventVAC\\Release\\PreventVAC.dll";
int main( ) {

    

    HANDLE hProc = NULL;
    HMODULE hModule = GetModuleHandleA( "ntdll.dll" );
    DWORD bytesNeeded;
    DWORD dwTemp;
    ExternLoaderInformation Ldr;

    printf( "[+] waiting on steam.exe\n" );
    while( hProc == NULL )
        hProc = GetProcHandle( "steam.exe" );
    printf( "[+] found process\n" );



    HMODULE modules[ 260 ];
    CHAR moduleName[ 260 ];
    BOOL rc = EnumProcessModules( hProc, modules, sizeof( modules ), &bytesNeeded );

    printf( "[+] waiting on steamservice.dll\n" );
    while( 1 )
    {
        int count = ( int )( bytesNeeded / sizeof( HMODULE ) );
        for( int i = 0; i < count; i++ )
        {

            GetModuleFileName( modules[ i ], moduleName, 260 );
            if( !strstr( moduleName, "steamservice" ) )
                goto done;

        }
    }
done:
    Sleep( 1000 );
    NtSuspendProcess( hProc );
    printf( "[+] found steamservice.dll\n" );
    
    printf( "[+] injecting shellcode into %p\n", hProc );


    LPVOID StructAllocation = VirtualAllocEx( hProc, 0, sizeof( ExternLoaderInformation ), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    if( StructAllocation == NULL )
    {
        printf( "[+] couldn't alloc struct\n" );
        while( 1 );
    }
    printf( "[+] allocated ldr struct at %p\n", StructAllocation );

    LPVOID StringAddress = VirtualAllocEx(
        hProc, 0, lstrlenW( uDllPath ) * sizeof( wchar_t ),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

    if( StringAddress == NULL )
    {
        printf( "[+] couldn't alloc string\n" );
        while( 1 );
    }

    printf( "[+] allocated string at %p\n", StringAddress );

    Ldr.LdrLoadDll = ( fLdrLoadDll )GetProcAddress( hModule, "LdrLoadDll" );
    Ldr.RtlInitUnicodeString = ( fRtlInitUnicodeString )GetProcAddress( hModule, "RtlInitUnicodeString" );
    Ldr.StringAddress = (PWSTR)StringAddress;
    
    if( !WriteProcessMemory( hProc, StringAddress, &uDllPath, lstrlenW( uDllPath ) * sizeof( wchar_t ), &dwTemp ) )
    {
        printf( "[+] couldn't write string\n" );
        while( 1 );
    }
    printf( "[+] wrote string at %p\n", StringAddress );

    if( !WriteProcessMemory( hProc, StructAllocation, &Ldr, sizeof( Ldr ), &dwTemp ) )
    {
        printf( "[+] couldn't write struct\n" );
        while( 1 );
    }
    printf( "[+] wrote struct at %p\n", StructAllocation );

    PVOID LdrMem = VirtualAllocEx( hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE );

    if( LdrMem == NULL )
    {
        printf( "[+] couldn't alloc loader shellcode\n" );
        while( 1 );
    }

    if( !WriteProcessMemory( hProc, ( PVOID )LdrMem, ExternLoader,
        ( DWORD )endstub - ( DWORD )ExternLoader, NULL ) )
    {
        printf( "[+] couldn't write loader shellcode\n" );
        while( 1 );

    }
    printf( "[+] writing shellcode %p at %p\n", ExternLoader, LdrMem );
    NtResumeProcess( hProc );


    HANDLE hThread = CreateRemoteThread( hProc, 0, 0, ( LPTHREAD_START_ROUTINE )( LdrMem ), StructAllocation, 0, 0 );
    SuspendThread( hThread );
    Sleep( 1000 );
    ResumeThread( hThread );
    printf( "[+] executed shellcode\n\n" );

    

eoc:
    system( "pause" );
    
}
