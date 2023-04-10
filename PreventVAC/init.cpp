#include "preventvac.hpp"
#include "minhook/MinHook.h"
#include <Psapi.h>
#include "../PVACLoader/ntos.h"

win32hook( VOID __stdcall, OutputDebugStringA, ( LPCSTR lpOut ) ) {
    printf( "[Valve Anti-Cheat] %s", lpOut );
    _hOutputDebugStringA( lpOut );
}

win32hook( HWND __stdcall, GetForegroundWindow, ( ) ) {

    
    //printf( "[WIN32] redirecting to desktop device context\n" );
    return GetDesktopWindow(  );
}



win32hook( SIZE_T __stdcall, VirtualQueryEx, ( HANDLE h, LPCVOID s, PMEMORY_BASIC_INFORMATION x, SIZE_T aa ) ) {
    
    printf( "[WIN32] VirtualQueryEx: %p, %x\n", h, x );

    SetLastError( ERROR_ACCESS_DENIED );
    return NULL;
}

win32hook( HANDLE __stdcall, OpenProcess, ( DWORD dw, BOOL b, DWORD dwProcessId ) ) {

    DWORD buffSize = 1024;
    CHAR buffer[ 1024 ];

    HANDLE h = _hOpenProcess(
        PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE |    // limited handle, don't allow VM
        PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD |
        PROCESS_DUP_HANDLE | SYNCHRONIZE, b, dwProcessId );
    
    if( h == INVALID_HANDLE_VALUE )
        return INVALID_HANDLE_VALUE;

    if( dw & PROCESS_VM_OPERATION || dw & PROCESS_VM_READ || dw & PROCESS_VM_WRITE )
    {
        printf( "[WIN32] OpenProcess: %d, %p, returning limited handle\n", dwProcessId, h );
        printf( "   -> security with VM W/R rights\n\n", buffer );
    }
    

   

    DWORD s = GetProcessImageFileNameA( h, buffer, buffSize );
    if( dwProcessId == GetCurrentProcessId( ) || !strstr( buffer, "csgo.exe" ) || !strstr( buffer, "steam" ) )
        return h;



    printf( "   -> prevented access to %s\n\n", buffer );
    CloseHandle( h );

    SetLastError( ERROR_ACCESS_DENIED );
    return NULL;
}


win32hook( BOOL __stdcall, ReadProcessMemory, ( HANDLE h, LPCVOID lpBase, LPVOID lp, SIZE_T nSize, SIZE_T* lpNumber ) ) {
    
    printf( "[WIN32] ReadProcessMemory: %p, %p, %d\n", h, lpBase, nSize );
    if( h != GetCurrentProcess( ) )
    {
        printf( "   -> prevented memory read to %x\n\n", h );
        SetLastError( ERROR_ACCESS_DENIED );
        return FALSE;
    }
    return _hReadProcessMemory( h, lpBase, lp, nSize, lpNumber );
}


win32hook( HANDLE __stdcall, CreateFileW, ( LPCWSTR lpfile, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
           DWORD dwCreationDisposition,
           DWORD dwFlagsAndAttributes,
           HANDLE hTemplateFile ) ) {


    
    //printf( "[WIN32] CreateFileW: %ls\n", ( lpfile ) );

    if( !wcsstr( lpfile, L"C:\\User\\" ) )
        return _hCreateFileW( lpfile, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );


    printf( "[WIN32] CreateFileW -> prevented access to %ls\n", ( lpfile ) );
    SetLastError( STATUS_SHARING_VIOLATION );
    return 0;
}

Hooks HookTable[ ] = {

    {"55 8B EC 81 EC ? ? ? ? 53 56 57 6A 00 68 ? ? ? ?", 0, &vac_system_code_integrity, ( LPVOID* )&_vac_system_code_integrity },
    {"55 8B EC 83 EC 3C 56", 0, &vac_init_section, ( LPVOID* )&_vac_init_section },
    {"57 8B 7D 0C 85 FF 75 1C", 0x5, &vac_read_proc, ( LPVOID* )&_vac_read_proc },

    {"55 8B EC 83 EC 3C 53 56 8B 75 0C", 0, &vac_monitor_manager, ( LPVOID* )&_vac_monitor_manager },

    {"55 8B EC B8 ? ? ? ? E8 ? ? ? ? 53 56 57 8D 45 E4", 0, &vac_enum_proc, ( LPVOID* )&_vac_enum_proc },
    {"8B F0 85 F6 74 18 6A 00", -0x17, &vac_is_pid_alive, ( LPVOID* )&_vac_is_pid_alive },
    {"55 8B EC 8B 45 08 FF 75 0C", 0, &vac_resolve_steam_export, ( LPVOID* )&_vac_resolve_steam_export },
    
};

WinHooks Win32Table[ ] = {

    {"OpenProcess", "kernel32.dll", &hOpenProcess, ( LPVOID* )&_hOpenProcess},
    {"OutputDebugStringA", "kernel32.dll", &hOutputDebugStringA, ( LPVOID* )&_hOutputDebugStringA},
    {"GetForegroundWindow", "user32.dll", &hGetForegroundWindow, ( LPVOID* )&_hGetForegroundWindow},
    {"ReadProcessMemory", "kernel32.dll", &hReadProcessMemory, ( LPVOID* )&_hReadProcessMemory},
    {"VirtualQueryEx", "kernel32.dll", &hVirtualQueryEx, ( LPVOID* )&_hVirtualQueryEx},
    {"CreateFileW", "kernel32.dll", &hCreateFileW, ( LPVOID* )&_hCreateFileW},

};



VOID MainThread( ) {

    LPVOID lpAdd;

    AllocConsole( );
    freopen( "CONOUT$", "w", stdout );
    SetConsoleTitleA( "PreventVAC" );

    if( MH_Initialize( ) != MH_OK )
    {
        MessageBoxA( 0, "Something went wrong while initializating minhook.", "Error", 0 );
        ExitProcess( -1 );
    }


    for( int i = 0; i < sizeof( HookTable ) / sizeof( Hooks ); i++ )
    {

        LPVOID T = service::sigscan( HookTable[ i ].signature, HookTable[ i ].offset );

        if( MH_CreateHook( T, HookTable[ i ].lp, HookTable[ i ].orig ) != MH_OK )
        {
            printf( "[+] hook index: %d, failed! %s + 0x%X\n", i, HookTable[ i ].signature, HookTable[ i ].offset );
            ExitProcess( -1 );
        }
        printf( "[+] %s + 0x%X (%p) - %p, %p\n", HookTable[ i ].signature, HookTable[ i ].offset, T,
                HookTable[ i ].lp, HookTable[ i ].orig );

    }


    for( int i = 0; i < sizeof( Win32Table ) / sizeof( WinHooks ); i++ )
    {
        LPVOID T = GetProcAddress( GetModuleHandleA( Win32Table[ i ].mod ), Win32Table[ i ].win32 );

        if( !T || MH_CreateHook( T, Win32Table[ i ].lp, Win32Table[ i ].orig ) != MH_OK )
        {
            printf( "[+] win32 hook index: %d, failed! %s %s\n", i, Win32Table[ i ].mod, Win32Table[ i ].win32 );
            ExitProcess( -1 );
        }
        printf( "[+] %s / %s (%p) - %p, %p\n", Win32Table[ i ].mod, Win32Table[ i ].win32, T,
                Win32Table[ i ].lp, Win32Table[ i ].orig );
    }


    lpAdd = service::sigscan( "FF 52 1C 5F 83 7E 0C 00", -12 );
    service::patch( lpAdd, 12 );
    printf( "[+] patched runfunc call ( 1 )%p\n", lpAdd );

    lpAdd = service::sigscan( "FF 52 1C E9 ? ? ? ? 8B 46 14", -12 );
    service::patch( lpAdd, 12 );
    printf( "[+] patched runfunc call ( 2 )%p\n", lpAdd );

    lpAdd = ( UINT* )service::sigscan( "C7 46 ? ? ? ? ? 5E B0 01", -12 );
    service::patch( lpAdd, 12 );
    printf( "[+] patched runfunc call ( 3 )%p\n\n\n", lpAdd );


    if( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK )
    {
        MessageBoxA( 0, "Something went wrong while enabling the hook!", "Error", 0 );
        ExitProcess( -1 );
    }
    
    Sleep( INFINITE );
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved ) {

    if( fdwReason == 1 )
    {

        CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )MainThread, 0, 0, 0 );


    }

    return 1;
}
