#include "../preventvac.hpp"

defhook( bool __cdecl, vac_read_proc, ( DWORD proc, int a2, int a3 ) ) {

    printf( "\n[+] vac_read_proc: %d, %d, %d\n\n", proc, a2, a3 );
    return 0;

}

defhook( char __cdecl, vac_enum_proc, ( DWORD* addy ) ) {

    printf( "\n[+] vac_enum_proc: %p\n\n", addy );
    if( addy == nullptr )
        return 0;

    char s = _vac_enum_proc( addy );
    memset( addy, 0, 1024 );
    return s;
}

defhook( bool __cdecl, vac_is_pid_alive, ( DWORD dwProcessId ) ) {

    printf( "\n[+] vac_is_pid_alive: %d\n", dwProcessId );
    if( dwProcessId != GetCurrentProcessId( ) )
    {
        printf( "   -> prevented access to handle %p\n\n", GetCurrentProcess( ) );
        return 0;
    }
    return _vac_is_pid_alive( dwProcessId );
}