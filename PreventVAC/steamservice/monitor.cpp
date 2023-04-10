#include "../preventvac.hpp"

defhook( void __cdecl, vac_monitor_manager, ( int a1, int a2, int a3, void( __cdecl*** a4 )( DWORD, const char*, const char* ) ) ) {

    printf( "\n[+] vac_monitor_manager: 0x%X, 0x%X, 0x%X, %p\n\n", a1, a2, a3, a4 );

    //
    //  Skip process monitor registration
    //
    /*a2 = 0;
    _vac_monitor_manager( a1, a2, a3, a4 );*/

}

defhook( FARPROC __cdecl, vac_resolve_steam_export, ( LPCSTR lpModuleName, LPCSTR lpProcName ) ) {
    printf( "\n[+] vac_resolve_steam_export: %s, %s\n\n", lpModuleName, lpProcName );
    if( !strcmp( lpProcName, "_runfunc@20" ) )
        return nullptr;

    return _vac_resolve_steam_export( lpModuleName, lpProcName );
}
