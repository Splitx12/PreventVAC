#include "../preventvac.hpp"

defhook( DWORD __stdcall, vac_system_code_integrity, ( HANDLE TargetHandle, int a2, int a3 ) ) {


    printf( "\n[+] vac_system_code_integrity: %p, %d, %d\n", TargetHandle, a2, a3 );
    if( TargetHandle != GetCurrentProcess( ) )
    {
        printf( "   -> prevented access to handle %p\n\n", GetCurrentProcess( ) );
        return 0;
    }

    return _vac_system_code_integrity( TargetHandle, a2, a3 );

}

defhook( DWORD*, vac_init_section, ( void* structure ) ) {

    printf( "\n[+] init_vac_section: %p\n\n", structure );
    return nullptr;

}