#pragma once
#include <Windows.h>
#include <stdio.h>
#include <vector>

#define win32hook(x, xx, xxx) \
typedef x def_ ## xx ## xxx; \
def_ ## xx ##* _h ## xx ## = 0; \
x h ## xx ## xxx

#define exphook(x, xx, xxx) \
typedef x def_ ## xx ## xxx;\
extern def_ ## xx ##* _ ## xx ##; \
extern x xx xxx;

#define defhook(x, xx, xxx) \
def_ ## xx ##* _ ## xx ## = 0; \
x xx xxx

namespace service
{
	uint8_t* sigscan( const char* signature, int offset );
	void patch( LPVOID address, SIZE_T size );
}

struct Hooks
{
	const char* signature;
	int offset;
	LPVOID lp;
	LPVOID* orig;
};

struct WinHooks
{
	const char* win32;
	const char* mod;
	LPVOID lp;
	LPVOID* orig;
};


// system.cpp
exphook( DWORD __stdcall, vac_system_code_integrity, ( HANDLE TargetHandle, int a2, int a3 ) )
exphook( DWORD*, vac_init_section, ( void* structure ) )

// processes.cpp
exphook( bool __cdecl, vac_read_proc, ( DWORD proc, int a2, int a3 ) )
exphook( char __cdecl, vac_enum_proc, ( DWORD* addy ) )
exphook( bool __cdecl, vac_is_pid_alive, ( DWORD dwProcessId ) )

// monitor.cpp
exphook( void __cdecl, vac_monitor_manager, ( int a1, int a2, int a3, void( __cdecl*** a4 )( DWORD, const char*, const char* ) ) )
exphook( FARPROC __cdecl, vac_resolve_steam_export, ( LPCSTR lpModuleName, LPCSTR lpProcName ) )