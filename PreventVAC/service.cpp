#include "preventvac.hpp"

uint8_t* service::sigscan( const char* signature, int offset ) {

	static auto pattern_to_byte = [ ]( const char* pattern ) {
		auto bytes = std::vector<int>{};
		auto start = const_cast< char* >( pattern );
		auto end = const_cast< char* >( pattern ) + strlen( pattern );

		for( auto current = start; current < end; ++current )
		{
			if( *current == '?' )
			{
				++current;
				if( *current == '?' )
					++current;
				bytes.push_back( -1 );
			} else
			{
				bytes.push_back( strtoul( current, &current, 16 ) );
			}
		}
		return bytes;
	};

	auto dosHeader = ( PIMAGE_DOS_HEADER )GetModuleHandleA( "steamservice.dll" );
	auto ntHeaders = ( PIMAGE_NT_HEADERS )( ( uint8_t* )dosHeader + dosHeader->e_lfanew );

	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = pattern_to_byte( signature );
	auto scanBytes = reinterpret_cast< uint8_t* >( dosHeader );

	auto s = patternBytes.size( );
	auto d = patternBytes.data( );

	for( auto i = 0ul; i < sizeOfImage - s; ++i )
	{
		bool found = true;
		for( auto j = 0ul; j < s; ++j )
		{
			if( scanBytes[ i + j ] != d[ j ] && d[ j ] != -1 )
			{
				found = false;
				break;
			}
		}
		if( found )
		{
			return &scanBytes[ i ] + offset;
		}
	}
	return nullptr;

}

void service::patch( LPVOID address, SIZE_T size ) {

	DWORD oldProt;

	VirtualProtect( address, size, PAGE_READWRITE, &oldProt );
	for( int i = 0; i < size; i++ )
		*( UCHAR* )( ( UCHAR* )address + i ) = 0x90;

	VirtualProtect( address, size, oldProt, &oldProt );

}