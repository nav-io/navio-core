#pragma once
/**
	@file
	@brief link gmp/gmpxx (was mpir/mpirxx via cybozulib_ext)
	@author MITSUNARI Shigeo(@herumi)
*/
#if defined(_WIN32) && defined(_MT)
	#pragma comment(lib, "gmpxx.lib")
	#pragma comment(lib, "gmp.lib")
#endif
