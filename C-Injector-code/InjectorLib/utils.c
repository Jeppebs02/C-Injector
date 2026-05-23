// utils.c
#include <windows.h>
#include <stdint.h>

BOOL XorCStringToBuffer(IN const char* src, IN size_t srcLen, OUT char* dst, IN size_t dstSize, IN const unsigned char* key, IN size_t keyLen) {

	if (!src || !dst || !key || keyLen == 0) {
		return FALSE;
	}

	if (dstSize < srcLen + 1) {
		return FALSE;
	}

	for (size_t i = 0, j = 0; i < srcLen; ++i, j = (j + 1) % keyLen) {
		dst[i] = (char)(((unsigned char)src[i]) ^ key[j]);
	}
	dst[srcLen] = '\0';
	return TRUE;
}

BOOL XorWStringToBuffer(IN const wchar_t* src, IN size_t srcLen, OUT wchar_t* dst, IN size_t dstSize, IN const unsigned char* key, IN size_t keyLen) {

	if (!src || !dst || !key || keyLen == 0) {
		return FALSE;
	}

	if (dstSize < srcLen + 1) {
		return FALSE;
	}

	for (size_t i = 0, j = 0; i < srcLen; ++i, j = (j + 1) % keyLen) {
		dst[i] = (wchar_t)(((uint16_t)src[i]) ^ key[j]);
	}
	dst[srcLen] = L'\0';
	return TRUE;
}
