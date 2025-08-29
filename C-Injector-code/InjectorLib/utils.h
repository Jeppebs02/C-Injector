// utils.h
#pragma once
#include <windows.h>

BOOL XorCStringToBuffer(const char* src, char* dst, size_t dstSize, const unsigned char* key, size_t keyLen);

BOOL XorWStringToBuffer(const wchar_t* src, wchar_t* dst, size_t dstSize, const unsigned char* key, size_t keyLen);