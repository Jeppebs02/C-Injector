// utils.h
#pragma once
#include <windows.h>

BOOL XorCStringToBuffer(const char* src, size_t srcLen, char* dst, size_t dstSize, const unsigned char* key, size_t keyLen);

BOOL XorWStringToBuffer(const wchar_t* src, size_t srcLen, wchar_t* dst, size_t dstSize, const unsigned char* key, size_t keyLen);