// utils.c
#include <windows.h>
#include <stdint.h>

BOOL XorCStringToBuffer(IN const char* src, OUT char* dst, IN size_t dstSize, IN const unsigned char* key, IN size_t keyLen){
    
    if (!src || !dst || !key || keyLen == 0) {

        return FALSE;
    }

    const size_t len = strlen(src);
    if (dstSize < len + 1) {   // +1 for the NUL terminator
        return FALSE;
    }

    // XOR into dst, keep src intact
    for (size_t i = 0, j = 0; i < len; ++i, j = (j + 1) % keyLen) {
        // cast to unsigned to avoid sign-extension errors when char is signed
        dst[i] = (char)(((unsigned char)src[i]) ^ key[j]);
    }
    dst[len] = '\0';
    return TRUE;
}




BOOL XorWStringToBuffer(IN const wchar_t* src, OUT wchar_t* dst, IN size_t dstSize, IN const unsigned char* key, IN size_t keyLen){

    if (!src || !dst || !key || keyLen == 0){
        
        return FALSE;
    }

    size_t len = wcslen(src);
    if (dstSize < len + 1) {                // +1 for the NUL terminator
        return FALSE;
    }

    for (size_t i = 0, j = 0; i < len; ++i, j = (j + 1) % keyLen)
    {
        dst[i] = (wchar_t)(((uint16_t)src[i]) ^ key[j]);
    }
    dst[len] = L'\0';
    return TRUE;
}