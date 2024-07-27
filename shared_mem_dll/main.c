#include <windows.h>
#include <stdio.h>

HANDLE hMapFile;
char* pBuf;

__declspec(dllexport) void initSharedMem()
{
    hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1000000, TEXT("Local\\XidiControllers"));
    pBuf = MapViewOfFile(hMapFile, FILE_MAP_WRITE, 0, 0, 1000000);
}

__declspec(dllexport) int writeSharedMemXidi(const char *str)
{
    if(pBuf != NULL) snprintf(pBuf, strlen(str) + 1, str);
    return 0;
}
