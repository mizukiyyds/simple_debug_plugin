#include <windows.h>
#include <iostream>
#include <cstdio>

int main()
{
	//获取LoadLibraryA地址并将其写入文件address.txt
	FILE* fp;
	errno_t err; 
	err = fopen_s(&fp, "address.txt", "wb");
	if (err != 0)
	{
		return -1;
	}
	HMODULE hModule = GetModuleHandleA("kernel32.dll");
	if (hModule == NULL)
	{
		return -1;
	}
	FARPROC pFunc = GetProcAddress(hModule, "LoadLibraryA");
	if (pFunc == NULL)
	{
		return -1;
	}
	fprintf_s(fp, "%p", pFunc);
	fclose(fp);
	return 0;




}