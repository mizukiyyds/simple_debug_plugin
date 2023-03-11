#include <windows.h>
#include <iostream>
#include <cstdio>

int main()
{
	//��ȡLoadLibraryA��ַ������д���ļ�address.txt
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