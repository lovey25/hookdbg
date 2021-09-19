#include "windows.h"
#include "stdio.h"
#include <Psapi.h>
#include <tchar.h>

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
    // WriteFile() API 주소 구하기
    g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");

    // API Hook - WriteFile()
    //   첫 번째 byte 를 0xCC (INT 3) 으로 변경 
    //   (orginal byte 는 백업)
    memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
    ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
        &g_chOrgByte, sizeof(BYTE), NULL);
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
        &g_chINT3, sizeof(BYTE), NULL);

    return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
    CONTEXT ctx;
    PBYTE lpBuffer = NULL;
    DWORD64 dwNumOfBytesToWrite, dwAddrOfBuffer, i;
    PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

    // BreakPoint exception (INT 3) 인 경우
    if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
    {
        // BP 주소가 WriteFile() 인 경우
        if (g_pfWriteFile == per->ExceptionAddress)
        {
            // #1. Unhook
            //   0xCC 로 덮어쓴 부분을 original byte 로 되돌림
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                &g_chOrgByte, sizeof(BYTE), NULL);

            // #2. Thread Context 구하기
            ctx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(g_cpdi.hThread, &ctx);

            // #3. WriteFile() 의 param 2, 3 값 구하기
            //   함수의 파라미터는 해당 프로세스의 스택에 존재함
            //   param 2 : Rdx
            //   param 3 : R8
            dwAddrOfBuffer = ctx.Rdx;
            dwNumOfBytesToWrite = ctx.R8;

            // #4. 임시 버퍼 할당
            lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);
            memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);

            // #5. WriteFile() 의 버퍼를 임시 버퍼에 복사
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(dwAddrOfBuffer),
                lpBuffer, dwNumOfBytesToWrite, NULL);
            printf("\n### original string ###\n%s\n", lpBuffer);

            // #6. 소문자 -> 대문자 변환
            for (i = 0; i < dwNumOfBytesToWrite; i++)
            {
                if (0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A)
                    lpBuffer[i] -= 0x20;
            }

            printf("\n### converted string ###\n%s\n", lpBuffer);

            // #7. 변환된 버퍼를 WriteFile() 버퍼로 복사
            WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
               lpBuffer, dwNumOfBytesToWrite, NULL);

            // #8. 임시 버퍼 해제
            free(lpBuffer);

            // #9. Thread Context 의 RIP 를 WriteFile() 시작으로 변경
            //   (현재는 WriteFile() + 1 만큼 지나왔음)
            ctx.Rip = (DWORD64)g_pfWriteFile;
            SetThreadContext(g_cpdi.hThread, &ctx);

            // #10. Debuggee 프로세스를 진행시킴
            ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
            Sleep(0);

            // #11. API Hook
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                &g_chINT3, sizeof(BYTE), NULL);

            return TRUE;
        }
    }

    return FALSE;
}

void DebugLoop()
{
    DEBUG_EVENT de;
    DWORD dwContinueStatus;

    // Debuggee 로부터 event 가 발생할 때까지 기다림
    while (WaitForDebugEvent(&de, INFINITE))
    {
        dwContinueStatus = DBG_CONTINUE;

        // Debuggee 프로세스 생성 혹은 attach 이벤트
        if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
        {
            OnCreateProcessDebugEvent(&de);
        }
        // 예외 이벤트
        else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)
        {
            if (OnExceptionDebugEvent(&de))
                continue;
        }
        // Debuggee 프로세스 종료 이벤트
        else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
        {
            // debuggee 종료 -> debugger 종료
            break;
        }

        // Debuggee 의 실행을 재개시킴
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
    }
}

DWORD GetProcessByFileName(LPWSTR name)
{
    DWORD process_id_array[1024];
    DWORD bytes_returned;
    DWORD num_processes;
    HANDLE hProcess;
    WCHAR image_name[MAX_PATH] = { 0, };

    DWORD i;
    EnumProcesses(process_id_array, 1024 * sizeof(DWORD), &bytes_returned);
    num_processes = (bytes_returned / sizeof(DWORD));
    for (i = 0; i < num_processes; i++) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, process_id_array[i]);
        if (GetModuleBaseName(hProcess, 0, image_name, 256)) {
            if (!wcscmp(image_name, name)) {
                CloseHandle(hProcess);
                return process_id_array[i];
            }
        }
        CloseHandle(hProcess);
    }
    return 0;
}

int main(int argc, char* argv[])
{
    DWORD dwPID;

    // Attach Process
    if (argc != 2)
    {
        WCHAR pname[] =_T( "Notepad.exe");
        dwPID = GetProcessByFileName(pname);
    }
    else
    {
        dwPID = atoi(argv[1]);
    }
    
    if (!DebugActiveProcess(dwPID))
    {
        printf("DebugActiveProcess(%d) failed!!!\n"
            "Error Code = %d\n", dwPID, GetLastError());
        return 1;
    }

    // 디버거 루프
    DebugLoop();

    return 0;
}
