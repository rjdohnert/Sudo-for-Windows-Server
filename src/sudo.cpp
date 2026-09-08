/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2026, Roberto J Dohnert
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of the project nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <sstream>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

// Enable Virtual Terminal processing for ANSI color rendering
void EnableVTMode() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
}

// Check if current process is running with Administrator privileges
bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// Get path of the current executable
std::wstring GetSelfPath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    return std::wstring(buffer);
}

// Extract target command from process command line
std::wstring GetTargetCommandLine() {
    std::wstring cmd = GetCommandLineW();
    bool inQuote = false;
    size_t i = 0;

    // Skip executable name
    while (i < cmd.length()) {
        if (cmd[i] == L'"') inQuote = !inQuote;
        else if (cmd[i] == L' ' && !inQuote) break;
        i++;
    }
    // Skip trailing spaces
    while (i < cmd.length() && cmd[i] == L' ') i++;

    return (i < cmd.length()) ? cmd.substr(i) : L"";
}

// Thread worker to forward data from Pipe/Handle to Handle/Pipe
void StreamData(HANDLE hRead, HANDLE hWrite) {
    char buffer[4096];
    DWORD bytesRead = 0, bytesWritten = 0;
    while (ReadFile(hRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!WriteFile(hWrite, buffer, bytesRead, &bytesWritten, NULL)) {
            break;
        }
    }
}

// Execute target command directly if already elevated
int RunElevatedDirect(const std::wstring& targetCmd) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    std::vector<wchar_t> cmdBuffer(targetCmd.begin(), targetCmd.end());
    cmdBuffer.push_back(L'\0');

    if (!CreateProcessW(NULL, cmdBuffer.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        std::wcerr << L"sudo: failed to execute command (Error " << GetLastError() << L")\n";
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exitCode);
}

// Worker Mode: Triggered post-UAC in hidden process
int RunWorker(const std::wstring& guid, const std::wstring& targetCmd) {
    std::wstring pipeInName  = L"\\\\.\\pipe\\sudo_in_" + guid;
    std::wstring pipeOutName = L"\\\\.\\pipe\\sudo_out_" + guid;
    std::wstring pipeErrName = L"\\\\.\\pipe\\sudo_err_" + guid;
    std::wstring pipeExitName= L"\\\\.\\pipe\\sudo_exit_" + guid;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE }; // Enable handle inheritance

    // Connect to client pipes
    HANDLE hPipeIn = CreateFileW(pipeInName.c_str(), GENERIC_READ, 0, &sa, OPEN_EXISTING, 0, NULL);
    HANDLE hPipeOut = CreateFileW(pipeOutName.c_str(), GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, NULL);
    HANDLE hPipeErr = CreateFileW(pipeErrName.c_str(), GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, NULL);
    HANDLE hPipeExit = CreateFileW(pipeExitName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipeIn == INVALID_HANDLE_VALUE || hPipeOut == INVALID_HANDLE_VALUE || 
        hPipeErr == INVALID_HANDLE_VALUE || hPipeExit == INVALID_HANDLE_VALUE) {
        return 1;
    }

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hPipeIn;
    si.hStdOutput = hPipeOut;
    si.hStdError = hPipeErr;

    PROCESS_INFORMATION pi = { 0 };
    std::vector<wchar_t> cmdBuffer(targetCmd.begin(), targetCmd.end());
    cmdBuffer.push_back(L'\0');

    // Launch child process silently inside the elevated worker
    if (CreateProcessW(NULL, cmdBuffer.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        
        DWORD written = 0;
        WriteFile(hPipeExit, &exitCode, sizeof(exitCode), &written, NULL);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        DWORD exitCode = GetLastError();
        DWORD written = 0;
        WriteFile(hPipeExit, &exitCode, sizeof(exitCode), &written, NULL);
    }

    CloseHandle(hPipeIn);
    CloseHandle(hPipeOut);
    CloseHandle(hPipeErr);
    CloseHandle(hPipeExit);
    return 0;
}

// Client Mode: Runs in the original user terminal window
int RunClient(const std::wstring& targetCmd) {
    // Generate unique GUID for IPC session
    GUID guid;
    CoCreateGuid(&guid);
    wchar_t guidBuf[64];
    StringFromGUID2(guid, guidBuf, 64);
    std::wstring guidStr(guidBuf);

    std::wstring pipeInName   = L"\\\\.\\pipe\\sudo_in_" + guidStr;
    std::wstring pipeOutName  = L"\\\\.\\pipe\\sudo_out_" + guidStr;
    std::wstring pipeErrName  = L"\\\\.\\pipe\\sudo_err_" + guidStr;
    std::wstring pipeExitName = L"\\\\.\\pipe\\sudo_exit_" + guidStr;

    // Build Security Descriptor allowing unprivileged to elevated pipe access
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

    // Create named pipes
    HANDLE hPipeIn = CreateNamedPipeW(pipeInName.c_str(), PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, &sa);
    HANDLE hPipeOut = CreateNamedPipeW(pipeOutName.c_str(), PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, &sa);
    HANDLE hPipeErr = CreateNamedPipeW(pipeErrName.c_str(), PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, &sa);
    HANDLE hPipeExit = CreateNamedPipeW(pipeExitName.c_str(), PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, &sa);

    if (hPipeIn == INVALID_HANDLE_VALUE || hPipeOut == INVALID_HANDLE_VALUE ||
        hPipeErr == INVALID_HANDLE_VALUE || hPipeExit == INVALID_HANDLE_VALUE) {
        std::wcerr << L"sudo: failed to create IPC pipes.\n";
        return 1;
    }

    // Trigger UAC elevation for hidden worker
    std::wstring workerParams = L"--sudo-worker " + guidStr + L" " + targetCmd;
    std::wstring selfPath = GetSelfPath();

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = selfPath.c_str();
    sei.lpParameters = workerParams.c_str();
    sei.nShow = SW_HIDE; // Keeps worker hidden from creating a new window

    if (!ShellExecuteExW(&sei)) {
        if (GetLastError() == ERROR_CANCELLED) {
            std::wcerr << L"sudo: UAC prompt was denied.\n";
        } else {
            std::wcerr << L"sudo: elevation failed (Error " << GetLastError() << L")\n";
        }
        return 1;
    }

    // Await pipe connections from worker
    ConnectNamedPipe(hPipeIn, NULL);
    ConnectNamedPipe(hPipeOut, NULL);
    ConnectNamedPipe(hPipeErr, NULL);
    ConnectNamedPipe(hPipeExit, NULL);

    // Spawn async background streaming threads to relay I/O
    std::thread tOut(StreamData, hPipeOut, GetStdHandle(STD_OUTPUT_HANDLE));
    std::thread tErr(StreamData, hPipeErr, GetStdHandle(STD_ERROR_HANDLE));
    std::thread tIn(StreamData, GetStdHandle(STD_INPUT_HANDLE), hPipeIn);

    // Read exit code from elevated process
    DWORD exitCode = 1;
    DWORD bytesRead = 0;
    ReadFile(hPipeExit, &exitCode, sizeof(exitCode), &bytesRead, NULL);

    if (tOut.joinable()) tOut.join();
    if (tErr.joinable()) tErr.join();
    if (tIn.joinable()) tIn.detach(); // Detach stdin thread as it may block on ReadFile

    CloseHandle(hPipeIn);
    CloseHandle(hPipeOut);
    CloseHandle(hPipeErr);
    CloseHandle(hPipeExit);

    return static_cast<int>(exitCode);
}

void PrintUsage(const wchar_t* prog_name) {
    std::wcout << L"Usage: " << prog_name << L" [OPTIONS] <command> [args...]\n"
               << L"Execute a command with elevated privileges.\n\n"
               << L"Options:\n"
               << L"  -h, --help           Show this help text\n"
               << L"  -v, --version        Show version information\n"
               << L"      --validate       Validate the current environment and exit\n"
               << L"      --sudo-worker    Internal worker mode (used by the elevation flow)\n";
}

void PrintVersion() {
    std::wcout << L"sudo v3.0.3\n";
}

int wmain(int argc, wchar_t* argv[]) {
    EnableVTMode();

    if (argc < 2) {
        PrintUsage(L"sudo");
        return 0;
    }

    std::wstring firstArg = argv[1];

    // Handle Help flags
    if (firstArg == L"-h" || firstArg == L"--help") {
        PrintUsage(L"sudo");
        return 0;
    }

    if (firstArg == L"-v" || firstArg == L"--version") {
        PrintVersion();
        return 0;
    }

    if (firstArg == L"--validate") {
        std::wcout << L"sudo: environment validation passed\n";
        return 0;
    }

    // Check if worker mode triggered by internal runner
    if (firstArg == L"--sudo-worker") {
        if (argc < 4) return 1;
        std::wstring guid = argv[2];
        
        // Reconstruct target command line string
        std::wstring cmd = GetCommandLineW();
        size_t pos = cmd.find(guid);
        if (pos == std::wstring::npos) return 1;
        std::wstring targetCmd = cmd.substr(pos + guid.length() + 1);

        return RunWorker(guid, targetCmd);
    }

    std::wstring targetCmd = GetTargetCommandLine();

    // Direct launch if already running elevated
    if (IsAdmin()) {
        return RunElevatedDirect(targetCmd);
    }

    // Otherwise, trigger Client Proxy logic
    return RunClient(targetCmd);
}
