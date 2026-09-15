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
#include <sddl.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <sstream>
#include <cwchar>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")

constexpr DWORD PIPE_CONNECT_TIMEOUT_MS = 15000;

void CloseHandleIfValid(HANDLE handle) {
    if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
}

bool BuildPipeSecurity(SECURITY_ATTRIBUTES& attributes, PSECURITY_DESCRIPTOR& descriptor) {
    descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)",
            SDDL_REVISION_1, &descriptor, NULL)) {
        return false;
    }

    attributes = { sizeof(attributes), descriptor, FALSE };
    return true;
}

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
    std::vector<wchar_t> buffer(MAX_PATH);
    while (buffer.size() <= 32768) {
        DWORD length = GetModuleFileNameW(NULL, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return L"";
        }
        if (length < buffer.size()) {
            return std::wstring(buffer.data(), length);
        }
        buffer.resize(buffer.size() * 2);
    }
    return L"";
}

std::wstring QuoteCommandLineArgument(const std::wstring& argument) {
    if (argument.empty()) {
        return L"\"\"";
    }

    std::wstring quoted = L"\"";
    size_t backslashes = 0;
    for (wchar_t character : argument) {
        if (character == L'\\') {
            backslashes++;
        } else if (character == L'\"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(character);
            backslashes = 0;
        } else {
            quoted.append(backslashes, L'\\');
            backslashes = 0;
            quoted.push_back(character);
        }
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'\"');
    return quoted;
}

std::wstring GetMachinePath() {
    const wchar_t* key = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    DWORD required = 0;
    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, key, L"Path",
                                  RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                                  NULL, NULL, &required);
    if (status != ERROR_SUCCESS || required == 0) {
        return L"";
    }

    std::vector<wchar_t> buffer(required / sizeof(wchar_t));
    status = RegGetValueW(HKEY_LOCAL_MACHINE, key, L"Path",
                          RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                          NULL, buffer.data(), &required);
    return status == ERROR_SUCCESS ? std::wstring(buffer.data()) : L"";
}

std::wstring GetCurrentDirectoryPath() {
    DWORD required = GetCurrentDirectoryW(0, NULL);
    if (required == 0) {
        return L"";
    }

    std::vector<wchar_t> buffer(required);
    DWORD length = GetCurrentDirectoryW(required, buffer.data());
    return (length > 0 && length < required) ? std::wstring(buffer.data(), length) : L"";
}

void AddTrustedDirectory(std::vector<std::wstring>& directories, const std::wstring& directory,
                         const std::wstring& currentDirectory) {
    if (directory.empty()) {
        return;
    }

    std::wstring candidate = directory;
    if (candidate.size() >= 2 && candidate.front() == L'\"' && candidate.back() == L'\"') {
        candidate = candidate.substr(1, candidate.size() - 2);
    }
    if (candidate.empty() || (candidate.size() < 2 || candidate[1] != L':') &&
        !(candidate.size() >= 2 && candidate[0] == L'\\' && candidate[1] == L'\\')) {
        return;
    }
    while (candidate.size() > 3 && (candidate.back() == L'\\' || candidate.back() == L'/')) {
        candidate.pop_back();
    }
    if (!currentDirectory.empty() && _wcsicmp(candidate.c_str(), currentDirectory.c_str()) == 0) {
        return;
    }
    for (const std::wstring& existing : directories) {
        if (_wcsicmp(existing.c_str(), candidate.c_str()) == 0) {
            return;
        }
    }
    directories.push_back(candidate);
}

bool ResolveTargetCommand(const std::wstring& targetCommand, std::wstring& resolvedCommand) {
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(targetCommand.c_str(), &argumentCount);
    if (arguments == NULL || argumentCount == 0) {
        if (arguments != NULL) LocalFree(arguments);
        return false;
    }

    std::wstring executable = arguments[0];
    bool explicitPath = executable.find_first_of(L"\\/") != std::wstring::npos ||
                        (executable.size() >= 2 && executable[1] == L':');
    std::wstring resolvedExecutable;

    if (explicitPath) {
        DWORD required = GetFullPathNameW(executable.c_str(), 0, NULL, NULL);
        if (required != 0) {
            std::vector<wchar_t> buffer(required);
            DWORD length = GetFullPathNameW(executable.c_str(), required, buffer.data(), NULL);
            if (length > 0 && length < required && GetFileAttributesW(buffer.data()) != INVALID_FILE_ATTRIBUTES) {
                resolvedExecutable.assign(buffer.data(), length);
            }
        }
    } else {
        std::vector<std::wstring> directories;
        std::vector<wchar_t> systemDirectory(32768);
        UINT systemLength = GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size()));
        std::wstring currentDirectory = GetCurrentDirectoryPath();
        if (systemLength > 0 && systemLength < systemDirectory.size()) {
            AddTrustedDirectory(directories, std::wstring(systemDirectory.data(), systemLength), L"");
        }

        std::vector<wchar_t> windowsDirectory(32768);
        UINT windowsLength = GetWindowsDirectoryW(windowsDirectory.data(), static_cast<UINT>(windowsDirectory.size()));
        if (windowsLength > 0 && windowsLength < windowsDirectory.size()) {
            AddTrustedDirectory(directories, std::wstring(windowsDirectory.data(), windowsLength), L"");
        }

        std::wstring path = GetMachinePath();
        size_t start = 0;
        while (start <= path.size()) {
            size_t end = path.find(L';', start);
            AddTrustedDirectory(directories, path.substr(start, end - start), currentDirectory);
            if (end == std::wstring::npos) break;
            start = end + 1;
        }

        std::wstring trustedPath;
        for (const std::wstring& directory : directories) {
            if (!trustedPath.empty()) trustedPath.push_back(L';');
            trustedPath += directory;
        }

        const wchar_t* extension = executable.find(L'.') == std::wstring::npos ? L".exe" : NULL;
        DWORD required = SearchPathW(trustedPath.c_str(), executable.c_str(), extension, 0, NULL, NULL);
        if (required != 0) {
            std::vector<wchar_t> buffer(required + 1);
            DWORD length = SearchPathW(trustedPath.c_str(), executable.c_str(), extension,
                                       static_cast<DWORD>(buffer.size()), buffer.data(), NULL);
            if (length > 0 && length < buffer.size()) {
                resolvedExecutable.assign(buffer.data(), length);
            }
        }
    }

    if (resolvedExecutable.empty()) {
        LocalFree(arguments);
        return false;
    }

    resolvedCommand = QuoteCommandLineArgument(resolvedExecutable);
    for (int index = 1; index < argumentCount; index++) {
        resolvedCommand.push_back(L' ');
        resolvedCommand += QuoteCommandLineArgument(arguments[index]);
    }
    LocalFree(arguments);
    return true;
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

bool WriteExitCode(HANDLE pipe, DWORD exitCode) {
    DWORD written = 0;
    return WriteFile(pipe, &exitCode, sizeof(exitCode), &written, NULL) && written == sizeof(exitCode);
}

// Worker Mode: Triggered post-UAC in hidden process
int RunWorker(const std::wstring& guid, DWORD clientProcessId, bool consoleMode,
              const std::wstring& targetCmd) {
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
        CloseHandleIfValid(hPipeIn);
        CloseHandleIfValid(hPipeOut);
        CloseHandleIfValid(hPipeErr);
        CloseHandleIfValid(hPipeExit);
        return 1;
    }

    HANDLE hClientProcess = OpenProcess(SYNCHRONIZE, FALSE, clientProcessId);
    if (hClientProcess == NULL) {
        WriteExitCode(hPipeExit, ERROR_INVALID_HANDLE);
        CloseHandle(hPipeIn);
        CloseHandle(hPipeOut);
        CloseHandle(hPipeErr);
        CloseHandle(hPipeExit);
        return 1;
    }

    HANDLE hChildIn = hPipeIn;
    HANDLE hChildOut = hPipeOut;
    HANDLE hChildErr = hPipeErr;
    if (consoleMode) {
        FreeConsole();
        if (!AttachConsole(clientProcessId)) {
            WriteExitCode(hPipeExit, GetLastError());
            CloseHandle(hClientProcess);
            CloseHandle(hPipeIn);
            CloseHandle(hPipeOut);
            CloseHandle(hPipeErr);
            CloseHandle(hPipeExit);
            return 1;
        }
        hChildIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
        hChildOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
        hChildErr = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
        if (hChildIn == INVALID_HANDLE_VALUE || hChildOut == INVALID_HANDLE_VALUE ||
            hChildErr == INVALID_HANDLE_VALUE) {
            WriteExitCode(hPipeExit, GetLastError());
            CloseHandleIfValid(hChildIn);
            CloseHandleIfValid(hChildOut);
            CloseHandleIfValid(hChildErr);
            CloseHandle(hClientProcess);
            CloseHandle(hPipeIn);
            CloseHandle(hPipeOut);
            CloseHandle(hPipeErr);
            CloseHandle(hPipeExit);
            return 1;
        }
    }

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hChildIn;
    si.hStdOutput = hChildOut;
    si.hStdError = hChildErr;

    PROCESS_INFORMATION pi = { 0 };
    std::vector<wchar_t> cmdBuffer(targetCmd.begin(), targetCmd.end());
    cmdBuffer.push_back(L'\0');

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = {};
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (hJob == NULL || !SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                                  &jobInfo, sizeof(jobInfo))) {
        WriteExitCode(hPipeExit, GetLastError());
    } else {
        DWORD creationFlags = CREATE_SUSPENDED | (consoleMode ? 0 : CREATE_NO_WINDOW);
        if (CreateProcessW(NULL, cmdBuffer.data(), NULL, NULL, TRUE, creationFlags,
                           NULL, NULL, &si, &pi)) {
            if (!AssignProcessToJobObject(hJob, pi.hProcess) || ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
                TerminateProcess(pi.hProcess, ERROR_ACCESS_DENIED);
            }

            HANDLE waitHandles[] = { pi.hProcess, hClientProcess };
            DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
            if (waitResult == WAIT_OBJECT_0 + 1) {
                TerminateJobObject(hJob, ERROR_CANCELLED);
                WaitForSingleObject(pi.hProcess, INFINITE);
            } else if (waitResult != WAIT_OBJECT_0) {
                TerminateJobObject(hJob, GetLastError());
                WaitForSingleObject(pi.hProcess, INFINITE);
            }

            DWORD exitCode = 1;
            if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
                exitCode = GetLastError();
            }
            WriteExitCode(hPipeExit, exitCode);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            WriteExitCode(hPipeExit, GetLastError());
        }
    }

    if (consoleMode) {
        CloseHandleIfValid(hChildIn);
        CloseHandleIfValid(hChildOut);
        CloseHandleIfValid(hChildErr);
    }
    CloseHandleIfValid(hJob);
    CloseHandle(hClientProcess);
    CloseHandle(hPipeIn);
    CloseHandle(hPipeOut);
    CloseHandle(hPipeErr);
    CloseHandle(hPipeExit);
    return 0;
}

bool IsConsoleHandle(HANDLE handle) {
    DWORD mode = 0;
    return handle != INVALID_HANDLE_VALUE && GetConsoleMode(handle, &mode) != FALSE;
}

bool ConnectPipeToWorker(HANDLE pipe, HANDLE workerProcess, DWORD workerProcessId) {
    HANDLE connectionEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (connectionEvent == NULL) {
        return false;
    }

    bool connected = false;
    DWORD connectionError = ERROR_SUCCESS;
    std::thread connectionThread([&]() {
        connected = ConnectNamedPipe(pipe, NULL) != FALSE;
        connectionError = connected ? ERROR_SUCCESS : GetLastError();
        SetEvent(connectionEvent);
    });

    HANDLE waitHandles[] = { connectionEvent, workerProcess };
    DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, PIPE_CONNECT_TIMEOUT_MS);
    if (waitResult != WAIT_OBJECT_0) {
        CancelSynchronousIo(connectionThread.native_handle());
    }
    connectionThread.join();

    CloseHandle(connectionEvent);
    if (!connected && connectionError != ERROR_PIPE_CONNECTED) {
        return false;
    }

    ULONG clientProcessId = 0;
    return GetNamedPipeClientProcessId(pipe, &clientProcessId) != FALSE &&
           clientProcessId == workerProcessId;
}

// Client Mode: Runs in the original user terminal window
int RunClient(const std::wstring& targetCmd) {
    // Generate unique GUID for IPC session
    GUID guid;
    if (FAILED(CoCreateGuid(&guid))) {
        std::wcerr << L"sudo: failed to create IPC session identifier.\n";
        return 1;
    }
    wchar_t guidBuf[64];
    if (StringFromGUID2(guid, guidBuf, 64) == 0) {
        std::wcerr << L"sudo: failed to format IPC session identifier.\n";
        return 1;
    }
    std::wstring guidStr(guidBuf);

    std::wstring pipeInName   = L"\\\\.\\pipe\\sudo_in_" + guidStr;
    std::wstring pipeOutName  = L"\\\\.\\pipe\\sudo_out_" + guidStr;
    std::wstring pipeErrName  = L"\\\\.\\pipe\\sudo_err_" + guidStr;
    std::wstring pipeExitName = L"\\\\.\\pipe\\sudo_exit_" + guidStr;

    SECURITY_ATTRIBUTES sa = {};
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    if (!BuildPipeSecurity(sa, securityDescriptor)) {
        std::wcerr << L"sudo: failed to secure IPC pipes (Error " << GetLastError() << L")\n";
        return 1;
    }

    // Create named pipes
    DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    HANDLE hPipeIn = CreateNamedPipeW(pipeInName.c_str(), PIPE_ACCESS_OUTBOUND, pipeMode, 1, 4096, 4096, 0, &sa);
    HANDLE hPipeOut = CreateNamedPipeW(pipeOutName.c_str(), PIPE_ACCESS_INBOUND, pipeMode, 1, 4096, 4096, 0, &sa);
    HANDLE hPipeErr = CreateNamedPipeW(pipeErrName.c_str(), PIPE_ACCESS_INBOUND, pipeMode, 1, 4096, 4096, 0, &sa);
    HANDLE hPipeExit = CreateNamedPipeW(pipeExitName.c_str(), PIPE_ACCESS_INBOUND, pipeMode, 1, 4096, 4096, 0, &sa);
    LocalFree(securityDescriptor);

    if (hPipeIn == INVALID_HANDLE_VALUE || hPipeOut == INVALID_HANDLE_VALUE ||
        hPipeErr == INVALID_HANDLE_VALUE || hPipeExit == INVALID_HANDLE_VALUE) {
        std::wcerr << L"sudo: failed to create IPC pipes.\n";
        CloseHandleIfValid(hPipeIn);
        CloseHandleIfValid(hPipeOut);
        CloseHandleIfValid(hPipeErr);
        CloseHandleIfValid(hPipeExit);
        return 1;
    }

    // Trigger UAC elevation for hidden worker
    bool consoleMode = IsConsoleHandle(GetStdHandle(STD_INPUT_HANDLE)) &&
                       IsConsoleHandle(GetStdHandle(STD_OUTPUT_HANDLE)) &&
                       IsConsoleHandle(GetStdHandle(STD_ERROR_HANDLE));
    std::wstring workerParams = L"--sudo-worker " + guidStr + L" " +
                                std::to_wstring(GetCurrentProcessId()) + L" " +
                                (consoleMode ? L"1 " : L"0 ") + QuoteCommandLineArgument(targetCmd);
    std::wstring selfPath = GetSelfPath();
    if (selfPath.empty()) {
        std::wcerr << L"sudo: failed to resolve its executable path.\n";
        CloseHandle(hPipeIn);
        CloseHandle(hPipeOut);
        CloseHandle(hPipeErr);
        CloseHandle(hPipeExit);
        return 1;
    }

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
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
        CloseHandle(hPipeIn);
        CloseHandle(hPipeOut);
        CloseHandle(hPipeErr);
        CloseHandle(hPipeExit);
        return 1;
    }

    if (sei.hProcess == NULL) {
        std::wcerr << L"sudo: elevation returned no worker process.\n";
        CloseHandle(hPipeIn);
        CloseHandle(hPipeOut);
        CloseHandle(hPipeErr);
        CloseHandle(hPipeExit);
        return 1;
    }

    DWORD workerProcessId = GetProcessId(sei.hProcess);
    if (workerProcessId == 0 ||
        !ConnectPipeToWorker(hPipeIn, sei.hProcess, workerProcessId) ||
        !ConnectPipeToWorker(hPipeOut, sei.hProcess, workerProcessId) ||
        !ConnectPipeToWorker(hPipeErr, sei.hProcess, workerProcessId) ||
        !ConnectPipeToWorker(hPipeExit, sei.hProcess, workerProcessId)) {
        std::wcerr << L"sudo: elevated worker failed IPC authentication or connection.\n";
        CloseHandle(sei.hProcess);
        CloseHandle(hPipeIn);
        CloseHandle(hPipeOut);
        CloseHandle(hPipeErr);
        CloseHandle(hPipeExit);
        return 1;
    }

    std::thread tOut;
    std::thread tErr;
    std::thread tIn;
    if (!consoleMode) {
        tOut = std::thread(StreamData, hPipeOut, GetStdHandle(STD_OUTPUT_HANDLE));
        tErr = std::thread(StreamData, hPipeErr, GetStdHandle(STD_ERROR_HANDLE));
        tIn = std::thread(StreamData, GetStdHandle(STD_INPUT_HANDLE), hPipeIn);
    }

    // Read exit code from elevated process
    DWORD exitCode = 1;
    DWORD bytesRead = 0;
    if (!ReadFile(hPipeExit, &exitCode, sizeof(exitCode), &bytesRead, NULL) ||
        bytesRead != sizeof(exitCode)) {
        exitCode = 1;
    }

    if (tOut.joinable()) tOut.join();
    if (tErr.joinable()) tErr.join();
    if (tIn.joinable()) {
        CancelSynchronousIo(tIn.native_handle());
        tIn.join();
    }

    CloseHandle(sei.hProcess);
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

int ValidateEnvironment() {
    bool valid = true;
    if (GetSelfPath().empty()) {
        std::wcerr << L"sudo: validation failed: executable path is unavailable\n";
        valid = false;
    }

    std::wstring resolvedCommand;
    if (!ResolveTargetCommand(L"cmd.exe /d /c exit 0", resolvedCommand)) {
        std::wcerr << L"sudo: validation failed: trusted executable resolution is unavailable\n";
        valid = false;
    }

    SECURITY_ATTRIBUTES attributes = {};
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!BuildPipeSecurity(attributes, descriptor)) {
        std::wcerr << L"sudo: validation failed: secure IPC descriptor is unavailable\n";
        valid = false;
    } else {
        GUID guid;
        wchar_t guidBuffer[64];
        if (FAILED(CoCreateGuid(&guid)) || StringFromGUID2(guid, guidBuffer, 64) == 0) {
            std::wcerr << L"sudo: validation failed: IPC identifiers are unavailable\n";
            valid = false;
        } else {
            std::wstring pipeName = L"\\\\.\\pipe\\sudo_validate_" + std::wstring(guidBuffer);
            HANDLE pipe = CreateNamedPipeW(pipeName.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                                           PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1,
                                           1024, 1024, 0, &attributes);
            if (pipe == INVALID_HANDLE_VALUE) {
                std::wcerr << L"sudo: validation failed: secure IPC pipes cannot be created\n";
                valid = false;
            } else {
                CloseHandle(pipe);
            }
        }
        LocalFree(descriptor);
    }

    DWORD enableLua = 1;
    DWORD valueSize = sizeof(enableLua);
    LSTATUS registryStatus = RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"EnableLUA", RRF_RT_REG_DWORD, NULL, &enableLua, &valueSize);
    if (registryStatus == ERROR_SUCCESS && enableLua == 0 && !IsAdmin()) {
        std::wcerr << L"sudo: validation failed: UAC is disabled for a non-elevated process\n";
        valid = false;
    }

    if (valid) {
        std::wcout << L"sudo: environment validation passed\n";
        return 0;
    }
    return 1;
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
        return ValidateEnvironment();
    }

    // Check if worker mode triggered by internal runner
    if (firstArg == L"--sudo-worker") {
        if (argc != 6) return 1;
        std::wstring guid = argv[2];
        wchar_t* end = NULL;
        unsigned long parsedProcessId = std::wcstoul(argv[3], &end, 10);
        if (end == argv[3] || *end != L'\0' || parsedProcessId == 0 || parsedProcessId > MAXDWORD ||
            (std::wstring(argv[4]) != L"0" && std::wstring(argv[4]) != L"1")) {
            return 1;
        }
        return RunWorker(guid, static_cast<DWORD>(parsedProcessId),
                         std::wstring(argv[4]) == L"1", argv[5]);
    }

    std::wstring targetCmd = GetTargetCommandLine();
    std::wstring resolvedTargetCmd;
    if (!ResolveTargetCommand(targetCmd, resolvedTargetCmd)) {
        std::wcerr << L"sudo: command was not found in a trusted location\n";
        return 1;
    }

    // Direct launch if already running elevated
    if (IsAdmin()) {
        return RunElevatedDirect(resolvedTargetCmd);
    }

    // Otherwise, trigger Client Proxy logic
    return RunClient(resolvedTargetCmd);
}
