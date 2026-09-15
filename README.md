# Sudo for Windows Server

`sudo` brings a familiar way to run commands with administrator privileges to Windows Server.

Microsoft has made `sudo` available for Windows 10 and Windows 11, but it has not been available for Windows Server systems. This project provides a standalone `sudo.exe` for:

- Windows Server 2022
- Windows Server 2025
- Server with Desktop Experience
- Server Core

When the current process is not already running with administrator privileges, `sudo` requests elevation through UAC and runs the command with administrator privileges. When it is already elevated, the command is launched directly. The command's input, output, error output, and exit code are preserved as part of the execution.

## Installation

1. Download the ZIP file for the release.
2. Decompress the ZIP file.
3. Copy `sudo.exe` to `C:\Windows\System32` or to another directory included in the system `PATH`.
4. Open a new Command Prompt or PowerShell session if you changed the `PATH`.

You can verify the installation with:

```powershell
sudo --version
```

## Usage

```text
sudo [OPTIONS] <command> [args...]
```

Run a command with administrator privileges:

```powershell
sudo cmd.exe /c whoami
sudo powershell.exe -NoProfile -Command "Get-Service"
```

The command runs in the current console where possible. Windows may display a User Account Control prompt when elevation is required. If the prompt is canceled, `sudo` reports the denied elevation and returns a failure exit code.

## Options

| Option | Description |
| --- | --- |
| `-h`, `--help` | Display usage information. |
| `-v`, `--version` | Display the installed version. |
| `--validate` | Validate executable discovery, secure IPC creation, and the local UAC configuration. |

## Requirements

- Windows Server 2022 or Windows Server 2025
- Desktop Experience or Server Core
- UAC enabled when elevation is required
- A command shell such as Command Prompt or PowerShell

## Server Core

`sudo` is designed to run on Windows Server 2022 and Windows Server 2025 Server Core. It uses native Windows console, process, security, and IPC APIs and does not require Desktop Experience or the Server Core App Compatibility Feature on Demand.

The elevation behavior depends on the session and UAC policy:

- An interactive local or console session can display the UAC consent or credential prompt when elevation is required.
- WinRM, SSH, scheduled task, service, and other noninteractive sessions might not have an interactive secure desktop. In those sessions, prompt-based elevation can fail; start the session or process with an administrative token instead.
- If UAC is disabled, an already elevated administrator can run commands directly, but a non-elevated process cannot acquire an elevated token through `sudo`.
- Server security policy can change or deny elevation behavior even when UAC is enabled.

Verify a Server Core installation from its console before relying on it operationally:

```powershell
sudo --validate
sudo cmd.exe /c whoami
sudo powershell.exe -NoProfile -Command '$p = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
```

The final command should print `True`.

## Notes

- Administrative privileges are granted to the command being launched, not permanently to the calling shell.
- The target command's exit code is returned by `sudo`.
- Bare command names are resolved from Windows system directories and the machine-level `PATH`. Use an explicit path such as `.\tool.exe` for commands in the current directory or on a user-only `PATH`.
- Place only a trusted copy of `sudo.exe` in a directory on the system `PATH`.

## Building from source

The project is a native C++ Windows application. To build it, open a Visual Studio Developer Command Prompt with `cl.exe` available and compile `src\sudo.cpp` with the Windows SDK installed. The repository also includes a VS Code build task for Microsoft `cl.exe`.

## License

This project is licensed under the BSD 3-Clause License. See [LICENSE.txt](LICENSE.txt) for the full license text.