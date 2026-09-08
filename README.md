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
| `--validate` | Validate that the `sudo` environment can be used. |

## Requirements

- Windows Server 2022 or Windows Server 2025
- Desktop Experience or Server Core
- UAC enabled when elevation is required
- A command shell such as Command Prompt or PowerShell

## Notes

- Administrative privileges are granted to the command being launched, not permanently to the calling shell.
- The target command's exit code is returned by `sudo`.
- Place only a trusted copy of `sudo.exe` in a directory on the system `PATH`.

## Building from source

The project is a native C++ Windows application. To build it, open a Visual Studio Developer Command Prompt with `cl.exe` available and compile `src\sudo.cpp` with the Windows SDK installed. The repository also includes a VS Code build task for Microsoft `cl.exe`.

## License

This project is licensed under the BSD 3-Clause License. See [LICENSE.txt](LICENSE.txt) for the full license text.