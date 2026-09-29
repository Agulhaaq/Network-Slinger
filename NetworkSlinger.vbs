' Network Slinger - Silent Local Desktop Launcher
' Launches the desktop application without any command prompt console flash
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
WshShell.Run "cmd /c pythonw run.py app", 0, False
