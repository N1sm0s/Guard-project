Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' or Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*IntegrityGuard*' } |
    Select-Object ProcessId,ParentProcessId,CommandLine | Format-List
