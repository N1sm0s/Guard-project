import subprocess, sys, os, time

# Kill existing pythonw processes
result = subprocess.run(
    ['taskkill', '/F', '/FI', 'IMAGENAME eq pythonw.exe'],
    capture_output=True, text=True, shell=True
)
print("Kill:", result.stdout.strip() or result.stderr.strip())
time.sleep(2)

# Launch app
venv_py = r'F:\New\integrityguard\.venv\Scripts\pythonw.exe'
launch = r'F:\New\integrityguard\launch_gui.py'
proc = subprocess.Popen([venv_py, launch],
    cwd=r'F:\New\integrityguard',
    creationflags=0x00000008 | 0x08000000)  # DETACHED_PROCESS | CREATE_NO_WINDOW
print(f"New PID: {proc.pid}")
