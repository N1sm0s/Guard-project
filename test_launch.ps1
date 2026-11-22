# Запускаем через python.exe (с консолью) чтобы увидеть ошибку
$python = 'F:\New\integrityguard\.venv\Scripts\python.exe'
$pyw    = 'F:\New\integrityguard\IntegrityGuard.pyw'
$root   = 'F:\New\integrityguard'
Set-Location $root
& $python $pyw 2>&1
