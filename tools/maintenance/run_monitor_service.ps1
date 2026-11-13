Set-Location "F:\New\integrityguard"
$python = ".venv\Scripts\python.exe"
$registry = 'C:\Users\pavel\AppData\Local\IntegrityGuard\data\registry'
$model = 'C:\Users\pavel\AppData\Local\IntegrityGuard\data\runs\20261110_212946\detector.pt'
$pkg = 'C:\Users\pavel\AppData\Local\IntegrityGuard\data\demo_packages\project_001\candidates\00_dependency_dependency'
$log = 'C:\Users\pavel\AppData\Local\IntegrityGuard\data\monitor_service.log'
& $python -m integrityguard.cli monitor --registry $registry --model $model --package $pkg --interval 30 *>> $log
