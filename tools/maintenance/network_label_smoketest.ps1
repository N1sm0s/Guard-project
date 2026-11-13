Set-Location "F:\New\integrityguard"
$python = ".venv\Scripts\python.exe"
$dataRoot = "C:\Users\pavel\AppData\Local\IntegrityGuard\data\_network_label_smoketest"
Remove-Item -Recurse -Force $dataRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null

Write-Output "=== network-capture ==="
$captureJson = & $python -m integrityguard.cli network-capture --data-root $dataRoot
$captureJson
$capture = $captureJson | ConvertFrom-Json
$eventId = $capture.event_id

Write-Output "=== network-events ==="
& $python -m integrityguard.cli network-events --data-root $dataRoot --limit 5

if (-not $capture.flows -or $capture.flows.Count -eq 0) {
    Write-Output "=== нет живых внешних потоков на этой машине сейчас, тест разметки не выполнить ==="
    exit 0
}
$flowId = $capture.flows[0].id
Write-Output "=== label target: event=$eventId flow=$flowId ip=$($capture.flows[0].remote_ip) ==="

$evidence = Join-Path $dataRoot "evidence_note.txt"
"Смоук-тест: соединение с $($capture.flows[0].remote_ip), наблюдается активным процессом на машине. Не найдено совпадений с публичными blocklist при ручной проверке." | Set-Content -Path $evidence -Encoding utf8

Write-Output "=== 1st reviewer vote (benign) ==="
& $python -m integrityguard.cli network-label --data-root $dataRoot --event-id $eventId --flow-id $flowId `
    --verdict benign --evidence $evidence --rationale "Смоук-тест: одно наблюдение, явной угрозы не выявлено, второй ревьюер пока не голосовал."
