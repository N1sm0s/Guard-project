# Внешняя оценка класса `dependency`

`tools/eval_external_packages.py` принимает проверенные пары пакетов IntegrityGuard: чистый эталон и кандидат. Для каждой пары разметка должна быть `clean` или `dependency`, а поле `evidence` должно указывать источник, подтверждающий метку. Пути в JSON-манифесте разрешаются относительно самого манифеста.

Для исходных PyPI артефактов используйте `tools/convert_pypi_pair_static.py`: он читает файлы `.py`, `.pth` и `METADATA` в память, строит пару `PackageSpec` и передаёт её evaluator без записи исходников. Для предсказания используются одинаковые нейтральные тестовые веса с обеих сторон; эта конвертация оценивает статическое изменение пакета, не целостность реальных model weights.

Поддерживаются каталоги и ZIP-архивы, каждый из которых содержит ровно один пакет IntegrityGuard (`manifest.json` и `model.pt`). ZIP распаковывается во временный каталог с ограничениями на пути, ссылки, размер файла, общий объём и число файлов. Исходный код не импортируется и не запускается. `model.pt` проходит существующую проверку pickle и загружается только с `weights_only=True`.

Пример `pairs.json`:

```json
{
  "pairs": [
    {
      "id": "incident-001",
      "reference": "verified-clean.zip",
      "candidate": "affected-release.zip",
      "label": "dependency",
      "evidence": "URL advisory, affected version range, access date"
    }
  ]
}
```

Запуск из корня проекта:

```powershell
.venv\Scripts\python.exe tools\eval_external_packages.py `
  --manifest data\external\pairs.json `
  --model models\detector.pt `
  --out outputs\external-eval\metrics.json
```

Отчёт ограничен полнотой обнаружения угрозы зависимости и долей ложных тревог на чистых парах. Он не оценивает остальные восемь классов, не доказывает надёжность на реальных средах и не считает метку истинной без проверки указанного свидетельства.

Набор DataDog содержит подтверждённые вредоносные пакеты и метаданные затронутых версий, но не готовые пары в формате IntegrityGuard. Перед включением образца необходимо статически проверить происхождение и диапазон затронутых версий, получить чистый эталон той же линии пакета и вручную подтвердить пару. Пакеты нельзя устанавливать или запускать. Никакие внешние образцы не добавляются в репозиторий скриптом.

## Зафиксированный внешний случай (одна пара)

Elementary сообщила, что `elementary-data==0.23.3`, опубликованный 24 апреля 2026 г. в 22:20:47 UTC, содержал вредоносный код; все остальные версии CLI, включая 0.23.2, не были затронуты ([официальный отчёт](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3)). Для чистого эталона использован PyPI wheel `elementary_data-0.23.2-py3-none-any.whl`, дата загрузки 15 апреля 2026 г. 07:37:30 UTC, SHA-256 `0fc244c3a4533741177bd17e624cdc30221952df7e13bd049851d34ec84f35f8`. Для кандидата использованы байты образца DataDog `2026-04-24-elementary-data-v0.23.3.zip` (SHA-256 `07cb429d3deff04af059e94273ee1b1525fba41182d3a3238fbc720fa067d45c`). В его `package_info` для исходного PyPI wheel 0.23.3 указан SHA-256 `d0f7e407596e5ed73c91f00f00398269109e182231904cfb60367094119cf141`; PyPI уже не отдаёт этот удалённый release. Источники артефактов: [чистый wheel](https://files.pythonhosted.org/packages/9a/df/4b34e86f447d1f8f9aa9991e6fdb877030c8e3b633283ab37f5a616f6a24/elementary_data-0.23.2-py3-none-any.whl), [DataDog sample](https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/compromised_lib/elementary-data/0.23.3/2026-04-24-elementary-data-v0.23.3.zip). Датасет DataDog лицензирован Apache-2.0; встроенная метаинформация обоих релизов указывает Apache-2.0 для исходного пакета.

Итоговый прогон `tools/convert_pypi_pair_static.py` обработал исходники только в памяти: 174 Python-модуля и 34 зависимости для эталона; 175 модулей и 34 зависимости для кандидата. Дополнительный модуль — `elementary.pth`. Код не исполнялся, не импортировался и не устанавливался. Предыдущая неудачная попытка дискового преобразования оставила временные копии исходников вне проекта в `%TEMP%\ig_elementary_pair_20261110\ig_format` и `converted_repro`; очистка этих двух каталогов пока не выполнена. Одинаковый нейтральный синтетический `state_dict` использован для обоих состояний; поэтому результат не оценивает подмену весов и не является независимой проверкой поведенческой ветви.

Первый внешний пример `num2words==0.5.15` описан в отчёте PyPI о фишинговой атаке: злоумышленник выпустил вредоносные версии 0.5.15 и 0.5.16, которые PyPI удалил в течение нескольких часов ([отчёт PyPI](https://blog.pypi.org/posts/2025-07-31-incident-report-phishing-attack/)). Для сравнения взяты чистый wheel 0.5.14 и архив DataDog для 0.5.15. SHA-256: wheel `1c8e5b00142fc2966fd8d685001e36c4a9911e070d1b120e1beb721fa1edb33d`, архив `d9b676fab404fb05781907a5ef639bb9defe347c6851dbef0e00f5ce3fddc0a1`. При статическом чтении один файл `.py` кандидата содержал 408 405 символов замены UTF-8 из 1 275 659 (32,02%); бинарное содержимое было замаскировано расширением Python.

Для отрицательной пары сопоставлены чистые `num2words==0.5.13` и `0.5.14`; обе версии находятся вне списка затронутых PyPI релизов. SHA-256: wheel 0.5.13 `39e662c663f0a7e15415431ea68eb3dc711b49e3b776d93403e1da0a219ca4ee`, wheel 0.5.14 — выше. Текущая эвристика не сработала на чистом обновлении.

Результаты на трёх внешних парах (две положительные, одна чистая):

| Модель | Вердикт | Названный класс | Risk score |
|---|---|---|---:|
| Основная `models/detector.pt`, Elementary | BLOCK | dependency | 89 |
| Экспериментальная `outputs/leakage-reduced-20261110/internal/detector.pt`, Elementary | BLOCK | adversarial (ошибка класса) | 74 |
| Основная `models/detector.pt`, num2words | REVIEW; нейросеть ALLOW | dependency, эвристика формата | 30 |
| Экспериментальная `outputs/overlap-controls-20261110/detector.pt`, num2words | REVIEW; нейросеть ALLOW | dependency, эвристика формата | 30 |
| Основная и экспериментальная модели, чистое обновление num2words | ALLOW | clean | 25 / 26 |

Итоговый вердикт `REVIEW` для num2words выдала детерминированная проверка формата, а не нейросеть: обе модели сами вернули `ALLOW`. Эвристика ищет новые/изменённые `.py` с большим числом UTF-8 replacement-символов и назначает ручную проверку, не объявляя пакет вредоносным. На одной чистой паре ложного срабатывания нет; этого недостаточно для оценки частоты ложных тревог. Для Elementary сохранены ранее измеренные результаты, но отдельный JSON отчёта для этой пары в `outputs/external-eval` пока отсутствует.

В сумме итоговое решение обнаружило 2/2 положительных пар (Elementary через модель; num2words через правило формата) и разрешило 1/1 чистую пару. Выборка слишком мала и неоднородна, поэтому эти числа не являются оценкой надёжности модели или доказательством обобщения. Особенно важно разделять нейросетевую классификацию и эвристическое правило; на num2words нейросеть пропустила угрозу.

JSON отчёты последних двух пар: `outputs/external-eval/num2words_pair.json` и `outputs/external-eval/num2words_clean_pair.json`. В каждом прогнозе поля `neural_verdict` и `source_anomalies` показывают вклад модели и правила отдельно.

Повторить преобразование из заранее скачанных архивов можно так:

```powershell
.venv\Scripts\python.exe tools\convert_pypi_pair_static.py `
  --reference-wheel <path-to-elementary_data-0.23.2-py3-none-any.whl> `
  --datadog-archive <path-to-2026-04-24-elementary-data-v0.23.3.zip> `
  --model models\detector.pt `
  --model outputs\leakage-reduced-20261110\internal\detector.pt `
  --out <path-outside-repository>\elementary-eval.json
```
