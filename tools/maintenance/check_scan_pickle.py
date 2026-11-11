"""Разовая проверка: сузили белый список GLOBAL-ссылок и добавили лимит размера pickle-потока."""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from integrityguard.scan import scan_pickle, _MAX_PICKLE_BYTES

# 1) настоящий чекпоинт проекта не должен считаться подозрительным
real = Path("models/detector.pt").read_bytes()
bad, refs = scan_pickle(real)
print("[OK]  " if not bad else "[FAIL]", "настоящий detector.pt не помечен подозрительным:", refs)

# 2) посторонняя GLOBAL-ссылка вне узкого списка — подозрительна (симулируем через обычный pickle)
import pickle


class Evil:
    def __reduce__(self):
        return (eval, ("1+1",))


evil_bytes = pickle.dumps(Evil())
bad2, refs2 = scan_pickle(evil_bytes)
print("[OK]  " if bad2 else "[FAIL]", "вредоносный GLOBAL-ref (eval) помечен подозрительным:", refs2)

# 3) обычный безопасный pickle с разрешённым GLOBAL (collections.OrderedDict) не помечается
from collections import OrderedDict

safe_bytes = pickle.dumps(OrderedDict(a=1))
bad3, refs3 = scan_pickle(safe_bytes)
print("[OK]  " if not bad3 else "[FAIL]", "обычный OrderedDict не помечен подозрительным:", refs3)

# 4) zip-бомба: .pkl-запись с заявленным огромным file_size не распаковывается, а сразу помечается
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    info = zipfile.ZipInfo("fake/data.pkl")
    z.writestr(info, b"\x00" * 1000)  # реальное содержимое маленькое
# искусственно подменяем заявленный file_size в заголовке записи, как могла бы сделать атака
data = bytearray(buf.getvalue())
with zipfile.ZipFile(io.BytesIO(bytes(data))) as z:
    real_info = z.infolist()[0]
    print("    исходный file_size в тестовом архиве:", real_info.file_size)

bomb_bad, bomb_refs = scan_pickle(bytes(data))
# при обычном (не подменённом) размере бомбы тут не получится — проверяем сам механизм лимита напрямую
from integrityguard import scan as scan_mod

orig_limit = scan_mod._MAX_PICKLE_BYTES
scan_mod._MAX_PICKLE_BYTES = 10  # искусственно занижаем лимит, чтобы проверить срабатывание без гигабайт данных
try:
    bad4, refs4 = scan_pickle(bytes(data))
    print("[OK]  " if bad4 and "zip-бомбу" in refs4[0] else "[FAIL]", "превышение лимита размера pkl-потока отловлено:", refs4)
finally:
    scan_mod._MAX_PICKLE_BYTES = orig_limit

print("Готово.")
