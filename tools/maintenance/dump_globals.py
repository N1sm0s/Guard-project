import io
import zipfile
import pickletools
from pathlib import Path

p = Path("models/detector.pt")
data = p.read_bytes()
with zipfile.ZipFile(io.BytesIO(data)) as z:
    pkls = [n for n in z.namelist() if n.endswith(".pkl")]
    print(pkls)
    for n in pkls:
        payload = z.read(n)
        strings = []
        refs = set()
        for op, arg, _ in pickletools.genops(payload):
            if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8"):
                strings.append(arg)
            ref = None
            if op.name == "GLOBAL":
                ref = arg.replace(" ", ".")
            elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
                ref = f"{strings[-2]}.{strings[-1]}"
            if ref:
                refs.add(ref)
        print(n, sorted(refs))
