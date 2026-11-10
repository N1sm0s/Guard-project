"""Командная строка IntegrityGuard."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import torch


def _progress(i, n):
    print(f"\r  проектов: {i}/{n}", end="" if i < n else "\n", flush=True)


def cmd_corpus(a):
    from .corpus import build_corpus
    t = time.time()
    samples = build_corpus(a.projects, a.seed)
    torch.save(samples, a.out)
    print(f"Корпус: {len(samples)} образцов -> {a.out} ({time.time() - t:.0f} с)")


def cmd_train(a):
    from .train import run_experiment
    # corpus.pt содержит объекты PackageSpec (не только тензоры), поэтому его нельзя
    # загрузить с weights_only=True; файл создаётся локально командой `corpus`,
    # внешний/недоверенный corpus.pt этой командой подавать нельзя.
    samples = torch.load(a.corpus, weights_only=False)
    _, r = run_experiment(samples, a.out, a.epochs, a.fpr, a.seed, not a.no_ablation)
    print((Path(a.out) / "report.md").read_text(encoding="utf-8"))


def cmd_export(a):
    from .collect import export_corpus
    labels = export_corpus(a.out, a.projects, a.seed)
    print(f"Выгружено пакетов-кандидатов: {len(labels)} -> {a.out} (разметка: labels.json)")


def _guard(a):
    from .system import IntegrityGuard
    return IntegrityGuard(a.registry, a.model, Path(a.key).read_bytes() if a.key else None)


def cmd_sign(a):
    from .collect import sign_package
    print(sign_package(a.package, Path(a.key).read_bytes()))


def cmd_baseline(a):
    name = _guard(a).register_baseline(a.package, a.control, a.index)
    print(f"Эталон зарегистрирован: {name}")


def cmd_check(a):
    from .system import format_event
    g = _guard(a)
    ev = g.check(a.package, a.stage, a.index, a.strict)
    code = g.respond(ev, a.package, a.promote)
    print(json.dumps(ev, ensure_ascii=False, indent=1) if a.json else format_event(ev))
    sys.exit(code)


def cmd_monitor(a):
    from .system import format_event
    _guard(a).monitor(a.package, a.interval, a.once, lambda ev: print(format_event(ev), flush=True),
                      lambda err: print(f"Ошибка проверки: {err}", flush=True))


def cmd_demo(a):
    """Сквозная демонстрация: корпус -> обучение -> выгрузка пакетов -> эталон -> проверки."""
    from .collect import export_corpus
    from .corpus import build_corpus
    from .system import IntegrityGuard, format_event
    from .train import run_experiment
    out = Path(a.out)
    print(f"1/4 Формирование корпуса ({a.projects} проектов)")
    samples = build_corpus(a.projects, 0, progress=_progress)
    torch.save(samples, out.mkdir(parents=True, exist_ok=True) or out / "corpus.pt")
    print("2/4 Обучение и оценка")
    run_experiment(samples, out / "run", a.epochs, ablation=False, log=lambda s: None)
    print((out / "run" / "report.md").read_text(encoding="utf-8").split("## По уровням")[0])
    print("3/4 Выгрузка примеров пакетов на диск и регистрация эталона")
    labels = export_corpus(out / "packages", 1, seed=777)
    proj = out / "packages" / "project_000"
    g = IntegrityGuard(out / "registry", out / "run" / "detector.pt", (out / "packages" / "signing.key").read_bytes())
    g.register_baseline(proj / "reference", proj / "control.npz")
    print("4/4 Проверка кандидатов (разметка -> вердикт)")
    ok = 0
    for lb in labels:
        c = proj / "candidates" / lb["candidate"]
        ev = g.check(c, "build", f"{c}.index.json")
        g.respond(ev)
        hit = (ev["verdict"] != "ALLOW") == (lb["class"] != "clean")
        ok += hit
        print(f"  {'+' if hit else '-'} {lb['candidate']:<36} -> {ev['verdict']:<6} {ev['threat']:<10} {ev['score']:.3f}"
              f"  [{ev['timing_ms']['total']:.0f} мс]")
    print(f"Верных решений: {ok}/{len(labels)}. Пример полного события:\n")
    bad = next(lb for lb in labels if lb["class"] != "clean")
    c = proj / "candidates" / bad["candidate"]
    print(format_event(g.check(c, "build", f"{c}.index.json")))
    print(f"\nЖурнал событий для SIEM: {out / 'registry' / 'events.jsonl'}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="integrityguard", description="Контроль целостности пакетно-нейросетевых программ")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("corpus", help="сформировать корпус примеров нарушений (признаки)")
    s.add_argument("--projects", type=int, default=300)
    s.add_argument("--out", default="corpus.pt")
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--workers", type=int, default=0)
    s.set_defaults(fn=cmd_corpus)

    s = sub.add_parser("train", help="обучить и оценить детектор")
    s.add_argument("--corpus", default="corpus.pt")
    s.add_argument("--out", default="run")
    s.add_argument("--epochs", type=int, default=70)
    s.add_argument("--fpr", type=float, default=0.02, help="допустимая доля ложных срабатываний")
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--no-ablation", action="store_true")
    s.set_defaults(fn=cmd_train)

    s = sub.add_parser("export", help="выгрузить корпус в виде каталогов пакетов")
    s.add_argument("--out", default="packages")
    s.add_argument("--projects", type=int, default=2)
    s.add_argument("--seed", type=int, default=1000)
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("sign", help="подписать пакет")
    s.add_argument("--package", required=True)
    s.add_argument("--key", required=True, help="файл с ключом подписи")
    s.set_defaults(fn=cmd_sign)

    def common(s):
        s.add_argument("--registry", default="registry", help="каталог эталонов и журналов")
        s.add_argument("--model", default="run/detector.pt")
        s.add_argument("--key", help="файл с ключом подписи (иначе IG_SIGNING_KEY или registry/signing.key)")
        s.add_argument("--package", required=True)

    s = sub.add_parser("baseline", help="зарегистрировать эталонное состояние пакета")
    common(s)
    s.add_argument("--control", help="контрольный набор .npz (X, y)")
    s.add_argument("--index", help="доверенный индекс зависимостей .json")
    s.set_defaults(fn=cmd_baseline)

    s = sub.add_parser("check", help="проверить пакет (код возврата: 0 допуск, 1 блокировка, 2 на проверку)")
    common(s)
    s.add_argument("--stage", default="build", choices=["build", "deploy", "runtime"])
    s.add_argument("--index", help="доверенный индекс зависимостей .json (по умолчанию — из реестра)")
    s.add_argument("--strict", action="store_true", help="считать «на проверку» блокировкой")
    s.add_argument("--promote", action="store_true", help="при допуске сделать пакет новым эталоном")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("monitor", help="контроль развёрнутого пакета в эксплуатации")
    common(s)
    s.add_argument("--interval", type=float, default=30)
    s.add_argument("--once", action="store_true")
    s.set_defaults(fn=cmd_monitor)

    s = sub.add_parser("demo", help="сквозная демонстрация на малом корпусе")
    s.add_argument("--out", default="demo")
    s.add_argument("--projects", type=int, default=30)
    s.add_argument("--epochs", type=int, default=50)
    s.add_argument("--workers", type=int, default=0)
    s.set_defaults(fn=cmd_demo)

    for stream in (sys.stdout, sys.stderr):          # консоль Windows может не знать «—», «→» и т. п.
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")   # кириллица всегда в UTF-8
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
