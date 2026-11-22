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


def cmd_baseline_wheel(a):
    from .wheel_scan import register_wheel_baseline
    manifest = register_wheel_baseline(a.wheel, a.registry, source_url=a.source_url,
                                       provenance_ref=a.provenance_ref, verify_pypi=a.verify_pypi)
    print(json.dumps({key: manifest[key] for key in
                      ("name", "version", "sha256", "source_url", "provenance_ref", "source_verification")},
                     ensure_ascii=False, indent=2))


def cmd_check_wheel(a):
    from .wheel_scan import assess_wheel, persist_wheel_event
    from .report import generate
    event = assess_wheel(a.wheel, a.registry)
    persist_wheel_event(event, a.registry)
    if a.report:
        generate(event, a.report)
    print(json.dumps(event, ensure_ascii=False, indent=2))
    sys.exit({"ALLOW": 0, "BLOCK": 1, "REVIEW": 2}.get(event.get("verdict"), 2))


def cmd_train_candidate(a):
    from .online_learn import candidate_readiness, build_candidate
    readiness = candidate_readiness(a.data_root)
    if not readiness["ready"]:
        print(json.dumps({"status": "insufficient_confirmed_data", **readiness}, ensure_ascii=False, indent=2))
        return
    from .training_process import training_lock
    with training_lock(a.data_root):
        result = build_candidate(a.data_root, a.model, device=a.device, cpu_threads=a.cpu_threads)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_network_capture(a):
    import psutil
    from .network_telemetry import NetworkTelemetry
    from .network_evidence import NetworkEventLog
    telemetry = NetworkTelemetry()
    snapshot = telemetry.sample(psutil)
    log = NetworkEventLog(Path(a.data_root) / "online" / "network_events.sqlite")
    event_id = log.capture(snapshot)
    print(json.dumps({"event_id": event_id,
                      "remote_endpoint_count": snapshot.get("remote_endpoint_count"),
                      "flows": [{"id": f["id"], "remote_ip": f["remote_ip"],
                                 "connections": f["connection_count"]}
                                for f in snapshot.get("remote_endpoints", [])]},
                     ensure_ascii=False, indent=2))


def cmd_network_events(a):
    from .network_evidence import NetworkEventLog
    log = NetworkEventLog(Path(a.data_root) / "online" / "network_events.sqlite")
    print(json.dumps(log.list_recent(a.limit), ensure_ascii=False, indent=2))


def cmd_network_label(a):
    from .network_evidence import NetworkEventLog
    from .network_label_reviews import NetworkLabelReviews
    log = NetworkEventLog(Path(a.data_root) / "online" / "network_events.sqlite")
    event = log.get(a.event_id)
    if event is None:
        print(json.dumps({"error": "событие не найдено"}, ensure_ascii=False))
        sys.exit(1)
    flow_ids = {flow["id"] for flow in event["snapshot"].get("remote_endpoints", [])}
    if a.flow_id not in flow_ids:
        print(json.dumps({"error": "указанный flow-id отсутствует в этом захваченном снимке",
                          "known_flow_ids": sorted(flow_ids)}, ensure_ascii=False))
        sys.exit(1)
    reviews = NetworkLabelReviews(Path(a.data_root) / "online" / "network_label_reviews.sqlite")
    decision = reviews.propose(a.event_id, a.flow_id, event["snapshot_sha256"],
                               a.verdict == "malicious", a.evidence, a.rationale)
    print(json.dumps(decision, ensure_ascii=False, indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(prog="integrityguard", description="Контроль целостности пакетно-нейросетевых программ")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("train-candidate", help="дообучить отдельного кандидата на подтверждённых реальных данных")
    s.add_argument("--data-root", required=True, type=Path)
    s.add_argument("--model", required=True, type=Path)
    s.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    s.add_argument("--cpu-threads", type=int, default=4, help="число CPU-потоков PyTorch для дообучения (по умолчанию 4)")
    s.set_defaults(fn=cmd_train_candidate)

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

    s = sub.add_parser("baseline-wheel", help="зарегистрировать точный trusted PyPI wheel и его происхождение")
    s.add_argument("--verify-pypi", action="store_true",
                   help="сверить SHA-256 с PyPI; отправляются только имя и версия публичного пакета")
    s.add_argument("--wheel", required=True, type=Path)
    s.add_argument("--registry", default="registry")
    s.add_argument("--source-url", required=True, help="страница проекта или URL артефакта")
    s.add_argument("--provenance-ref", required=True, help="PyPI attestation URL, digest record или reviewer reference")
    s.set_defaults(fn=cmd_baseline_wheel)

    s = sub.add_parser("check-wheel", help="статически проверить реальный .whl без установки или исполнения")
    s.add_argument("--wheel", required=True, type=Path)
    s.add_argument("--registry", default="registry")
    s.add_argument("--report", type=Path, help="необязательный путь PDF-отчёта")
    s.set_defaults(fn=cmd_check_wheel)

    s = sub.add_parser("network-capture", help="сохранить реальный снимок сетевой телеметрии для последующей разметки")
    s.add_argument("--data-root", required=True, type=Path)
    s.set_defaults(fn=cmd_network_capture)

    s = sub.add_parser("network-events", help="показать последние захваченные снимки сетевой телеметрии")
    s.add_argument("--data-root", required=True, type=Path)
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=cmd_network_events)

    s = sub.add_parser("network-label", help="подтвердить метку (benign/malicious) для конкретного потока в захваченном снимке")
    s.add_argument("--data-root", required=True, type=Path)
    s.add_argument("--event-id", required=True)
    s.add_argument("--flow-id", required=True)
    s.add_argument("--verdict", required=True, choices=("benign", "malicious"))
    s.add_argument("--evidence", required=True, type=Path)
    s.add_argument("--rationale", required=True)
    s.set_defaults(fn=cmd_network_label)

    for stream in (sys.stdout, sys.stderr):          # консоль Windows может не знать «—», «→» и т. п.
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")   # кириллица всегда в UTF-8
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
