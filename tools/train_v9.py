"""Canonical entry point for network-model training and evaluation research.

All new training/evaluation logic belongs in this file. Use its CLI to select
CTU-13 or IoT-23, a whole-capture split, feature contract, estimator, and
training parameters; do not fork another versioned training script for new
experiments. Older train_v6/v7/v8 and train_ctu13_* files are historical
experiments and are not the source of truth for current work.

Ground-truth handling is conservative: only explicitly labeled attack and
normal rows are included; Background and other ambiguous labels are excluded.
Splits are capture-based. Validation may select weights/thresholds but is not
an independent test. Consumed IoT-23 captures and CTU-IDSEVAL-6 are not
independent evidence for candidates trained or tuned on those same captures. Outputs remain
research-only and never activate a model or authorize network blocking.
"""
from __future__ import annotations

import csv
import argparse
import hashlib
import json
import math
import random
import sys
import tarfile
import time
import uuid
import zipfile
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard import network_flow_schema as flow_v8
from integrityguard import network_flow_schema_v9 as flow_v9
from integrityguard import network_flow_schema_v10 as flow_v10
from integrityguard.network_statistics import (
    MIN_BENIGN_SUPPORT_ZERO_FP, MIN_RELEASE_ATTACK_SUPPORT,
    RELEASE_FPR_CI_CEILING,
)
from integrityguard.paths import DATA_ROOT

FEATURE_NAMES = flow_v8.FEATURE_NAMES
FEATURE_VERSION = flow_v8.FEATURE_VERSION
feature_vector = flow_v8.feature_vector
from_ctu_row = flow_v8.from_ctu_row


def configure_feature_schema(version: int) -> None:
    """Select the one supported canonical CTU flow contract for this run."""
    global FEATURE_NAMES, FEATURE_VERSION, feature_vector, from_ctu_row
    if version == flow_v8.FEATURE_VERSION:
        FEATURE_NAMES = flow_v8.FEATURE_NAMES
        FEATURE_VERSION = flow_v8.FEATURE_VERSION
        feature_vector = flow_v8.feature_vector
        from_ctu_row = flow_v8.from_ctu_row
    elif version == flow_v9.FEATURE_VERSION:
        FEATURE_NAMES = flow_v9.FEATURE_NAMES
        FEATURE_VERSION = flow_v9.FEATURE_VERSION
        feature_vector = flow_v8.feature_vector
        from_ctu_row = flow_v9.from_ctu_row
    elif version == flow_v10.FEATURE_VERSION:
        FEATURE_NAMES = flow_v10.FEATURE_NAMES
        FEATURE_VERSION = flow_v10.FEATURE_VERSION
        feature_vector = flow_v10.from_live_flow
        from_ctu_row = from_ctu_v10_row
    else:
        raise ValueError(f"Unsupported CTU flow feature version: {version}")


def from_ctu_v10_row(row: dict) -> list[float]:
    """Map CTU NetFlow rows to v10 using ports; do not infer unavailable TCP flags."""
    base = flow_v9.from_ctu_row(row)
    def normalize_port(value, name):
        text = str(value or "").strip()
        if text in {"", "-"}:
            return "0"
        try:
            port = int(text, 0)
        except ValueError:
            try:
                # CTU files also contain zero-padded decimal strings, which
                # Python's base-0 parser intentionally rejects.
                port = int(text, 10)
            except ValueError:
                raise ValueError(f"Invalid CTU {name}") from None
        if not 0 <= port <= 65535:
            raise ValueError(f"Invalid CTU {name}")
        return str(port)

    transport = flow_v10._transport_features(
        row.get("Proto"), normalize_port(row.get("Sport"), "Sport"),
        normalize_port(row.get("Dport"), "Dport"))
    return base + transport

DATA = ROOT / "outputs" / "network-eval"
IOT_SPLITS = {
    # capture groups, not row-random splits. Captures 36-1, 43-1, 52-1 and 60-1 stay reserved.
    "multifamily-to-3": {"train": ("1-1", "8-1", "9-1", "34-1", "35-1"), "validation": "3-1"},
    "multifamily-to-3-clean-holdout": {
        "train": ("1-1", "8-1", "9-1", "34-1", "35-1"),
        "validation": ("3-1", "4-1", "5-1")},
    "cross-family-3-35": {
        "train": ("1-1", "8-1", "9-1", "34-1"),
        "validation": ("3-1", "35-1")},
    "cross-family-3-35-train-48": {
        "train": ("1-1", "8-1", "9-1", "34-1", "48-1"),
        "validation": ("3-1", "35-1")},
    "cross-family-3-35-train-48-49": {
        "train": ("1-1", "8-1", "9-1", "34-1", "48-1", "49-1"),
        "validation": ("3-1", "35-1")},
    "cross-family-1-35": {
        "train": ("3-1", "8-1", "9-1", "34-1", "48-1", "49-1"),
        "validation": ("1-1", "35-1")},
    "multifamily-to-35": {"train": ("1-1", "3-1", "8-1", "9-1", "34-1"), "validation": "35-1"},
    "mirai-to-35": {
        "train": ("1-1", "3-1", "8-1", "9-1", "34-1", "48-1", "49-1"),
        "validation": "35-1"},
    "multifamily-to-35-add-torii20-21": {
        "train": ("1-1", "3-1", "8-1", "9-1", "20-1", "21-1", "34-1", "48-1", "49-1"),
        "validation": "35-1"},
    "multifamily-to-35-add-kenjiro-ircbot": {
        "train": ("1-1", "3-1", "8-1", "9-1", "33-1", "34-1", "39-1", "48-1", "49-1"),
        "validation": "35-1"},
    "mirai-to-35-36": {
        "train": ("1-1", "3-1", "8-1", "9-1", "34-1", "48-1", "49-1"),
        "validation": ("35-1", "36-1")},
    "mirai-44-to-35": {
        "train": ("1-1", "3-1", "8-1", "9-1", "34-1", "44-1", "48-1", "49-1"),
        "validation": "35-1"},
    "mixed-to-3": {"train": ("34-1", "35-1"), "validation": "3-1"},
    "34-to-3": {"train": ("34-1",), "validation": "3-1"},
    "34-to-35": {"train": ("34-1",), "validation": "35-1"},
}
IOT_CLEAN = ("4-1", "5-1", "7-2", "7-3", "7-4", "7-5", "7-6")
IOT_DIR = DATA / "official-iot23v2"
IOT_FILES = {
    "1-1": IOT_DIR / "ctu-iot-malware-1-1-zeek-conn.log.labeled",
    "3-1": IOT_DIR / "ctu-iot-malware-3-1-zeek-conn.log.labeled",
    "8-1": IOT_DIR / "ctu-iot-malware-8-1-zeek-conn.log.labeled",
    "9-1": IOT_DIR / "ctu-iot-malware-9-1-zeek-conn.log.labeled",
    "34-1": IOT_DIR / "ctu-iot-malware-34-1-zeek-conn.log.labeled",
    "35-1": IOT_DIR / "ctu-iot-malware-35-1-zeek-conn.log.labeled",
    "20-1": IOT_DIR / "capture-20-1" / "zeek-conn.log.labeled",
    "21-1": IOT_DIR / "capture-21-1" / "zeek-conn.log.labeled",
    "44-1": IOT_DIR / "ctu-iot-malware-44-1-zeek-conn.log.labeled",
    "48-1": IOT_DIR / "ctu-iot-malware-48-1-zeek-conn.log.labeled",
    "49-1": IOT_DIR / "ctu-iot-malware-49-1-zeek-conn.log.labeled",
    "17-1": IOT_DIR / "ctu-iot-malware-17-1-zeek-conn.log.labeled",
    "33-1": IOT_DIR / "ctu-iot-malware-33-1-zeek-conn.log.labeled",
    "39-1": IOT_DIR / "ctu-iot-malware-39-1-zeek-conn.log.labeled",
    "43-1": IOT_DIR / "ctu-iot-malware-43-1-zeek-conn.log.labeled",
    "36-1": IOT_DIR / "ctu-iot-malware-36-1-zeek-conn.log.labeled",
    "52-1": IOT_DIR / "ctu-iot-malware-52-1-zeek-conn.log.labeled",
    "60-1": IOT_DIR / "ctu-iot-malware-60-1-zeek-conn.log.labeled",
    **{capture: IOT_DIR / f"ctu-honeypot-{capture}-zeek-conn.log.labeled"
       for capture in IOT_CLEAN},
}
IOT_RESERVED_TEST_IDS = frozenset({"36-1", "43-1", "52-1", "60-1"})
IOT_CAPTURE_SOURCE_URLS = {
    "36-1": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-36-1/2018-12-21-13-36-41-192.168.1.198-zeek-conn-log.labeled",
    "52-1": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-52-1/2019-03-08-13-24-30-192.168.1.197-zeek-conn-log.labeled",
    "43-1": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-43-1/2019-01-10-19-22-51-192.168.1.198-zeek-conn-log.labeled",
    "60-1": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-60-1/2019-09-20-02-40-32-192.168.1.195-zeek-conn-log.labeled",
}

OUT = DATA / "train-v9-validation-only"
TRAIN_CAPTURES = {
    "42": DATA / "ctu-42.binetflow",
    "43": DATA / "ctu-43.binetflow",
    "44": DATA / "official-ctu13" / "capture20110812_ctu44.binetflow",
}
CTU_ADDITIONAL_TRAIN_CAPTURES = {
    # Capture 46 was previously scored as an independent test for older
    # candidates; it is consumed and may only be reused for development training
    # when --ctu-allow-consumed-capture-training explicitly names it.
    "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
    # Capture 47 was also scored as an independent test for an older candidate;
    # if selected here, it is development training only and permanently consumed.
    "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
    "48": DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow",
    "49": DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow",
    "50": DATA / "official-ctu13" / "capture20110817_ctu50.binetflow",
    "51": DATA / "official-ctu13" / "capture20110818_ctu51.binetflow",
    "52": DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow",
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
    # Real benign-only source from MCFP. Its labels.config explicitly labels
    # SrcAddr=10.0.0.46 as Benign after defaulting every source to Background.
    "normal12": DATA / "official-mcfp" / "ctu-normal-12" / "2013-12-17_capture1.binetflow",
    # This capture was evaluated once as an independent test, failed, and is now
    # permanently consumed as development data for future candidates.
    "sme11-win7ad1": DATA / "official-ctu-sme11" / "CTU-SME-11_Experiment-VM-Microsoft-Windows7AD-1_v1.0.0.tar.bz2",
    "ctu6-b": DATA / "official-ctu-idseval-6" / "zeek.zip",
    "ctu6-m1": DATA / "official-ctu-idseval-6" / "zeek.zip",
    "ctu6-m2": DATA / "official-ctu-idseval-6" / "zeek.zip",
    "ctu6-p1": DATA / "official-ctu-idseval-6" / "zeek.zip",
    "ctu6-p2": DATA / "official-ctu-idseval-6" / "zeek.zip",
    "ctu6-p3": DATA / "official-ctu-idseval-6" / "zeek.zip",
}
CTU_IDSEVAL6_TRAIN_MEMBERS = {
    "ctu6-b": "ctu-idseval-6-benign-user-traffic-1.conn-labeled.log",
    "ctu6-m1": "ctu-idseval-6-malicious-malware-1.conn-labeled.log",
    "ctu6-m2": "ctu-idseval-6-malicious-malware-2.conn-labeled.log",
    "ctu6-p1": "ctu-idseval-6-malicious-portscan-1.conn-labeled.log",
    "ctu6-p2": "ctu-idseval-6-malicious-portscan-2.conn-labeled.log",
    "ctu6-p3": "ctu-idseval-6-malicious-portscan-3.conn-labeled.log",
}
CTU_CONSUMED_TRAIN_ONLY_CAPTURES = frozenset({
    "46", "47", "sme11-win7ad1", *CTU_IDSEVAL6_TRAIN_MEMBERS,
})
CTU_NORMAL12_LABEL_CONFIG = DATA / "official-mcfp" / "ctu-normal-12" / "labels.config"
CTU_NORMAL12_LABEL_CONFIG_SHA256 = "2881a478a231f1b948af907eabba05bf59b62152f985942e0b5fe372e5fa9925"
CTU_NORMAL12_HOST = "10.0.0.46"
CTU_SME11_WIN7AD1_SHA256 = "1654712980ae8cb27e4417359ffe1483156c582d674d2dcf031112b141652a63"
CTU_SME11_WIN7AD1_MD5 = "c97f72da16c46c5176bac52ad2101f0f"
VALIDATION_CAPTURE = {
    "45": DATA / "official-ctu13" / "capture20110815_ctu45.binetflow",
}
CTU_VALIDATION_CAPTURE_PATHS = {
    **VALIDATION_CAPTURE,
    "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
    "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
    "53": CTU_ADDITIONAL_TRAIN_CAPTURES["53"],
    "49": CTU_ADDITIONAL_TRAIN_CAPTURES["49"],
    "50": CTU_ADDITIONAL_TRAIN_CAPTURES["50"],
    # Whole captures can be assigned to validation instead of training for a run.
    "51": CTU_ADDITIONAL_TRAIN_CAPTURES["51"],
    "52": CTU_ADDITIONAL_TRAIN_CAPTURES["52"],
    "54": CTU_ADDITIONAL_TRAIN_CAPTURES["54"],
}
CTU_EVAL_CAPTURES = {
    "45": DATA / "official-ctu13" / "capture20110815_ctu45.binetflow",
    "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
    "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
    "61-1": DATA / "official-mcfp" / "ctu-mcfp-61-1-2014-05-30_capture-win13.binetflow",
}
CTU_SME11_EVAL_ARCHIVES = {
    "sme11-win7ad1": DATA / "official-ctu-sme11" / "CTU-SME-11_Experiment-VM-Microsoft-Windows7AD-1_v1.0.0.tar.bz2",
}
CTU_SME11_EVAL_MD5 = {"sme11-win7ad1": "c97f72da16c46c5176bac52ad2101f0f"}
CTU_IDSEVAL6_DIR = DATA / "official-ctu-idseval-6"
CTU_IDSEVAL6_ZEEK = CTU_IDSEVAL6_DIR / "zeek.zip"
CTU_IDSEVAL6_LABELS = CTU_IDSEVAL6_DIR / "labels.zip"
CTU_IDSEVAL6_ZEEK_SHA256 = "7350b5acfffbfd259266bf2f6ca1c3c7c721d80e59bc58502a8c82334a6f8065"
CTU_IDSEVAL6_ZEEK_MD5 = "33b57c813053eed12ec3738b65f27ef0"
CTU_IDSEVAL6_LABELS_SHA256 = "9cc26a52fc5076e691e6e32299fbf0c6a05d4290b1d0040fa50b65b1360e5822"
CTU_IDSEVAL6_LABELS_MD5 = "a017b6f47fe0603595cec7d643f7e4a2"
ISCX2017_THURSDAY = DATA / "official-iscx2017-zeek" / "Thursday-WorkingHours_labeled.parquet"
ISCX2017_THURSDAY_SHA256 = "f2b77777d65ad0843c413d31f17dc1712a1084daff86dcbceafc3471164317dc"
ISCX2017_THURSDAY_MD5 = "0c4a64a439f19eb147df93727622d8fb"
APEX_IDS2026_ARCHIVE = DATA / "official-apex-ids2026" / "apex_ids2026_hc_subset.zip"
APEX_IDS2026_SHA256 = "67bd424cd1a9314fb0b54412ced5600ec8f1aeb7da380de26af26698e919e8ef"
APEX_IDS2026_MD5 = "115ed72bb8759d3ce90fe17c52a0ee98"
ISCX2017_EXPLICIT_ATTACK_LABELS = frozenset({
    "PORTSCAN", "DDOS_LOIC", "BOTNET_ARES", "WEB_BRUTEFORCE", "WEB_XSS",
    "WEB_SQL_INJECTION", "FTP_PATATOR", "SSH_PATATOR", "DOS_HULK",
    "DOS_SLOWHTTPTEST", "DOS_GOLDENEYE", "DOS_SLOWLORIS", "HEARTBLEED",
    "INFILTRATION", "BOT",
})
SEED = 1907
EPOCHS = 60
PATIENCE = 8
BATCH_SIZE = 4096
# Keep the generic development selection default separate from the prospective
# release gate. CTU training supplies its preregistered per-capture dev ceiling.
FPR_CEILING = 0.0001

# Relative positive-class multipliers are intentionally modest and fixed before
# running. Each scheme is normalized to mean sample weight 1.0.
WEIGHT_SCHEMES = {
    "natural": {"attack_multiplier": 1.0, "udp_attack_multiplier": 1.0},
    "class_balanced": {"attack_multiplier": 1.0, "udp_attack_multiplier": 1.0,
                        "use_class_balance": True},
    "balanced_udp_2x": {"attack_multiplier": 1.0, "udp_attack_multiplier": 2.0,
                        "use_class_balance": True},
}


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def label_for_ctu(label: str) -> int | None:
    """Return attack=1 / normal=0 only for explicit publisher labels."""
    value = (label or "").strip()
    if value.startswith("flow=From-Botnet-"):
        return 1
    if value.startswith("flow=From-Normal-"):
        return 0
    return None


def feature_from_zeek_mapping(row: dict) -> list[float]:
    """Map publisher Zeek conn fields through the selected versioned schema."""
    protocol = row.get("proto")
    duration = row.get("duration")
    if FEATURE_VERSION == flow_v9.FEATURE_VERSION:
        # The versioned Zeek adapter interprets standard Zeek conn positions
        # and appends an explicit duration-missing indicator.
        columns = ["-"] * 20
        columns[6] = str(protocol or "-")
        columns[8] = str(duration or "-")
        for index, key in ((16, "orig_pkts"), (17, "orig_ip_bytes"),
                           (18, "resp_pkts"), (19, "resp_ip_bytes")):
            value = row.get(key, "-")
            columns[index] = "-" if value is None else str(value)
        return flow_v9.from_zeek_row(columns)
    if FEATURE_VERSION == flow_v10.FEATURE_VERSION:
        columns = ["-"] * 21
        columns[3] = str(row.get("id.orig_p", "-"))
        columns[5] = str(row.get("id.resp_p", "-"))
        columns[6] = str(protocol or "-")
        columns[8] = str(duration or "-")
        for index, key in ((16, "orig_pkts"), (17, "orig_ip_bytes"),
                           (18, "resp_pkts"), (19, "resp_ip_bytes")):
            value = row.get(key, "-")
            columns[index] = "-" if value is None else str(value)
        return flow_v10.from_zeek_row(columns)
    packets = float(row.get("orig_pkts", "-")) + float(row.get("resp_pkts", "-"))
    source_bytes = float(row.get("orig_ip_bytes", "-"))
    destination_bytes = float(row.get("resp_ip_bytes", "-"))
    return flow_v8.feature_vector(duration, packets, source_bytes + destination_bytes,
                                  source_bytes, destination_bytes, protocol)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def label_for_zeek(columns: list[str]) -> str:
    """Handle both IoT-23 v2 layouts: tab-separated or packed label tail."""
    if len(columns) >= 22 and columns[-2].strip().lower() in {"malicious", "benign"}:
        return columns[-2].strip().lower()
    tail = columns[-1].strip().split() if columns else []
    return tail[-2].lower() if len(tail) >= 3 else ""


def load_iot_capture(capture_id: str, path: Path, feature_version: int,
                     max_per_class: int | None, seed: int, capture_clean: bool = False):
    """Stream a real Zeek capture, preserve only publisher-labeled rows, hash source."""
    if not path.is_file():
        raise FileNotFoundError(f"Missing IoT-23 capture {capture_id}: {path}")
    if feature_version == 9:
        from integrityguard.network_flow_schema_v9 import from_zeek_row
    elif feature_version == 10:
        from integrityguard.network_flow_schema_v10 import from_zeek_row
    else:
        raise ValueError("Only causal, runtime-supported IoT feature versions 9 and 10 may be trained")
    rng = random.Random(seed + sum(map(ord, capture_id)))
    reservoir = {0: [], 1: []}
    seen = {0: 0, 1: 0}
    counts = {"attack": 0, "benign": 0, "unknown": 0, "invalid": 0}
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for raw_line in stream:
            digest.update(raw_line)
            if not raw_line or raw_line.startswith(b"#"):
                continue
            try:
                columns = raw_line.decode("utf-8", errors="replace").rstrip("\r\n").split("\t")
                label = label_for_zeek(columns)
                if label == "malicious":
                    target = 1
                elif label == "benign" or (capture_clean and not label):
                    target = 0
                else:
                    counts["unknown"] += 1
                    continue
                vector = from_zeek_row(columns)
            except (TypeError, ValueError, IndexError, OverflowError):
                counts["invalid"] += 1
                continue
            counts["attack" if target else "benign"] += 1
            if max_per_class is None:
                reservoir[target].append(vector)
            else:
                seen[target] += 1
                if len(reservoir[target]) < max_per_class:
                    reservoir[target].append(vector)
                else:
                    replacement = rng.randrange(seen[target])
                    if replacement < max_per_class:
                        reservoir[target][replacement] = vector
    if not any(reservoir.values()):
        raise ValueError(f"Capture {capture_id} has no usable explicit labels")
    x = np.asarray(reservoir[0] + reservoir[1], dtype=np.float32)
    y = np.concatenate((np.zeros(len(reservoir[0]), dtype=np.int64),
                        np.ones(len(reservoir[1]), dtype=np.int64)))
    counts["sampled_rows"] = int(len(y))
    return x, y, counts, digest.hexdigest().upper()


def capture_balanced_sample_weights(labels: np.ndarray, capture_ids: np.ndarray,
                                    strategy: str = "equal") -> np.ndarray:
    """Weight capture groups equally or temper the effect of tiny groups."""
    labels = np.asarray(labels, dtype=np.int64)
    capture_ids = np.asarray(capture_ids)
    if len(labels) != len(capture_ids) or not len(labels):
        raise ValueError("Training labels and capture IDs must be non-empty and aligned")
    if strategy not in {"equal", "sqrt", "proportional"}:
        raise ValueError(f"Unsupported capture-weighting strategy: {strategy}")
    weights = np.zeros(len(labels), dtype=np.float64)
    for class_id in (0, 1):
        present_captures = [capture for capture in np.unique(capture_ids)
                            if np.any((capture_ids == capture) & (labels == class_id))]
        if not present_captures:
            raise ValueError(f"Training set lacks class {class_id}")
        capture_counts = {
            capture: int(np.count_nonzero((capture_ids == capture) & (labels == class_id)))
            for capture in present_captures
        }
        if strategy == "equal":
            masses = {capture: 1.0 for capture in present_captures}
        elif strategy == "sqrt":
            masses = {capture: math.sqrt(capture_counts[capture]) for capture in present_captures}
        else:
            masses = {capture: float(capture_counts[capture]) for capture in present_captures}
        total_mass = sum(masses.values())
        for capture in present_captures:
            mask = (capture_ids == capture) & (labels == class_id)
            weights[mask] = 0.5 * masses[capture] / total_mass / capture_counts[capture]
    weights *= len(weights) / weights.sum()
    return weights.astype(np.float32)


def capture_distribution_weights(labels: np.ndarray, capture_ids: np.ndarray,
                                 strategy: str) -> np.ndarray:
    """Reweight capture groups within each class while preserving class mass."""
    labels = np.asarray(labels, dtype=np.int64)
    capture_ids = np.asarray(capture_ids)
    if len(labels) != len(capture_ids) or not len(labels):
        raise ValueError("Training labels and capture IDs must be non-empty and aligned")
    if strategy not in {"equal", "sqrt"}:
        raise ValueError(f"Unsupported capture-distribution strategy: {strategy}")
    weights = np.ones(len(labels), dtype=np.float64)
    for class_id in (0, 1):
        captures = np.unique(capture_ids[labels == class_id])
        if not len(captures):
            raise ValueError(f"Training set lacks class {class_id}")
        counts = {capture: int(np.count_nonzero((labels == class_id) & (capture_ids == capture)))
                  for capture in captures}
        masses = {capture: (1.0 if strategy == "equal" else math.sqrt(counts[capture]))
                  for capture in captures}
        mass_total = sum(masses.values())
        class_total = sum(counts.values())
        for capture in captures:
            mask = (labels == class_id) & (capture_ids == capture)
            weights[mask] = class_total * masses[capture] / mass_total / counts[capture]
    weights /= weights.mean()
    return weights.astype(np.float32)


def run_iot23(args) -> None:
    """Unified whole-capture IoT-23 experiment runner. Capture 60-1 is reserved."""
    try:
        from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, HistGradientBoostingClassifier
        from sklearn.metrics import roc_auc_score, average_precision_score
    except ImportError as error:
        raise RuntimeError("Install scikit-learn to run --dataset iot23") from error
    import joblib
    split = IOT_SPLITS[args.split]
    training_ids = list(split["train"])
    validation_ids = [split["validation"]] if isinstance(split["validation"], str) else list(split["validation"])
    validation_clean_ids = [capture for capture in validation_ids if capture in IOT_CLEAN]
    training_clean_ids = [capture for capture in IOT_CLEAN if capture not in validation_clean_ids]
    train_ids = training_ids + (training_clean_ids if args.include_clean else [])
    all_ids = train_ids + validation_ids
    reserved_overlap = IOT_RESERVED_TEST_IDS.intersection(all_ids)
    if reserved_overlap:
        raise ValueError(f"Reserved independent test capture(s) cannot be included in development splits: {sorted(reserved_overlap)}")
    feature_module = (__import__(f"integrityguard.network_flow_schema_v{args.feature_version}",
                                fromlist=["FEATURE_NAMES"]))
    feature_names = feature_module.FEATURE_NAMES
    loss_tag = f"-focal{args.focal_gamma:g}" if args.model == "mlp" and args.focal_gamma > 0 else ""
    lr_tag = f"-lr{args.learning_rate:g}" if args.model == "mlp" and args.learning_rate != 3e-4 else ""
    width_tag = f"-width{args.hidden_width}" if args.model == "mlp" and args.hidden_width != 128 else ""
    weight_tag = f"-weight{args.capture_weighting}" if args.capture_weighting != "equal" else ""
    seed_tag = f"-seed{args.seed}" if args.seed != SEED else ""
    train_cap_tag = f"-cap{args.max_per_class if args.max_per_class is not None else 'all'}"
    val_cap_tag = f"-valcap{args.validation_max_per_class if args.validation_max_per_class is not None else 'all'}"
    output = DATA / "iot23-unified" / (
        f"{args.split}-v{args.feature_version}-{args.model}{loss_tag}{lr_tag}{width_tag}{weight_tag}"
        f"{train_cap_tag}{val_cap_tag}{seed_tag}")
    output.mkdir(parents=True, exist_ok=True)
    train_x, train_y, train_capture_ids, hashes, counts = [], [], [], {}, {}
    for capture_id in train_ids:
        clean = capture_id in IOT_CLEAN
        x, y, c, digest = load_iot_capture(capture_id, IOT_FILES[capture_id],
            args.feature_version, args.max_per_class, args.seed, capture_clean=clean)
        train_x.append(x); train_y.append(y)
        train_capture_ids.append(np.full(len(y), capture_id, dtype=object))
        hashes[capture_id] = digest; counts[capture_id] = c
        print("train", capture_id, c, flush=True)
    x_train, y_train = np.concatenate(train_x), np.concatenate(train_y)
    capture_ids_train = np.concatenate(train_capture_ids)
    sample_weights = capture_balanced_sample_weights(y_train, capture_ids_train,
                                                     args.capture_weighting)
    val_limit = args.validation_max_per_class
    val_x, val_y, val_counts, val_hashes = [], [], {}, {}
    for validation_id in validation_ids:
        x, y, c, digest = load_iot_capture(validation_id, IOT_FILES[validation_id],
            args.feature_version, val_limit, args.seed, capture_clean=validation_id in IOT_CLEAN)
        val_x.append(x); val_y.append(y); val_counts[validation_id] = c; val_hashes[validation_id] = digest
        print("validation", validation_id, c, flush=True)
    x_val, y_val = np.concatenate(val_x), np.concatenate(val_y)

    # One model-family switch and one feature-version switch keep every
    # comparison under the same parser, label policy, split, and report code.
    mean = scale = None
    if args.model == "mlp":
        mean = np.median(x_train, axis=0)
        q25, q75 = np.percentile(x_train, [25, 75], axis=0)
        scale = np.maximum(q75 - q25, 1e-6)
        x_train = np.clip((x_train - mean) / scale, -10.0, 10.0).astype(np.float32)
        x_val = np.clip((x_val - mean) / scale, -10.0, 10.0).astype(np.float32)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        seed_everything(args.seed)
        model = MLP(len(feature_names), args.hidden_width).to(device)
        loader = DataLoader(TensorDataset(torch.from_numpy(x_train), torch.from_numpy(y_train),
            torch.from_numpy(sample_weights)), batch_size=BATCH_SIZE, shuffle=True,
            generator=torch.Generator().manual_seed(args.seed), num_workers=0,
            pin_memory=device.type == "cuda")
        x_val_tensor = torch.from_numpy(x_val).to(device)
        y_val_tensor = torch.from_numpy(y_val).to(device)
        optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=1e-4)
        loss_fn = nn.CrossEntropyLoss(reduction="none")
        best_loss, best_epoch, stale, best_state = float("inf"), 0, 0, None
        best_gate_key = (-1.0, -1.0, -float("inf"))
        best_gate_point = None
        for epoch in range(1, args.epochs + 1):
            model.train()
            for bx, by, bw in loader:
                bx, by, bw = bx.to(device), by.to(device), bw.to(device)
                optimizer.zero_grad(set_to_none=True)
                per_item_loss = loss_fn(model(bx), by)
                if args.focal_gamma > 0:
                    pt = torch.exp(-per_item_loss)
                    per_item_loss = per_item_loss * torch.pow(1.0 - pt, args.focal_gamma)
                loss = (per_item_loss * bw).mean()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
                optimizer.step()
            model.eval()
            with torch.no_grad():
                validation_logits = model(x_val_tensor)
                per_item_val = loss_fn(validation_logits, y_val_tensor)
                capture_losses = []
                offset = 0
                for capture_y in val_y:
                    capture_len = len(capture_y)
                    capture_loss = per_item_val[offset:offset + capture_len]
                    capture_labels = y_val_tensor[offset:offset + capture_len]
                    offset += capture_len
                    present_classes = []
                    for class_id in (0, 1):
                        class_mask = capture_labels == class_id
                        if bool(class_mask.any()):
                            present_classes.append(capture_loss[class_mask].mean())
                    if present_classes:
                        capture_losses.append(torch.stack(present_classes).mean())
                val_loss = float(torch.stack(capture_losses).mean().item())
                epoch_scores = torch.softmax(validation_logits, dim=1)[:, 1].cpu().numpy().astype(np.float64)
            epoch_gate_point = select_joint_capture_threshold(epoch_scores, validation_ids, val_y,
                                                               args.fpr_ci_ceiling)
            gate_lcb = epoch_gate_point["minimum_recall_ci95_lower"] if epoch_gate_point else -1.0
            gate_mean_recall = epoch_gate_point["mean_recall"] if epoch_gate_point else -1.0
            gate_key = (gate_lcb, gate_mean_recall, -val_loss)
            if gate_key > best_gate_key:
                best_gate_key = gate_key
                best_loss, best_epoch, stale = val_loss, epoch, 0
                best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                best_gate_point = epoch_gate_point
            else:
                stale += 1
            if epoch == 1 or epoch % 10 == 0:
                print("mlp", "epoch", epoch, "validation_nll", round(val_loss, 6),
                      "joint_min_recall_lcb", round(gate_lcb, 6),
                      "joint_mean_recall", round(gate_mean_recall, 6),
                      "best_epoch", best_epoch, flush=True)
            if stale >= PATIENCE:
                break
        model.load_state_dict(best_state); model.to(device); model.eval()
        predicted_scores = []
        with torch.no_grad():
            for start in range(0, len(x_val), 65536):
                logits = model(torch.from_numpy(x_val[start:start + 65536]).to(device))
                predicted_scores.extend(torch.softmax(logits, dim=1)[:, 1].cpu().numpy().tolist())
        scores = np.asarray(predicted_scores, dtype=np.float64)
        model_result = {"best_epoch": best_epoch, "validation_nll": best_loss,
            "selection_metric": "maximize minimum per-capture recall lower 95% Wilson bound under per-capture FPR upper 95% Wilson ceiling; tie-break by mean recall, then NLL",
            "best_joint_capture_operating_point": best_gate_point}
    elif args.model == "extra_trees":
        model = ExtraTreesClassifier(n_estimators=args.trees, min_samples_leaf=args.min_leaf,
            max_features=args.max_features, n_jobs=-1, random_state=args.seed)
    elif args.model == "random_forest":
        model = RandomForestClassifier(n_estimators=args.trees, min_samples_leaf=args.min_leaf,
            max_features=args.max_features, n_jobs=-1, class_weight="balanced_subsample",
            random_state=args.seed)
    elif args.model == "hist_gradient_boosting":
        model = HistGradientBoostingClassifier(max_iter=args.trees, max_leaf_nodes=31,
            learning_rate=.08, l2_regularization=1.0, random_state=args.seed)
    else:
        raise ValueError(f"Unsupported IoT model: {args.model}")
    started = time.time()
    if args.model != "mlp":
        model.fit(x_train, y_train, sample_weight=sample_weights)
        scores = model.predict_proba(x_val)[:, 1].astype(np.float64)
        model_result = {}
    thresholds = np.unique(scores)[::-1]
    thresholds = np.r_[np.nextafter(thresholds[0], np.inf), thresholds]
    best, best_recall = None, -1.0
    for threshold in thresholds:
        predicted = scores >= threshold
        attack = y_val == 1
        tp = int(np.count_nonzero(predicted & attack)); fn = int(np.count_nonzero(~predicted & attack))
        fp = int(np.count_nonzero(predicted & ~attack)); tn = int(np.count_nonzero(~predicted & ~attack))
        fpr_upper = float(wilson_upper(np.asarray([fp]), np.asarray([fp + tn]))[0])
        recall = tp / (tp + fn) if tp + fn else 0.0
        if fpr_upper <= args.fpr_ci_ceiling and recall > best_recall:
            best_recall = recall
            best = {"threshold": float(threshold), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                    "recall": recall, "recall_ci95_lower": float(1.0 - wilson_upper(
                        np.asarray([fn]), np.asarray([tp + fn]))[0]),
                    "fpr": fp / (fp + tn) if fp + tn else 1.0,
                    "fpr_ci95_upper": fpr_upper}
    joint_best = select_joint_capture_threshold(scores, validation_ids, val_y,
                                                args.fpr_ci_ceiling)
    selected_threshold = (joint_best["threshold"] if joint_best is not None
                          else best["threshold"] if best is not None else None)
    training_config = {
        "seed": args.seed, "max_per_class_per_capture": args.max_per_class,
        "validation_max_per_class_per_capture": args.validation_max_per_class,
        "max_epochs": args.epochs, "patience": PATIENCE,
        "batch_size": BATCH_SIZE, "include_clean_captures": args.include_clean,
        "fpr_ci_ceiling": args.fpr_ci_ceiling, "learning_rate": args.learning_rate,
        "capture_weighting": args.capture_weighting, "hidden_width": args.hidden_width,
    }
    loss_config = {"name": "focal" if args.focal_gamma > 0 else "cross_entropy",
                   "focal_gamma": args.focal_gamma}
    if args.model == "mlp":
        checkpoint_path = output / "candidate-mlp.pt"
        torch.save({"state_dict": {k: v.cpu() for k, v in model.state_dict().items()},
            "feature_version": args.feature_version, "feature_names": list(feature_names),
            "classes": ["benign", "attack"], "mean": mean.tolist(), "scale": scale.tolist(),
            "threshold": selected_threshold, "training_sha256": hashes,
            "validation_sha256": val_hashes, "dataset": "official IoT-23 v2",
            "split_name": args.split, "model": args.model,
            "hidden_width": args.hidden_width,
            "training_config": training_config, "loss": loss_config,
            "research_only": True, "promotion_eligible": False},
            checkpoint_path)
    else:
        checkpoint_path = output / f"candidate-{args.model}.joblib"
        joblib.dump({"estimator": model, "feature_version": args.feature_version,
            "feature_names": list(feature_names), "classes": ["benign", "attack"],
            "threshold": selected_threshold, "training_sha256": hashes,
            "validation_sha256": val_hashes, "dataset": "official IoT-23 v2",
            "split_name": args.split, "model": args.model,
            "hidden_width": args.hidden_width,
            "training_config": training_config, "loss": loss_config, "research_only": True,
            "promotion_eligible": False}, checkpoint_path)
    curve = score_curve(scores, y_val)
    with (output / "validation_curve.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["threshold", "recall", "fpr", "fpr_ci95_upper", "tp", "fp"])
        for i in range(len(curve[0])):
            writer.writerow([float(curve[0][i]), float(curve[1][i]), float(curve[2][i]),
                             float(curve[3][i]), int(curve[4][i]), int(curve[5][i])])
    metrics = {"auc": float(roc_auc_score(y_val, scores)),
               "average_precision": float(average_precision_score(y_val, scores))}
    validation_metrics_per_capture = {}
    validation_per_capture = {}
    validation_per_capture_best = {}
    offset = 0
    for capture_id, capture_y in zip(validation_ids, val_y):
        n = len(capture_y)
        local_scores = scores[offset:offset + n]
        offset += n
        local_attack_scores = local_scores[capture_y == 1]
        local_benign_scores = local_scores[capture_y == 0]
        validation_metrics_per_capture[capture_id] = {
            "attack_count": int(len(local_attack_scores)),
            "benign_count": int(len(local_benign_scores)),
            "auc": (float(roc_auc_score(capture_y, local_scores))
                    if len(local_attack_scores) and len(local_benign_scores) else None),
            "average_precision": (float(average_precision_score(capture_y, local_scores))
                                  if len(local_attack_scores) and len(local_benign_scores) else None),
            "attack_score_quantiles": {
                str(q): float(np.quantile(local_attack_scores, q))
                for q in (0.0, 0.5, 0.9, 0.99, 0.999, 1.0)
            } if len(local_attack_scores) else {},
            "benign_score_quantiles": {
                str(q): float(np.quantile(local_benign_scores, q))
                for q in (0.0, 0.5, 0.9, 0.99, 0.999, 1.0)
            } if len(local_benign_scores) else {},
        }
        local_curve = score_curve(local_scores, capture_y)
        local_eligible = np.flatnonzero(local_curve[3] <= args.fpr_ci_ceiling)
        local_best = None
        if len(local_eligible):
            local_i = int(local_eligible[np.argmax(local_curve[1][local_eligible])])
            local_tp = int(local_curve[4][local_i]); local_fp = int(local_curve[5][local_i])
            local_attack_n = int(np.count_nonzero(capture_y == 1))
            local_benign_n = int(np.count_nonzero(capture_y == 0))
            local_fn, local_tn = local_attack_n - local_tp, local_benign_n - local_fp
            local_best = {
                "threshold": float(local_curve[0][local_i]), "tp": local_tp, "fp": local_fp,
                "fn": local_fn, "tn": local_tn,
                "recall": local_tp / local_attack_n if local_attack_n else None,
                "recall_ci95_lower": (1.0 - float(wilson_upper(np.asarray([local_fn]),
                    np.asarray([local_attack_n]))[0])) if local_attack_n else None,
                "fpr": local_fp / local_benign_n if local_benign_n else None,
                "fpr_ci95_upper": float(local_curve[3][local_i]),
                "sample_gate_met": (local_attack_n >= MIN_RELEASE_ATTACK_SUPPORT
                                    and local_benign_n >= MIN_BENIGN_SUPPORT_ZERO_FP),
            }
        validation_per_capture_best[capture_id] = local_best

    offset = 0
    if selected_threshold is not None:
        offset = 0
        for capture_id, capture_x, capture_y in zip(validation_ids, val_x, val_y):
            n = len(capture_y)
            local_scores = scores[offset:offset + n]
            offset += n
            local_pred = local_scores >= selected_threshold
            local_attack = capture_y == 1
            local_tp = int(np.count_nonzero(local_pred & local_attack))
            local_fn = int(np.count_nonzero(~local_pred & local_attack))
            local_fp = int(np.count_nonzero(local_pred & ~local_attack))
            local_tn = int(np.count_nonzero(~local_pred & ~local_attack))
            local_attack_n, local_benign_n = local_tp + local_fn, local_fp + local_tn
            validation_per_capture[capture_id] = {
                "tp": local_tp, "fp": local_fp, "fn": local_fn, "tn": local_tn,
                "recall": local_tp / local_attack_n if local_attack_n else None,
                "recall_ci95_lower": (1.0 - float(wilson_upper(np.asarray([local_fn]),
                    np.asarray([local_attack_n]))[0])) if local_attack_n else None,
                "fpr": local_fp / local_benign_n if local_benign_n else None,
                "fpr_ci95_upper": float(wilson_upper(np.asarray([local_fp]),
                    np.asarray([local_benign_n]))[0]) if local_benign_n else None,
            }
    manifest = {"dataset": "official IoT-23 v2 whole-capture split",
        "feature_version": args.feature_version, "feature_names": list(feature_names),
        "label_policy": "published malicious/benign only; publisher-designated clean captures benign; unknown excluded",
        "split": {"train": train_ids, "validation": validation_ids,
                  "reserved_test": f"{', '.join(sorted(IOT_RESERVED_TEST_IDS))}; pinned and excluded from training/validation"},
        "training_counts": counts, "training_sha256": hashes,
        "validation_counts": val_counts, "validation_sha256": val_hashes,
        "model": args.model, "operating_point": best,
        "joint_capture_operating_point": joint_best,
        "selected_checkpoint_threshold": selected_threshold,
        "training_config": training_config, "loss": loss_config,
        "training_weighting": f"{args.capture_weighting} capture mass within each class; class totals equal",
        "model_training": model_result,
        "validation_metrics_per_capture": validation_metrics_per_capture,
        "validation_per_capture_at_selected_threshold": validation_per_capture,
        "validation_per_capture_best_at_fpr_ci_ceiling": validation_per_capture_best,
        **metrics,
        "checkpoint": checkpoint_path.name, "checkpoint_sha256": sha256_file(checkpoint_path),
        "elapsed_seconds": round(time.time() - started, 2),
        "promotion_eligible": False,
        "warning": "Development only; a reused validation capture is not independent release evidence."}
    (output / "summary.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2), flush=True)


def evaluate_iot23_candidate(args) -> None:
    """Stream a fixed candidate over one whole labeled capture once."""
    candidate_path = Path(args.candidate).resolve()
    model = None
    mean = scale = None
    if candidate_path.suffix.lower() == ".pt":
        artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    else:
        import joblib
        artifact = joblib.load(candidate_path)
    feature_version = int(artifact["feature_version"])
    if feature_version not in (9, 10):
        raise ValueError("Candidate has an unsupported IoT feature version")
    if args.capture not in IOT_RESERVED_TEST_IDS:
        raise ValueError(f"One-pass independent candidate evaluation requires a reserved whole capture: {sorted(IOT_RESERVED_TEST_IDS)}")
    path = IOT_FILES[args.capture]
    if not path.is_file():
        raise FileNotFoundError(path)
    trained_hashes = artifact.get("training_sha256", artifact.get("training_capture_hashes", {}))
    if args.capture in trained_hashes:
        raise ValueError(f"Reserved test capture {args.capture} is present in the candidate training manifest")
    if not args.expected_sha256:
        raise ValueError("A pinned expected capture SHA-256 is required for one-pass evaluation")
    schema = __import__(f"integrityguard.network_flow_schema_v{feature_version}", fromlist=["from_zeek_row"])
    if artifact.get("feature_names") != list(schema.FEATURE_NAMES) \
            or artifact.get("classes") != ["benign", "attack"]:
        raise ValueError("Candidate feature/class schema does not match the selected capture parser")
    estimator = artifact.get("estimator")
    if estimator is None:
        model = MLP(len(artifact["feature_names"]), int(artifact.get("hidden_width", 128)))
        model.load_state_dict(artifact["state_dict"])
        model.eval()
        mean = np.asarray(artifact["mean"], dtype=np.float32)
        scale = np.asarray(artifact["scale"], dtype=np.float32)
    threshold = float(artifact["threshold"])
    expected = args.expected_sha256.upper() if args.expected_sha256 else None
    digest = hashlib.sha256()
    counts = {"attack": 0, "benign": 0, "unknown": 0, "invalid": 0}
    tp = fp = fn = tn = 0
    batch_x, batch_y, batch_details = [], [], []
    per_publisher_label = {}

    def score_batch():
        nonlocal tp, fp, fn, tn
        if not batch_x:
            return
        values = np.asarray(batch_x, dtype=np.float32)
        if model is not None:
            values = np.clip((values - mean) / scale, -10.0, 10.0).astype(np.float32)
            with torch.no_grad():
                probabilities = torch.softmax(model(torch.from_numpy(values)), dim=1)[:, 1].numpy()
        else:
            probabilities = estimator.predict_proba(values)[:, 1]
        pred = probabilities >= threshold
        actual = np.asarray(batch_y, dtype=np.int8) == 1
        tp += int(np.count_nonzero(pred & actual)); fp += int(np.count_nonzero(pred & ~actual))
        fn += int(np.count_nonzero(~pred & actual)); tn += int(np.count_nonzero(~pred & ~actual))
        for category, is_attack, is_predicted_attack in zip(batch_details, actual, pred):
            item = per_publisher_label.setdefault(category, {"flows": 0, "predicted_attack": 0})
            item["flows"] += 1
            item["predicted_attack"] += int(is_predicted_attack)
            if is_attack:
                item["attack_flows"] = item.get("attack_flows", 0) + 1
                item["detected_attacks"] = item.get("detected_attacks", 0) + int(is_predicted_attack)
            else:
                item["benign_flows"] = item.get("benign_flows", 0) + 1
                item["false_positives"] = item.get("false_positives", 0) + int(is_predicted_attack)
        batch_x.clear(); batch_y.clear(); batch_details.clear()

    for capture_label, raw_path in ((args.capture, path),):
        with raw_path.open("rb") as stream:
            for raw_line in stream:
                digest.update(raw_line)
                if not raw_line or raw_line.startswith(b"#"):
                    continue
                try:
                    columns = raw_line.decode("utf-8", errors="replace").rstrip("\r\n").split("\t")
                    label = label_for_zeek(columns)
                    if label == "malicious":
                        target = 1
                    elif label == "benign":
                        target = 0
                    else:
                        counts["unknown"] += 1
                        continue
                    vector = schema.from_zeek_row(columns)
                    label_tail = columns[-1].strip().split() if columns else []
                    detail = label_tail[-1] if len(label_tail) >= 3 and label_tail[-1] != "-" else "unspecified"
                except (TypeError, ValueError, IndexError, OverflowError):
                    counts["invalid"] += 1
                    continue
                counts["attack" if target else "benign"] += 1
                batch_x.append(vector); batch_y.append(target)
                batch_details.append(f"{'malicious' if target else 'benign'}::{detail}")
                if len(batch_x) >= 8192:
                    score_batch()
        score_batch()
    capture_hash = digest.hexdigest().upper()
    if capture_hash != expected:
        raise ValueError(
            f"Capture SHA-256 mismatch ({capture_hash} != {expected}); "
            "evaluation metrics were not written")
    n_attack, n_benign = tp + fn, fp + tn
    recall = tp / n_attack if n_attack else 0.0
    fpr = fp / n_benign if n_benign else 1.0
    recall_lower = 1.0 - float(wilson_upper(np.asarray([fn]), np.asarray([n_attack]))[0]) if n_attack else 0.0
    fpr_upper = float(wilson_upper(np.asarray([fp]), np.asarray([n_benign]))[0]) if n_benign else 1.0
    report = {"dataset": "official IoT-23 v2",
        "capture": capture_label, "capture_source_url": IOT_CAPTURE_SOURCE_URLS.get(capture_label),
        "label_source": "publisher-provided expert label on Zeek flow; explicit Benign/Malicious only",
        "capture_role": "reserved whole-capture source test; excluded from candidate training and validation",
        "capture_sha256": capture_hash,
        "expected_sha256": expected, "capture_hash_matches_expected": capture_hash == expected,
        "candidate_sha256": sha256_file(candidate_path), "feature_version": feature_version,
        "candidate_split": artifact.get("split_name"),
        "candidate_training_captures": sorted(trained_hashes),
        "candidate_validation_captures": sorted(artifact.get("validation_sha256", {}).keys()),
        "threshold_source": "candidate checkpoint threshold selected on validation; not modified for this test",
        "threshold": threshold, "counts": counts,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "per_publisher_label": per_publisher_label,
        "recall": recall, "recall_ci95_lower": recall_lower, "fpr": fpr,
        "fpr_ci95_upper": fpr_upper,
        "minimum_sample_gate_met": (n_attack >= MIN_RELEASE_ATTACK_SUPPORT
                                     and n_benign >= MIN_BENIGN_SUPPORT_ZERO_FP),
        "recall_gate_met": recall_lower >= .80, "fpr_gate_met": fpr_upper <= RELEASE_FPR_CI_CEILING,
        "research_only": True, "promotion_eligible": False}
    report_path = candidate_path.with_name(f"{args.capture}-one-pass-evaluation.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_ctu_sme11_candidate(args) -> None:
    """One-pass independent scoring of an expert-labeled CTU-SME-11 archive."""
    candidate_path = Path(args.candidate).resolve()
    archive_path = CTU_SME11_EVAL_ARCHIVES[args.capture]
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    configure_feature_schema(int(artifact.get("feature_version", -1)))
    if artifact.get("feature_version") != FEATURE_VERSION \
            or artifact.get("feature_names") != list(FEATURE_NAMES) \
            or artifact.get("classes") != ["benign", "attack"]:
        raise ValueError("Candidate feature/class schema does not match CTU-SME-11 flow adapter")
    if args.threshold is None or not math.isfinite(args.threshold) or not 0 <= args.threshold <= 1:
        raise ValueError("Supply the frozen validation threshold with --threshold")
    trained = set(artifact.get("training_captures", []))
    if "CTU-SME-11-Windows7AD-1" in trained:
        raise ValueError("The independent CTU-SME-11 capture appears in training provenance")
    expected = str(args.expected_sha256 or "").upper()
    if len(expected) != 64 or any(c not in "0123456789ABCDEF" for c in expected):
        raise ValueError("A pinned 64-character expected archive SHA-256 is required")
    archive_sha = sha256_file(archive_path).upper()
    if archive_sha != expected:
        raise ValueError("Archive SHA-256 mismatch; test metrics were not calculated")
    md5 = hashlib.md5()
    with archive_path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            md5.update(chunk)
    source_md5 = md5.hexdigest()
    if source_md5 != CTU_SME11_EVAL_MD5[args.capture]:
        raise ValueError("Archive MD5 differs from the publisher's Zenodo checksum")

    model = MLP(len(FEATURE_NAMES), int(artifact.get("hidden_width", 128)))
    model.load_state_dict(artifact["state_dict"])
    model.eval()
    mean = np.asarray(artifact["mean"], dtype=np.float32)
    scale = np.asarray(artifact["scale"], dtype=np.float32)
    days: dict[str, dict] = {}
    active_day = "unknown"
    batch_x: list[list[float]] = []
    batch_y: list[int] = []

    def day_record(day: str) -> dict:
        return days.setdefault(day, {"flow_rows": 0, "benign": 0, "malicious": 0,
            "background_or_unknown_excluded": 0, "incomplete_excluded": 0,
            "explicit_labeled_rows": 0, "explicit_labeled_incomplete_excluded": 0,
            "tp": 0, "fp": 0, "fn": 0, "tn": 0})

    def score_batch(day: str) -> None:
        if not batch_x:
            return
        x = np.asarray(batch_x, dtype=np.float32)
        x = np.clip((x - mean) / scale, -10.0, 10.0).astype(np.float32)
        with torch.no_grad():
            probabilities = torch.softmax(model(torch.from_numpy(x)), dim=1)[:, 1].numpy()
        truth = np.asarray(batch_y, dtype=np.int8) == 1
        predicted = probabilities >= float(args.threshold)
        record = day_record(day)
        record["tp"] += int(np.count_nonzero(truth & predicted))
        record["fp"] += int(np.count_nonzero(~truth & predicted))
        record["fn"] += int(np.count_nonzero(truth & ~predicted))
        record["tn"] += int(np.count_nonzero(~truth & ~predicted))
        batch_x.clear(); batch_y.clear()

    with tarfile.open(archive_path, mode="r|bz2") as archive:
        for member in archive:
            if not member.isfile() or not member.name.endswith("/zeek/conn.log.labeled"):
                continue
            active_day = next((part for part in member.name.split("/")
                               if part.startswith("2023-02-")), "unknown")
            record = day_record(active_day)
            fields = None
            stream = archive.extractfile(member)
            if stream is None:
                continue
            for raw in stream:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.startswith("#fields\t"):
                    fields = line.split("\t")[1:]
                    continue
                if not line or line.startswith("#") or fields is None:
                    continue
                record["flow_rows"] += 1
                values = line.split("\t")
                row = dict(zip(fields, values))
                label = (row.get("label") or "").strip().lower()
                if label not in {"benign", "malicious"}:
                    record["background_or_unknown_excluded"] += 1
                    continue
                record["explicit_labeled_rows"] += 1
                if len(values) != len(fields):
                    record["incomplete_excluded"] += 1
                    record["explicit_labeled_incomplete_excluded"] += 1
                    continue
                try:
                    duration = row.get("duration")
                    packets = float(row.get("orig_pkts", "-")) + float(row.get("resp_pkts", "-"))
                    source_bytes = float(row.get("orig_ip_bytes", "-"))
                    destination_bytes = float(row.get("resp_ip_bytes", "-"))
                    vector = feature_vector(duration, packets, source_bytes + destination_bytes,
                                            source_bytes, destination_bytes, row.get("proto"))
                except (TypeError, ValueError, OverflowError):
                    record["incomplete_excluded"] += 1
                    record["explicit_labeled_incomplete_excluded"] += 1
                    continue
                record[label] += 1
                batch_x.append(vector); batch_y.append(int(label == "malicious"))
                if len(batch_x) >= 8192:
                    score_batch(active_day)
            score_batch(active_day)

    totals = {key: sum(item[key] for item in days.values()) for key in
              ("flow_rows", "benign", "malicious", "background_or_unknown_excluded",
               "incomplete_excluded", "explicit_labeled_rows",
               "explicit_labeled_incomplete_excluded", "tp", "fp", "fn", "tn")}
    if not totals["benign"] or not totals["malicious"]:
        raise ValueError("CTU-SME-11 archive did not contain both explicit labeled classes")

    def metrics(counts: dict) -> dict:
        attacks = counts["tp"] + counts["fn"]
        benign = counts["fp"] + counts["tn"]
        recall_lower = (1.0 - float(wilson_upper(np.asarray([counts["fn"]]),
                                                   np.asarray([attacks]))[0]) if attacks else None)
        fpr_upper = (float(wilson_upper(np.asarray([counts["fp"]]),
                                         np.asarray([benign]))[0]) if benign else None)
        return {"attack_flows": attacks, "benign_flows": benign,
            "recall": counts["tp"] / attacks if attacks else None,
            "recall_ci95_lower": recall_lower,
            "fpr": counts["fp"] / benign if benign else None,
            "fpr_ci95_upper": fpr_upper,
            "minimum_sample_gate_met": attacks >= 100 and benign >= MIN_BENIGN_SUPPORT_ZERO_FP,
            "recall_gate_met": recall_lower is not None and recall_lower >= .80,
            "fpr_gate_met": fpr_upper is not None and fpr_upper <= RELEASE_FPR_CI_CEILING}

    per_day = {day: {"counts": counts, "metrics": metrics(counts)}
               for day, counts in sorted(days.items())}
    report = {"dataset": "CTU-SME-11", "capture": args.capture,
        "capture_role": "one-pass independent seven-day source-test; not used for training or threshold selection",
        "capture_source_url": "https://zenodo.org/records/7958259/files/CTU-SME-11_Experiment-VM-Microsoft-Windows7AD-1_v1.0.0.tar.bz2?download=1",
        "label_source": "publisher-provided expert labels in Zeek conn.log.labeled; explicit benign/malicious only; background/unknown excluded",
        "feature_adapter": "Zeek duration, orig/resp IP bytes and packets mapped to the existing v8 flow feature contract",
        "archive_size_bytes": archive_path.stat().st_size,
        "archive_sha256": archive_sha, "publisher_md5": source_md5,
        "publisher_md5_matches": source_md5 == CTU_SME11_EVAL_MD5[args.capture],
        "candidate_sha256": sha256_file(candidate_path),
        "candidate_training_captures": artifact.get("training_captures", []),
        "candidate_validation_captures": artifact.get("validation_capture", []),
        "threshold_source": "fixed validation-45 threshold; no test-driven adjustment",
        "threshold": float(args.threshold), "counts": totals,
        "confusion": {key: totals[key] for key in ("tp", "fp", "fn", "tn")},
        "coverage": {
            "explicitly_labeled_rows": totals["explicit_labeled_rows"],
            "scored_explicitly_labeled_rows": totals["benign"] + totals["malicious"],
            "explicitly_labeled_but_incomplete_rows": totals["explicit_labeled_incomplete_excluded"],
            "scored_fraction_of_explicitly_labeled_rows":
                (totals["benign"] + totals["malicious"]) / max(totals["explicit_labeled_rows"], 1),
            "explicit_label_fraction_of_all_flow_rows":
                totals["explicit_labeled_rows"] / max(totals["flow_rows"], 1),
            "scored_fraction_of_all_flow_rows":
                (totals["benign"] + totals["malicious"]) / max(totals["flow_rows"], 1),
        },
        "metrics": metrics(totals), "per_day": per_day,
        "research_only": True, "promotion_eligible": False,
        "enforcement_applied": False}
    report_path = candidate_path.with_name("ctu-sme11-win7ad1-independent-evaluation.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_ctu_sme11_live_v3(args) -> None:
    """Registered one-pass source-family evaluation for the deployed v3 model."""
    from integrityguard.network_flow_model import (
        FLOW_V3_FEATURE_NAMES, _FlowV3AutoencoderClassifier,
    )

    candidate_path = Path(args.candidate).resolve()
    archive_path = CTU_SME11_EVAL_ARCHIVES[args.capture]
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    candidate_sha = sha256_file(candidate_path).lower()
    expected_candidate = str(args.expected_candidate_sha256 or "").lower()
    if len(expected_candidate) != 64 or candidate_sha != expected_candidate:
        raise ValueError("Candidate SHA-256 is missing or differs from its pre-registration")
    if artifact.get("feature_version") != 3 or artifact.get("features") != list(FLOW_V3_FEATURE_NAMES) \
            or artifact.get("classes") != ["benign", "attack"]:
        raise ValueError("Checkpoint schema does not match the deployed v3 classifier")
    if "CTU-SME-11-Windows7AD-1" in artifact.get("train_captures", []):
        raise ValueError("Independent CTU-SME-11 capture appears in v3 training provenance")
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)
    expected_archive = str(args.expected_sha256 or "").lower()
    archive_sha = sha256_file(archive_path).lower()
    if len(expected_archive) != 64 or archive_sha != expected_archive:
        raise ValueError("Archive SHA-256 mismatch; scoring was not started")
    md5 = hashlib.md5()
    with archive_path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            md5.update(block)
    publisher_md5 = md5.hexdigest()
    if publisher_md5 != CTU_SME11_EVAL_MD5[args.capture]:
        raise ValueError("Archive differs from the publisher's pinned MD5")
    if args.threshold is None or not math.isfinite(args.threshold) or not 0 <= args.threshold <= 1:
        raise ValueError("Supply the frozen v3 validation threshold")

    registration_path = Path(args.registration_file or "").resolve()
    if not registration_path.is_file():
        raise ValueError("Pre-existing registration file is required for this one-pass test")
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    manifest_path = candidate_path.with_name("network_flow_v3_candidate_manifest.json")
    expected_registration = {
        "capture": args.capture,
        "capture_sha256": archive_sha,
        "publisher_md5": publisher_md5,
        "candidate_sha256": candidate_sha,
        "candidate_manifest_sha256": sha256_file(manifest_path),
        "threshold": float(args.threshold),
        "evaluator_sha256": sha256_file(Path(__file__).resolve()),
        "label_policy": "publisher Zeek benign/malicious only; background and unknown excluded",
        "purpose": "one-pass independent source-family evaluation; no tuning on this capture",
    }
    if any(registration.get(key) != value for key, value in expected_registration.items()):
        raise ValueError("Registration does not match candidate, capture, threshold, labels, or evaluator")

    configure_feature_schema(8)
    mean = torch.as_tensor(artifact["mean"], dtype=torch.float32)
    std = torch.as_tensor(artifact["std"], dtype=torch.float32)
    if mean.numel() != len(FLOW_V3_FEATURE_NAMES) or std.numel() != len(FLOW_V3_FEATURE_NAMES):
        raise ValueError("Checkpoint normalization dimensions do not match v3 features")
    model = _FlowV3AutoencoderClassifier()
    model.load_state_dict(artifact["state_dict"])
    model.eval()

    days: dict[str, dict] = {}
    active_day = "unknown"
    batch_x: list[list[float]] = []
    batch_y: list[int] = []

    def day_record(day: str) -> dict:
        return days.setdefault(day, {"flow_rows": 0, "benign": 0, "malicious": 0,
            "background_or_unknown_excluded": 0, "incomplete_excluded": 0,
            "explicit_labeled_rows": 0, "explicit_labeled_incomplete_excluded": 0,
            "tp": 0, "fp": 0, "fn": 0, "tn": 0})

    def score_batch(day: str) -> None:
        if not batch_x:
            return
        values = (torch.as_tensor(np.asarray(batch_x, dtype=np.float32)) - mean) / torch.where(
            std.abs() < 1e-6, torch.ones_like(std), std)
        with torch.no_grad():
            scores = torch.softmax(model(values)[1], dim=1)[:, 1].numpy()
        truth = np.asarray(batch_y, dtype=np.int8) == 1
        predicted = scores >= float(args.threshold)
        counts = day_record(day)
        counts["tp"] += int(np.count_nonzero(truth & predicted))
        counts["fp"] += int(np.count_nonzero(~truth & predicted))
        counts["fn"] += int(np.count_nonzero(truth & ~predicted))
        counts["tn"] += int(np.count_nonzero(~truth & ~predicted))
        batch_x.clear(); batch_y.clear()

    with tarfile.open(archive_path, mode="r|bz2") as archive:
        for member in archive:
            if not member.isfile() or not member.name.endswith("/zeek/conn.log.labeled"):
                continue
            active_day = next((part for part in member.name.split("/")
                               if part.startswith("2023-02-")), "unknown")
            counts = day_record(active_day)
            stream = archive.extractfile(member)
            if stream is None:
                continue
            fields = None
            for raw in stream:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.startswith("#fields\t"):
                    fields = line.split("\t")[1:]
                    continue
                if not line or line.startswith("#") or fields is None:
                    continue
                counts["flow_rows"] += 1
                values = line.split("\t")
                row = dict(zip(fields, values))
                label = (row.get("label") or "").strip().lower()
                if label not in {"benign", "malicious"}:
                    counts["background_or_unknown_excluded"] += 1
                    continue
                counts["explicit_labeled_rows"] += 1
                if len(values) != len(fields):
                    counts["incomplete_excluded"] += 1
                    counts["explicit_labeled_incomplete_excluded"] += 1
                    continue
                try:
                    duration = row.get("duration")
                    packets = float(row.get("orig_pkts", "-")) + float(row.get("resp_pkts", "-"))
                    source_bytes = float(row.get("orig_ip_bytes", "-"))
                    destination_bytes = float(row.get("resp_ip_bytes", "-"))
                    vector = feature_vector(duration, packets, source_bytes + destination_bytes,
                                            source_bytes, destination_bytes, row.get("proto"))
                except (TypeError, ValueError, OverflowError):
                    counts["incomplete_excluded"] += 1
                    counts["explicit_labeled_incomplete_excluded"] += 1
                    continue
                vector = vector[:len(FLOW_V3_FEATURE_NAMES)]
                counts[label] += 1
                batch_x.append(vector); batch_y.append(int(label == "malicious"))
                if len(batch_x) >= 8192:
                    score_batch(active_day)
            score_batch(active_day)

    totals = {key: sum(item[key] for item in days.values()) for key in
              ("flow_rows", "benign", "malicious", "background_or_unknown_excluded",
               "incomplete_excluded", "explicit_labeled_rows",
               "explicit_labeled_incomplete_excluded", "tp", "fp", "fn", "tn")}
    if not totals["benign"] or not totals["malicious"]:
        raise ValueError("CTU-SME-11 archive did not contain both explicit labeled classes")

    def metrics(counts: dict) -> dict:
        attacks = counts["tp"] + counts["fn"]
        benign = counts["fp"] + counts["tn"]
        recall_lower = (1.0 - float(wilson_upper(np.asarray([counts["fn"]]),
                                                   np.asarray([attacks]))[0]) if attacks else None)
        fpr_upper = (float(wilson_upper(np.asarray([counts["fp"]]),
                                         np.asarray([benign]))[0]) if benign else None)
        return {"attack_flows": attacks, "benign_flows": benign,
            "recall": counts["tp"] / attacks if attacks else None,
            "recall_ci95_lower": recall_lower,
            "fpr": counts["fp"] / benign if benign else None,
            "fpr_ci95_upper": fpr_upper,
            "minimum_sample_gate_met": attacks >= 100 and benign >= MIN_BENIGN_SUPPORT_ZERO_FP,
            "recall_gate_met": recall_lower is not None and recall_lower >= .80,
            "fpr_gate_met": fpr_upper is not None and fpr_upper <= RELEASE_FPR_CI_CEILING}

    per_day = {day: {"counts": counts, "metrics": metrics(counts)}
               for day, counts in sorted(days.items())}
    total_metrics = metrics(totals)
    report = {
        "dataset": "CTU-SME-11", "capture": args.capture,
        "capture_role": "one-pass independent source-family test for live v3; not used for training or threshold selection",
        "capture_source_url": "https://zenodo.org/records/7958259/files/CTU-SME-11_Experiment-VM-Microsoft-Windows7AD-1_v1.0.0.tar.bz2?download=1",
        "label_source": "publisher-provided Zeek labels; benign/malicious only; background/unknown excluded",
        "feature_adapter": "same v3 prefix: Zeek duration, bidirectional bytes/packets, protocol",
        "archive_size_bytes": archive_path.stat().st_size,
        "archive_sha256": archive_sha, "publisher_md5": publisher_md5,
        "candidate_sha256": candidate_sha,
        "candidate_manifest_sha256": expected_registration["candidate_manifest_sha256"],
        "registration_sha256": sha256_file(registration_path),
        "evaluator_sha256": expected_registration["evaluator_sha256"],
        "candidate_training_captures": artifact.get("train_captures", []),
        "candidate_validation_capture": artifact.get("validation_capture"),
        "threshold": float(args.threshold), "threshold_source": "checkpoint value selected on CTU-13 capture 45",
        "counts": totals,
        "coverage": {
            "explicitly_labeled_rows": totals["explicit_labeled_rows"],
            "scored_explicitly_labeled_rows": totals["benign"] + totals["malicious"],
            "explicitly_labeled_but_incomplete_rows": totals["explicit_labeled_incomplete_excluded"],
            "scored_fraction_of_explicitly_labeled_rows":
                (totals["benign"] + totals["malicious"]) / max(totals["explicit_labeled_rows"], 1),
            "explicit_label_fraction_of_all_flow_rows":
                totals["explicit_labeled_rows"] / max(totals["flow_rows"], 1),
        },
        "confusion": {key: totals[key] for key in ("tp", "fp", "fn", "tn")},
        "metrics": total_metrics, "per_day": per_day,
        "per_day_gate_passed": bool(per_day) and all(
            item["metrics"]["minimum_sample_gate_met"]
            and item["metrics"]["recall_gate_met"]
            and item["metrics"]["fpr_gate_met"] for item in per_day.values()),
        "research_only": True, "promotion_eligible": False, "enforcement_applied": False,
    }
    report_path = registration_path.with_name(registration_path.stem + "-one-pass-evaluation.json")
    report["report_path"] = str(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["report_sha256"] = sha256_file(report_path)
    print(json.dumps(report, indent=2), flush=True)


def evaluate_ctu_idseval6_candidate(args) -> None:
    """One-pass evaluation on the reserved publisher-labeled CTU-IDSEVAL-6 source family."""
    candidate_path = Path(args.candidate).resolve()
    for path in (CTU_IDSEVAL6_ZEEK, CTU_IDSEVAL6_LABELS):
        if not path.is_file():
            raise FileNotFoundError(path)
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    configure_feature_schema(int(artifact.get("feature_version", -1)))
    if artifact.get("feature_version") != FEATURE_VERSION \
            or artifact.get("feature_names") != list(FEATURE_NAMES) \
            or artifact.get("classes") != ["benign", "attack"]:
        raise ValueError("Candidate feature/class schema does not match CTU-IDSEVAL-6 flow adapter")
    if args.threshold is None or not math.isfinite(args.threshold) or not 0 <= args.threshold <= 1:
        raise ValueError("Supply the frozen validation threshold with --threshold")
    if any(capture_id in CTU_IDSEVAL6_TRAIN_MEMBERS
           for capture_id in artifact.get("training_captures", [])):
        raise ValueError("Reserved CTU-IDSEVAL-6 source appears in candidate training provenance")
    expected = str(args.expected_sha256 or "").lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("A pinned 64-character expected Zeek archive SHA-256 is required")
    zeek_sha = sha256_file(CTU_IDSEVAL6_ZEEK).lower()
    labels_sha = sha256_file(CTU_IDSEVAL6_LABELS).lower()
    if zeek_sha != expected or zeek_sha != CTU_IDSEVAL6_ZEEK_SHA256:
        raise ValueError("CTU-IDSEVAL-6 Zeek archive SHA-256 mismatch; no scores calculated")
    if labels_sha != CTU_IDSEVAL6_LABELS_SHA256:
        raise ValueError("CTU-IDSEVAL-6 label archive SHA-256 mismatch; no scores calculated")
    md5 = hashlib.md5()
    with CTU_IDSEVAL6_ZEEK.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            md5.update(chunk)
    zeek_md5 = md5.hexdigest()
    if zeek_md5 != CTU_IDSEVAL6_ZEEK_MD5:
        raise ValueError("CTU-IDSEVAL-6 Zeek archive differs from publisher checksum")
    md5 = hashlib.md5()
    with CTU_IDSEVAL6_LABELS.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            md5.update(chunk)
    labels_md5 = md5.hexdigest()
    if labels_md5 != CTU_IDSEVAL6_LABELS_MD5:
        raise ValueError("CTU-IDSEVAL-6 labels archive differs from publisher checksum")

    model = MLP(len(FEATURE_NAMES), int(artifact.get("hidden_width", 128)))
    model.load_state_dict(artifact["state_dict"])
    model.eval()
    mean = np.asarray(artifact["mean"], dtype=np.float32)
    scale = np.asarray(artifact["scale"], dtype=np.float32)
    captures: dict[str, dict] = {}
    batch_x: list[list[float]] = []
    batch_y: list[int] = []
    batch_capture_ids: list[str] = []

    def capture_record(capture_id: str) -> dict:
        return captures.setdefault(capture_id, {
            "flow_rows": 0, "explicit_labeled_rows": 0, "benign": 0, "malicious": 0,
            "background_or_unknown_excluded": 0, "incomplete_excluded": 0,
            "explicit_labeled_incomplete_excluded": 0,
            "tp": 0, "fp": 0, "fn": 0, "tn": 0,
        })

    def score_batch() -> None:
        if not batch_x:
            return
        x = np.asarray(batch_x, dtype=np.float32)
        x = np.clip((x - mean) / scale, -10.0, 10.0).astype(np.float32)
        with torch.no_grad():
            probabilities = torch.softmax(model(torch.from_numpy(x)), dim=1)[:, 1].numpy()
        truth = np.asarray(batch_y, dtype=np.int8) == 1
        predicted = probabilities >= float(args.threshold)
        capture_ids = np.asarray(batch_capture_ids, dtype=object)
        for capture_id in np.unique(capture_ids):
            mask = capture_ids == capture_id
            record = capture_record(str(capture_id))
            record["tp"] += int(np.count_nonzero(truth[mask] & predicted[mask]))
            record["fp"] += int(np.count_nonzero(~truth[mask] & predicted[mask]))
            record["fn"] += int(np.count_nonzero(truth[mask] & ~predicted[mask]))
            record["tn"] += int(np.count_nonzero(~truth[mask] & ~predicted[mask]))
        batch_x.clear(); batch_y.clear(); batch_capture_ids.clear()

    evaluated_logs = []
    with zipfile.ZipFile(CTU_IDSEVAL6_ZEEK, "r") as archive:
        names = sorted(name for name in archive.namelist()
                       if name.startswith("zeek/") and name.endswith(".conn-labeled.log"))
        if len(names) != 6:
            raise ValueError(f"Expected exactly six CTU-IDSEVAL-6 Zeek captures, found {len(names)}")
        for name in names:
            capture_id = Path(name).name.removesuffix(".conn-labeled.log")
            record = capture_record(capture_id)
            fields = None
            log_digest = hashlib.sha256()
            with archive.open(name, "r") as stream:
                for raw in stream:
                    log_digest.update(raw)
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("#fields\t"):
                        fields = line.split("\t")[1:]
                        continue
                    if not line or line.startswith("#") or fields is None:
                        continue
                    record["flow_rows"] += 1
                    values = line.split("\t")
                    row = dict(zip(fields, values))
                    label = (row.get("label") or "").strip().lower()
                    if label not in {"benign", "malicious"}:
                        record["background_or_unknown_excluded"] += 1
                        continue
                    record["explicit_labeled_rows"] += 1
                    if len(values) != len(fields):
                        record["incomplete_excluded"] += 1
                        record["explicit_labeled_incomplete_excluded"] += 1
                        continue
                    try:
                        vector = feature_from_zeek_mapping(row)
                    except (TypeError, ValueError, OverflowError):
                        record["incomplete_excluded"] += 1
                        record["explicit_labeled_incomplete_excluded"] += 1
                        continue
                    record[label] += 1
                    batch_x.append(vector)
                    batch_y.append(int(label == "malicious"))
                    batch_capture_ids.append(capture_id)
                    if len(batch_x) >= 8192:
                        score_batch()
            evaluated_logs.append({"name": name, "sha256": log_digest.hexdigest(),
                                   "size_bytes": archive.getinfo(name).file_size})
    score_batch()

    def metrics(counts: dict) -> dict:
        attacks = counts["tp"] + counts["fn"]
        benign = counts["fp"] + counts["tn"]
        recall_lower = (1.0 - float(wilson_upper(np.asarray([counts["fn"]]),
                                                   np.asarray([attacks]))[0]) if attacks else None)
        fpr_upper = (float(wilson_upper(np.asarray([counts["fp"]]),
                                         np.asarray([benign]))[0]) if benign else None)
        return {"attack_flows": attacks, "benign_flows": benign,
            "recall": counts["tp"] / attacks if attacks else None,
            "recall_ci95_lower": recall_lower,
            "fpr": counts["fp"] / benign if benign else None,
            "fpr_ci95_upper": fpr_upper,
            "minimum_sample_gate_met": attacks >= 100 and benign >= MIN_BENIGN_SUPPORT_ZERO_FP,
            "recall_gate_met": recall_lower is not None and recall_lower >= .80,
            "fpr_gate_met": fpr_upper is not None and fpr_upper <= RELEASE_FPR_CI_CEILING}

    totals = {key: sum(item[key] for item in captures.values()) for key in next(iter(captures.values()))}
    if totals["benign"] == 0 or totals["malicious"] == 0:
        raise ValueError("CTU-IDSEVAL-6 archive did not contain both explicitly labeled classes")
    per_capture = {capture_id: {"counts": counts, "metrics": metrics(counts)}
                   for capture_id, counts in sorted(captures.items())}
    scored = totals["benign"] + totals["malicious"]
    report = {
        "dataset": "CTU-IDSEVAL-6", "capture": "ctu-idseval-6",
        "capture_role": "pre-registered one-pass independent source-family test; not used for training, validation, feature/threshold selection",
        "source_url": "https://zenodo.org/records/21027042",
        "source_description": "Six publisher-labeled real network captures; includes benign user traffic, malware C2 and port scans",
        "label_source": "publisher-provided Zeek label field; only explicit Benign/Malicious included; Background/unknown excluded",
        "feature_adapter": f"Zeek duration, packets, orig/resp IP bytes and protocol mapped to v{FEATURE_VERSION} flow contract",
        "zeek_archive_sha256": zeek_sha, "zeek_archive_publisher_md5": zeek_md5,
        "labels_archive_sha256": labels_sha, "labels_archive_publisher_md5": labels_md5,
        "evaluated_logs": evaluated_logs,
        "candidate_sha256": sha256_file(candidate_path),
        "candidate_training_captures": artifact.get("training_captures", []),
        "candidate_training_sha256": artifact.get("training_sha256", {}),
        "candidate_validation_sha256": artifact.get("validation_sha256", {}),
        "threshold_source": "frozen threshold from training-run validation only; no test-driven adjustment",
        "threshold": float(args.threshold), "counts": totals,
        "coverage": {
            "explicitly_labeled_rows": totals["explicit_labeled_rows"],
            "scored_explicitly_labeled_rows": scored,
            "explicitly_labeled_but_incomplete_rows": totals["explicit_labeled_incomplete_excluded"],
            "scored_fraction_of_explicitly_labeled_rows":
                scored / max(totals["explicit_labeled_rows"], 1),
            "explicit_label_fraction_of_all_flow_rows":
                totals["explicit_labeled_rows"] / max(totals["flow_rows"], 1),
            "scored_fraction_of_all_flow_rows": scored / max(totals["flow_rows"], 1),
        },
        "metrics": metrics(totals), "per_capture": per_capture,
        "research_only": True, "promotion_eligible": False, "enforcement_applied": False,
    }
    report_path = candidate_path.with_name("ctu-idseval-6-one-pass-evaluation.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_iscx2017_thursday(args) -> None:
    """One-pass diagnostic on a separate CIC-IDS-2017 Zeek-derived capture day.

    The candidate is frozen by SHA/threshold first. This derivative's record
    does not fully document row-label construction, so it is external diagnostic
    evidence, not a release-promotion test.
    """
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("This research evaluator requires pyarrow in the research venv") from exc

    if not args.registration_file:
        raise ValueError("CIC-IDS-2017 one-pass evaluation requires a preregistration file")
    registration_path = Path(args.registration_file).resolve(strict=True)
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    if registration.get("status") != "preregistered_pending_review" \
            or registration.get("diagnostic_only") is not True:
        raise ValueError("CIC-IDS-2017 registration is not pending and diagnostic-only")
    candidate_path = Path(args.candidate).resolve()
    if not ISCX2017_THURSDAY.is_file():
        raise FileNotFoundError(ISCX2017_THURSDAY)
    digest = sha256_file(ISCX2017_THURSDAY).lower()
    expected = str(args.expected_sha256 or "").lower()
    if (expected != ISCX2017_THURSDAY_SHA256 or digest != ISCX2017_THURSDAY_SHA256):
        raise ValueError("CIC-IDS-2017 Thursday SHA-256 mismatch; no scores calculated")
    md5 = hashlib.md5()
    with ISCX2017_THURSDAY.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            md5.update(chunk)
    if md5.hexdigest() != ISCX2017_THURSDAY_MD5:
        raise ValueError("CIC-IDS-2017 Thursday file differs from the Zenodo publisher checksum")

    candidate_digest = sha256_file(candidate_path).lower()
    expected_candidate = str(args.expected_candidate_sha256 or "").lower()
    manifest_path = Path(registration["candidate"]["manifest_path"]).resolve(strict=True)
    schema_path = ROOT / "integrityguard" / "network_flow_schema_v10.py"
    evaluator_path = Path(__file__).resolve(strict=True)
    registered_inputs = [
        (candidate_path, registration["candidate"]["sha256"]),
        (manifest_path, registration["candidate"]["manifest_sha256"]),
        (ISCX2017_THURSDAY, registration["source"]["capture_sha256"]),
        (evaluator_path, registration["evaluator"]["sha256"]),
        (schema_path, registration["evaluator"]["feature_schema_sha256"]),
    ]
    if candidate_digest != expected_candidate \
            or expected_candidate != str(registration["candidate"]["sha256"]).lower():
        raise ValueError("Candidate SHA-256 differs from the preregistered candidate")
    if expected != str(registration["source"]["capture_sha256"]).lower():
        raise ValueError("Source SHA-256 differs from the preregistered capture")
    if args.threshold is None or not math.isfinite(args.threshold) \
            or not math.isclose(float(args.threshold), float(registration["decision"]["threshold"]),
                                rel_tol=0, abs_tol=1e-12):
        raise ValueError("Threshold differs from the preregistered frozen value")
    for path, expected_hash in registered_inputs:
        if sha256_file(path).lower() != str(expected_hash).lower():
            raise ValueError(f"SHA-256 mismatch for registered input: {path}")

    report_path = registration_path.with_name(registration_path.stem + "-one-pass-report.json")
    marker_path = registration_path.with_name(registration_path.stem + ".attempt.json")
    if report_path.exists() or marker_path.exists():
        raise FileExistsError("This registration has already been consumed or reported")

    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    configure_feature_schema(int(artifact.get("feature_version", -1)))
    artifact_feature_names = artifact.get("feature_names")
    if (not isinstance(artifact_feature_names, list) or not artifact_feature_names
            or len(set(artifact_feature_names)) != len(artifact_feature_names)
            or any(name not in FEATURE_NAMES for name in artifact_feature_names)):
        raise ValueError("Candidate feature-profile names are invalid for the selected flow schema")
    selected_indices = [FEATURE_NAMES.index(name) for name in artifact_feature_names]
    selected_feature_names = list(artifact_feature_names)
    if (artifact.get("feature_version") != FEATURE_VERSION
            or artifact.get("feature_names") != selected_feature_names
            or artifact.get("classes") != ["benign", "attack"]
            or artifact.get("ensemble_type")
            or int(registration["candidate"]["feature_version"]) != FEATURE_VERSION
            or artifact.get("feature_profile") != registration["candidate"]["feature_profile"]
            or selected_feature_names != registration["candidate"]["feature_names"]):
        raise ValueError("Candidate feature/class schema is incompatible with the Zeek flow adapter")
    if any("iscx2017" in str(c).lower() or "cic2017" in str(c).lower()
           for c in artifact.get("training_captures", [])):
        raise ValueError("CIC-IDS-2017 capture appears in candidate training provenance")

    attempt = {"registration_sha256": sha256_file(registration_path), "state": "started",
               "started_at_utc": datetime.now(timezone.utc).isoformat(), "score_passes": 1}
    with marker_path.open("x", encoding="utf-8") as stream:
        json.dump(attempt, stream, indent=2)
        stream.flush()
        import os
        os.fsync(stream.fileno())

    def persist_attempt(state: str, error_type: str | None = None) -> None:
        attempt["state"] = state
        attempt["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        if error_type:
            attempt["error_type"] = error_type
        temp_path = marker_path.with_name(marker_path.name + ".tmp")
        with temp_path.open("w", encoding="utf-8") as stream:
            json.dump(attempt, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, marker_path)

    state_dict = artifact["state_dict"]
    inferred_width = int(state_dict["layers.0.weight"].shape[0])
    hidden_width = int(artifact.get("hidden_width", inferred_width))
    if hidden_width != inferred_width:
        raise ValueError("Candidate hidden width disagrees with its state_dict")
    model = MLP(len(selected_feature_names), hidden_width)
    model.load_state_dict(artifact["state_dict"])
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device).eval()
    mean = np.asarray(artifact["mean"], dtype=np.float32)
    scale = np.asarray(artifact["scale"], dtype=np.float32)
    labels_seen: dict[str, dict[str, int]] = {}
    flow_rows = explicit_rows = unknown_labels = invalid_features = 0
    tp = fp = fn = tn = 0
    batch_features: list[list[float]] = []
    batch_labels: list[int] = []
    batch_raw_labels: list[str] = []

    def score_batch() -> None:
        nonlocal tp, fp, fn, tn
        if not batch_features:
            return
        x = np.asarray(batch_features, dtype=np.float32)
        x = np.clip((x - mean) / scale, -10.0, 10.0).astype(np.float32)
        with torch.no_grad():
            probabilities = torch.softmax(model(torch.from_numpy(x).to(device)), dim=1)[:, 1].cpu().numpy()
        truth = np.asarray(batch_labels, dtype=np.bool_)
        predicted = probabilities >= float(args.threshold)
        tp += int(np.count_nonzero(truth & predicted))
        fp += int(np.count_nonzero(~truth & predicted))
        fn += int(np.count_nonzero(truth & ~predicted))
        tn += int(np.count_nonzero(~truth & ~predicted))
        raw = np.asarray(batch_raw_labels, dtype=object)
        for label in set(batch_raw_labels):
            selected = raw == label
            item = labels_seen.setdefault(label, {"flows": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})
            item["flows"] += int(np.count_nonzero(selected))
            item["tp"] += int(np.count_nonzero(selected & truth & predicted))
            item["fp"] += int(np.count_nonzero(selected & ~truth & predicted))
            item["fn"] += int(np.count_nonzero(selected & truth & ~predicted))
            item["tn"] += int(np.count_nonzero(selected & ~truth & ~predicted))
        batch_features.clear(); batch_labels.clear(); batch_raw_labels.clear()

    parquet_file = parquet.ParquetFile(ISCX2017_THURSDAY)
    # Fail closed when a source omits any field used by the registered v10
    # adapter. In particular, missing Zeek ports must never silently become 0.
    columns = ["label", "duration", "orig_pkts", "resp_pkts", "orig_ip_bytes",
               "resp_ip_bytes", "proto"]
    if FEATURE_VERSION == flow_v10.FEATURE_VERSION:
        columns.extend(["id.orig_p", "id.resp_p"])
    available_columns = set(parquet_file.schema_arrow.names)
    missing_columns = sorted(set(columns) - available_columns)
    if missing_columns:
        raise ValueError(
            "CIC-IDS-2017 capture is missing required feature/label columns; "
            f"no labels or scores were read: {missing_columns}"
        )
    for batch in parquet_file.iter_batches(batch_size=8192, columns=columns):
        for row in batch.to_pylist():
            flow_rows += 1
            raw_label = str(row.get("label") or "").strip()
            normalized_label = raw_label.upper().replace("-", "_").replace(" ", "_")
            if normalized_label == "BENIGN":
                target = 0
            elif normalized_label in ISCX2017_EXPLICIT_ATTACK_LABELS:
                target = 1
            else:
                unknown_labels += 1
                continue
            explicit_rows += 1
            if FEATURE_VERSION == flow_v10.FEATURE_VERSION \
                    and ("id.orig_p" not in row or "id.resp_p" not in row):
                invalid_features += 1
                continue
            try:
                vector = feature_from_zeek_mapping(row)
                vector = [vector[i] for i in selected_indices]
            except (TypeError, ValueError, OverflowError):
                invalid_features += 1
                continue
            batch_features.append(vector)
            batch_labels.append(target)
            batch_raw_labels.append(raw_label)
            if len(batch_features) >= 8192:
                score_batch()
    score_batch()

    n_attack, n_benign = tp + fn, fp + tn
    recall = tp / n_attack if n_attack else None
    recall_lower = (1.0 - float(wilson_upper(np.asarray([fn]), np.asarray([n_attack]))[0])
                    if n_attack else None)
    fpr = fp / n_benign if n_benign else None
    fpr_upper = (float(wilson_upper(np.asarray([fp]), np.asarray([n_benign]))[0])
                 if n_benign else None)
    support_ok = n_attack >= 100 and n_benign >= MIN_BENIGN_SUPPORT_ZERO_FP
    report = {
        "dataset": "CIC-IDS-2017 Thursday Working Hours; Zeek-derived Zenodo release",
        "source_url": "https://zenodo.org/records/21469685",
        "upstream_source_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "capture": "Thursday-WorkingHours_labeled",
        "capture_role": "one-pass external source-family diagnostic; not used for candidate training or threshold selection",
        "source_characterization": "real PCAP-derived Zeek flows from a controlled testbed; attack activities were executed and captured as network traffic",
        "label_provenance_limit": "The Zenodo flow record provides a label column but does not document the exact row-level label-join implementation; diagnostic only, not release-promotion evidence",
        "label_policy": "BENIGN is benign; only the explicit CIC-IDS-2017 attack-label allowlist is attack; all other labels excluded",
        "feature_adapter": f"Zeek duration, packet counts, IP bytes, protocol, and ports mapped through v{FEATURE_VERSION}; checkpoint profile {artifact.get('feature_profile')} selects {len(selected_feature_names)} registered features; labels and metadata excluded from features",
        "feature_version": FEATURE_VERSION,
        "feature_profile": artifact.get("feature_profile"),
        "feature_names": selected_feature_names,
        "feature_indices": selected_indices,
        "capture_sha256": digest, "capture_publisher_md5": md5.hexdigest(),
        "candidate_sha256": sha256_file(candidate_path),
        "candidate_manifest_sha256": sha256_file(manifest_path),
        "registration_sha256": sha256_file(registration_path),
        "evaluator_sha256": sha256_file(evaluator_path),
        "feature_schema_sha256": sha256_file(schema_path),
        "candidate_training_captures": artifact.get("training_captures", []),
        "candidate_validation_sha256": artifact.get("validation_sha256", {}),
        "threshold": float(args.threshold),
        "threshold_source": "training validation capture only; frozen before this one-pass inference",
        "counts": {"flow_rows": flow_rows, "explicit_labeled_rows": explicit_rows,
                   "scored_rows": n_attack + n_benign, "attack": n_attack,
                   "benign": n_benign, "unknown_or_unsupported_labels_excluded": unknown_labels,
                   "explicit_labels_with_incomplete_features_excluded": invalid_features},
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": {"recall": recall, "recall_ci95_lower": recall_lower,
                    "fpr": fpr, "fpr_ci95_upper": fpr_upper,
                    "minimum_sample_gate_met": support_ok,
                    "recall_gate_met": bool(support_ok and recall_lower is not None and recall_lower >= .80),
                    "fpr_gate_met": bool(support_ok and fpr_upper is not None and fpr_upper <= RELEASE_FPR_CI_CEILING)},
        "per_publisher_label": labels_seen,
        "research_only": True, "promotion_eligible": False, "enforcement_applied": False,
    }
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.flush()
        import os
        os.fsync(stream.fileno())
    persist_attempt("completed")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_apex_ids2026(args) -> None:
    """One-pass diagnostic on the frozen APEX-IDS2026 high-confidence flow set.

    This is real, unidirectional NetFlow from an ISP-edge honeypot dataset. Only
    Attack_Verified and Benign_Verified labels are scored. The adapter maps the
    observed source-to-destination byte count to the initiator direction and
    zero response bytes. The publisher's benign tier is described as >=95%
    confidence, so this dataset cannot establish a 0.25% FPR release bound.
    """
    try:
        import pyarrow as pa
        import pyarrow.compute as pc
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("APEX evaluation requires pyarrow in the research venv") from exc

    candidate_path = Path(args.candidate).resolve()
    if not APEX_IDS2026_ARCHIVE.is_file():
        raise FileNotFoundError(APEX_IDS2026_ARCHIVE)
    capture_sha = sha256_file(APEX_IDS2026_ARCHIVE).lower()
    if str(args.expected_sha256 or "").lower() != APEX_IDS2026_SHA256 or capture_sha != APEX_IDS2026_SHA256:
        raise ValueError("APEX-IDS2026 archive SHA-256 mismatch; no scores calculated")
    md5 = hashlib.md5()
    with APEX_IDS2026_ARCHIVE.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            md5.update(chunk)
    if md5.hexdigest() != APEX_IDS2026_MD5:
        raise ValueError("APEX-IDS2026 archive differs from the Zenodo publisher checksum")

    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    configure_feature_schema(int(artifact.get("feature_version", -1)))
    if (artifact.get("feature_version") != flow_v9.FEATURE_VERSION
            or artifact.get("feature_names") != list(FEATURE_NAMES)
            or artifact.get("classes") != ["benign", "attack"]
            or artifact.get("ensemble_type")):
        raise ValueError("Candidate must be a single v9 binary MLP compatible with the fixed NetFlow adapter")
    if any("apex" in str(c).lower() for c in artifact.get("training_captures", [])):
        raise ValueError("APEX-IDS2026 appears in candidate training provenance")
    if args.threshold is None or not math.isfinite(args.threshold) or not 0 <= args.threshold <= 1:
        raise ValueError("Supply the frozen validation threshold with --threshold")

    model = MLP(len(FEATURE_NAMES), int(artifact.get("hidden_width", 128)))
    model.load_state_dict(artifact["state_dict"])
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device).eval()
    mean = np.asarray(artifact["mean"], dtype=np.float32)
    scale = np.asarray(artifact["scale"], dtype=np.float32)
    labels_seen: dict[str, dict[str, int]] = {}
    days: dict[str, dict[str, int]] = {}
    flow_rows = scored = attack_rows = benign_rows = unknown_labels = invalid_features = 0
    tp = fp = fn = tn = 0
    inference_seconds = 0.0

    def wilson_interval(successes: int, total: int) -> tuple[float | None, float | None]:
        if total <= 0:
            return None, None
        arr_s = np.asarray([successes], dtype=np.int64)
        arr_n = np.asarray([total], dtype=np.int64)
        upper = float(wilson_upper(arr_s, arr_n)[0])
        lower = 1.0 - float(wilson_upper(np.asarray([total - successes]), arr_n)[0])
        return lower, upper

    def add_result(raw_label: str, day: str, truth: np.ndarray, predicted: np.ndarray) -> None:
        nonlocal tp, fp, fn, tn, scored, attack_rows, benign_rows
        positive = truth.astype(np.bool_, copy=False)
        pred = predicted.astype(np.bool_, copy=False)
        counts = {
            "tp": int(np.count_nonzero(positive & pred)),
            "fp": int(np.count_nonzero(~positive & pred)),
            "fn": int(np.count_nonzero(positive & ~pred)),
            "tn": int(np.count_nonzero(~positive & ~pred)),
        }
        tp += counts["tp"]; fp += counts["fp"]
        fn += counts["fn"]; tn += counts["tn"]
        scored += len(positive)
        if raw_label == "Attack_Verified":
            attack_rows += len(positive)
        else:
            benign_rows += len(positive)
        item = labels_seen.setdefault(raw_label, {"flows": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})
        item["flows"] += len(positive)
        for key, value in counts.items():
            item[key] += value
        daily = days.setdefault(day, {"attack": 0, "benign": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})
        daily["attack" if raw_label == "Attack_Verified" else "benign"] += len(positive)
        for key, value in counts.items():
            daily[key] += value

    started = time.perf_counter()
    with zipfile.ZipFile(APEX_IDS2026_ARCHIVE) as archive:
        parquet_names = [name for name in archive.namelist() if name.lower().endswith(".parquet")]
        if parquet_names != ["apex_ids2026_hc_subset.parquet"]:
            raise ValueError("Unexpected APEX archive members; expected the pinned high-confidence Parquet file")
        with archive.open(parquet_names[0]) as parquet_stream:
            parquet_file = parquet.ParquetFile(parquet_stream)
            expected_rows = int(parquet_file.metadata.num_rows)
            required = {"label", "date", "duration_s", "protocol", "packets", "bytes"}
            available = set(parquet_file.schema_arrow.names)
            if not required.issubset(available):
                raise ValueError(f"APEX file is missing required fields: {sorted(required - available)}")
            for batch in parquet_file.iter_batches(
                    batch_size=131072,
                    columns=["label", "date", "duration_s", "protocol", "packets", "bytes"]):
                flow_rows += batch.num_rows
                labels = np.asarray(batch.column(0).to_numpy(zero_copy_only=False), dtype=object)
                label_attack = labels == "Attack_Verified"
                label_benign = labels == "Benign_Verified"
                selected = label_attack | label_benign
                unknown_labels += int(np.count_nonzero(~selected))
                if not np.any(selected):
                    continue

                duration_arr = batch.column(2)
                packets_arr = pc.cast(batch.column(4), pa.float64(), safe=True)
                bytes_arr = pc.cast(batch.column(5), pa.float64(), safe=True)
                duration = np.asarray(pc.cast(duration_arr, pa.float64(), safe=True).to_numpy(zero_copy_only=False), dtype=np.float64)
                packets = np.asarray(packets_arr.to_numpy(zero_copy_only=False), dtype=np.float64)
                byte_count = np.asarray(bytes_arr.to_numpy(zero_copy_only=False), dtype=np.float64)
                protocol = np.asarray(batch.column(3).to_numpy(zero_copy_only=False), dtype=object)
                date_values = np.asarray(batch.column(1).to_numpy(zero_copy_only=False), dtype=object)
                duration_missing = np.isnan(duration)
                finite = (np.isfinite(packets) & np.isfinite(byte_count)
                          & (packets >= 0) & (byte_count >= 0)
                          & (duration_missing | (np.isfinite(duration) & (duration >= 0))))
                keep = selected & finite
                invalid_features += int(np.count_nonzero(selected & ~finite))
                if not np.any(keep):
                    continue

                d = np.where(duration_missing, 0.0, duration)
                p = packets
                b = byte_count
                proto = np.char.lower(np.asarray([str(x or "") for x in protocol], dtype=str))
                is_tcp = proto == "tcp"
                is_udp = proto == "udp"
                is_icmp = np.isin(proto, ("icmp", "icmpv6"))
                is_other = ~(is_tcp | is_udp | is_icmp)
                # NetFlow records are unidirectional: all observed bytes belong
                # to the source direction. This adapter is explicit, not learned
                # from label or metadata columns.
                safe_packets = np.maximum(p, 1.0)
                safe_duration = np.maximum(d, 0.001)
                asym = np.divide(b, b, out=np.zeros_like(b), where=b > 0)
                udp_duration = np.where(is_udp, d, 0.0)
                x = np.column_stack((
                    np.log1p(d), np.log1p(p), np.log1p(b), np.log1p(b),
                    is_tcp, is_udp, is_icmp, is_other,
                    np.log1p(b / safe_packets), np.log1p(p / safe_duration), asym,
                    is_udp & (d < 0.001), np.log1p(p * d), is_udp & (d >= 1.0),
                    is_udp & (d >= 0.001) & (d < 1.0), udp_duration.astype(np.float64),
                    is_udp & (asym >= 1.0), duration_missing,
                )).astype(np.float32, copy=False)
                x = np.clip((x[keep] - mean) / scale, -10.0, 10.0).astype(np.float32, copy=False)
                with torch.no_grad():
                    t0 = time.perf_counter()
                    probs = torch.softmax(model(torch.from_numpy(x).to(device)), dim=1)[:, 1].cpu().numpy()
                    inference_seconds += time.perf_counter() - t0
                labels_kept = labels[keep]
                dates_kept = date_values[keep]
                pred = probs >= float(args.threshold)
                truth = labels_kept == "Attack_Verified"
                for raw_label in ("Attack_Verified", "Benign_Verified"):
                    class_mask = labels_kept == raw_label
                    if not np.any(class_mask):
                        continue
                    for day_value in np.unique(dates_kept[class_mask]):
                        day_mask = class_mask & (dates_kept == day_value)
                        add_result(raw_label, str(day_value), truth[day_mask], pred[day_mask])

    if flow_rows != expected_rows:
        raise ValueError(f"APEX row scan incomplete: expected {expected_rows}, observed {flow_rows}")
    if not attack_rows or not benign_rows:
        raise ValueError("APEX high-confidence subset must contain explicit attack and benign support")

    recall = tp / attack_rows
    fpr = fp / benign_rows
    recall_lower, _ = wilson_interval(tp, attack_rows)
    _, fpr_upper = wilson_interval(fp, benign_rows)
    daily_report = {}
    for day, counts in sorted(days.items()):
        day_attack, day_benign = counts["attack"], counts["benign"]
        day_recall = counts["tp"] / day_attack if day_attack else None
        day_fpr = counts["fp"] / day_benign if day_benign else None
        lower, _ = wilson_interval(counts["tp"], day_attack)
        _, upper = wilson_interval(counts["fp"], day_benign)
        daily_report[day] = {**counts, "recall": day_recall, "recall_ci95_lower": lower,
                             "fpr": day_fpr, "fpr_ci95_upper": upper,
                             "minimum_sample_gate_met": day_attack >= 100 and day_benign >= MIN_BENIGN_SUPPORT_ZERO_FP}
    elapsed = time.perf_counter() - started
    report = {
        "dataset": "APEX-IDS2026 high-confidence subset, Zenodo version 1.0.0",
        "source_url": "https://zenodo.org/records/22013914",
        "doi": "10.5281/zenodo.22013914",
        "license": "CC-BY-4.0",
        "capture_role": "one-pass external source-family diagnostic; not used for candidate training or threshold selection",
        "source_characterization": "real unidirectional NetFlow v9 exported from live ISP edge, June 21 through August 3 2026; no synthetic packet generation",
        "label_provenance": "only Attack_Verified and Benign_Verified publisher labels; tier 1 attack labels are honeypot source-IP/destination-port matches; tier 3 benign labels are publisher-verified safe destinations",
        "label_quality_limit": "publisher data card describes Benign_Verified as high confidence (95%+), which is not sufficient to establish a 0.25% FPR bound; result is diagnostic and cannot promote the model",
        "label_policy": "Attack_Verified=attack, Benign_Verified=benign; all other labels excluded, never mapped to benign",
        "feature_adapter": "v9 mapping from duration_s, packets, bytes, protocol; unidirectional bytes map to source/originator direction and zero observed response bytes; labels, dates, IPs, ports, flags, and taxonomy are not model features",
        "archive_sha256": capture_sha,
        "archive_publisher_md5": md5.hexdigest(),
        "archive_member": parquet_names[0],
        "candidate_sha256": sha256_file(candidate_path),
        "candidate_training_captures": artifact.get("training_captures", []),
        "candidate_validation_sha256": artifact.get("validation_sha256", {}),
        "feature_version": FEATURE_VERSION,
        "threshold": float(args.threshold),
        "threshold_source": "CTU-13 validation capture 45 only; frozen before this evaluation",
        "counts": {"flow_rows": flow_rows, "scored_rows": scored, "attack": attack_rows,
                   "benign": benign_rows, "unknown_labels_excluded": unknown_labels,
                   "explicit_labeled_rows_with_invalid_features": invalid_features},
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": {"recall": recall, "recall_ci95_lower": recall_lower,
                    "fpr": fpr, "fpr_ci95_upper": fpr_upper,
                    "minimum_sample_gate_met": attack_rows >= 100 and benign_rows >= MIN_BENIGN_SUPPORT_ZERO_FP,
                    "recall_gate_met": recall_lower is not None and recall_lower >= .80,
                    "fpr_gate_met": fpr_upper is not None and fpr_upper <= RELEASE_FPR_CI_CEILING,
                    "promotion_eligible": False},
        "interval_unit": "per-flow Wilson intervals; temporal/campaign dependence is not adjusted",
        "per_day": daily_report,
        "timing": {"wall_seconds": elapsed, "model_inference_seconds": inference_seconds,
                   "device": str(device)},
        "research_only": True,
        "promotion_eligible": False,
        "enforcement_applied": False,
    }
    report_path = DATA / "official-apex-ids2026" / "apex-high-confidence-one-pass-diagnostic.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_ctu13_candidate(args) -> None:
    """Evaluate one frozen CTU-13 candidate on a hash-pinned whole capture.

    The threshold must be supplied from validation. This path never selects or
    modifies it from test labels. Captures 46/47 were used in earlier project
    experiments, so results are candidate-held-out, but not pristine project-wide
    holdout evidence.
    """
    candidate_path = Path(args.candidate).resolve()
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    configure_feature_schema(int(artifact.get("feature_version", -1)))
    if artifact.get("feature_version") != FEATURE_VERSION \
            or artifact.get("feature_names") != list(FEATURE_NAMES) \
            or artifact.get("classes") != ["benign", "attack"]:
        raise ValueError("Candidate feature/class schema does not match CTU-13 loader")
    path = CTU_EVAL_CAPTURES[args.capture]
    if not path.is_file():
        raise FileNotFoundError(path)
    expected = str(args.expected_sha256 or "").upper()
    if len(expected) != 64 or any(c not in "0123456789ABCDEF" for c in expected):
        raise ValueError("A pinned 64-character expected SHA-256 is required")
    digest = sha256_file(path).upper()
    if digest != expected:
        raise ValueError("Capture SHA-256 mismatch; test metrics were not calculated")
    if args.threshold is None or not math.isfinite(args.threshold) or not 0 <= args.threshold <= 1:
        raise ValueError("Supply the frozen validation threshold with --threshold")

    x, y, _udp, excluded, raw_labels = load_capture(
        args.capture, path, include_raw_labels=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    scores = predict_candidate_artifact(artifact, x, device)
    predicted = scores >= float(args.threshold)
    attack = y == 1
    tp = int(np.count_nonzero(predicted & attack))
    fp = int(np.count_nonzero(predicted & ~attack))
    fn = int(np.count_nonzero(~predicted & attack))
    tn = int(np.count_nonzero(~predicted & ~attack))
    n_attack, n_benign = tp + fn, fp + tn
    per_publisher_label = {}
    label_array = np.asarray(raw_labels, dtype=object)
    for label in sorted(set(raw_labels)):
        selected = label_array == label
        positives = int(np.count_nonzero(selected & attack))
        negatives = int(np.count_nonzero(selected & ~attack))
        detected = int(np.count_nonzero(selected & attack & predicted))
        false_positive = int(np.count_nonzero(selected & ~attack & predicted))
        per_publisher_label[label] = {
            "class": "attack" if positives else "benign",
            "flows": positives + negatives,
            "detected_attacks": detected,
            "missed_attacks": positives - detected,
            "false_positives": false_positive,
            "recall_or_fpr": (detected / positives if positives else
                              false_positive / negatives if negatives else None),
        }
    report = {
        "dataset": "official publisher-labeled whole-capture evaluation",
        "capture": args.capture, "capture_sha256": digest,
        "candidate_sha256": sha256_file(candidate_path),
        "threshold": float(args.threshold), "threshold_source": "validation only",
        "counts": {"attack": n_attack, "benign": n_benign,
                   "unknown_or_invalid_excluded": int(excluded)},
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "recall": tp / n_attack if n_attack else 0.0,
        "recall_ci95_lower": 1.0 - float(wilson_upper(np.asarray([fn]),
            np.asarray([n_attack]))[0]) if n_attack else 0.0,
        "fpr": fp / n_benign if n_benign else 1.0,
        "fpr_ci95_upper": float(wilson_upper(np.asarray([fp]),
            np.asarray([n_benign]))[0]) if n_benign else 1.0,
        "minimum_sample_gate_met": (n_attack >= MIN_RELEASE_ATTACK_SUPPORT
                                     and n_benign >= MIN_BENIGN_SUPPORT_ZERO_FP),
        "recall_gate_met": n_attack >= MIN_RELEASE_ATTACK_SUPPORT and 1.0 - float(wilson_upper(
            np.asarray([fn]), np.asarray([n_attack]))[0]) >= .80,
        "fpr_gate_met": n_benign >= MIN_BENIGN_SUPPORT_ZERO_FP and float(wilson_upper(
            np.asarray([fp]), np.asarray([n_benign]))[0]) <= RELEASE_FPR_CI_CEILING,
        "capture_role": ("validation_used_for_threshold_selection" if args.capture == "45"
                         else "held_out_from_this_candidate_train_and_validation"),
        "test_history": (
            "Capture 46/47 were used in earlier project experiments; held out from this candidate's train/validation but not pristine project-wide holdout evidence."
            if args.capture in {"46", "47"} else
            "Capture 61-1 is a newly added official MCFP source capture; it was not used for this candidate's training or threshold selection."
            if args.capture == "61-1" else None),
        "per_publisher_label": per_publisher_label,
        "ensemble": artifact.get("ensemble_type"),
        "member_candidate_sha256": artifact.get("member_candidate_sha256"),
        "research_only": True, "promotion_eligible": False,
    }
    report_suffix = ("validation-diagnostic" if args.capture == "45"
                     else "independent-evaluation")
    report_path = candidate_path.with_name(
        f"{candidate_path.stem}-ctu-{args.capture}-{report_suffix}.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_live_v3_candidate(args) -> None:
    """One-pass, registration-pinned evaluation of the live v3 checkpoint.

    This adapter deliberately supports only the newly sourced MCFP 61-1
    capture. The feature vector is the unchanged v3 eight-feature prefix of
    the canonical CTU schema, and scoring matches network_flow_model.py.
    """
    from integrityguard.network_flow_model import (
        FLOW_V3_FEATURE_NAMES, _FlowV3AutoencoderClassifier,
    )

    candidate_path = Path(args.candidate).resolve()
    if args.capture != "61-1":
        raise ValueError("Live v3 evaluation is restricted to the newly registered CTU-MCFP 61-1 capture")
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    candidate_hash = sha256_file(candidate_path).lower()
    expected_candidate = str(args.expected_candidate_sha256 or "").lower()
    if len(expected_candidate) != 64 or candidate_hash != expected_candidate:
        raise ValueError("Candidate SHA-256 is missing or differs from the pre-registration")
    if artifact.get("feature_version") != 3 or artifact.get("features") != list(FLOW_V3_FEATURE_NAMES) \
            or artifact.get("classes") != ["benign", "attack"]:
        raise ValueError("Candidate is not the registered v3 binary flow model")
    if args.threshold is None or not math.isfinite(args.threshold) or not 0 <= args.threshold <= 1:
        raise ValueError("Supply the frozen v3 validation threshold")

    capture_path = CTU_EVAL_CAPTURES["61-1"]
    if not capture_path.is_file():
        raise FileNotFoundError(capture_path)
    expected_capture = str(args.expected_sha256 or "").lower()
    if len(expected_capture) != 64 or sha256_file(capture_path).lower() != expected_capture:
        raise ValueError("Capture SHA-256 mismatch; scoring was not started")

    registration_path = Path(args.registration_file or "").resolve()
    if not registration_path.is_file():
        raise ValueError("A pre-existing registration file is required for this one-pass test")
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    expected_registration = {
        "capture": "61-1",
        "capture_sha256": expected_capture,
        "candidate_sha256": candidate_hash,
        "threshold": float(args.threshold),
        "evaluator_sha256": sha256_file(Path(__file__).resolve()),
        "label_policy": "explicit CTU publisher From-Botnet/From-Normal only; all other labels excluded",
        "purpose": "one-pass independent source-family evaluation; no tuning on this capture",
    }
    if any(registration.get(key) != value for key, value in expected_registration.items()):
        raise ValueError("Registration does not match the candidate, capture, threshold, label policy, or evaluator")

    report_path = registration_path.with_name(registration_path.stem + "-one-pass-evaluation.json")
    attempt_path = registration_path.with_name(registration_path.stem + ".attempt.json")
    if report_path.exists() or attempt_path.exists():
        raise FileExistsError("This registered MCFP evaluation has already been attempted or reported")
    attempt = {
        "dataset": "CTU-MCFP 61-1", "candidate_sha256": candidate_hash,
        "capture_sha256": expected_capture,
        "registration_sha256": sha256_file(registration_path),
        "evaluator_sha256": expected_registration["evaluator_sha256"],
        "state": "started", "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "score_passes": 1,
    }
    with attempt_path.open("x", encoding="utf-8") as stream:
        json.dump(attempt, stream, indent=2)
        stream.flush()
        import os
        os.fsync(stream.fileno())

    configure_feature_schema(8)
    x, y, _udp, excluded, raw_labels = load_capture("61-1", capture_path, include_raw_labels=True)
    if x.ndim != 2 or x.shape[1] < len(FLOW_V3_FEATURE_NAMES):
        raise ValueError("CTU-MCFP 61-1 features do not match the preserved v3 prefix")
    x = x[:, :len(FLOW_V3_FEATURE_NAMES)].astype(np.float32, copy=False)
    mean = torch.as_tensor(artifact["mean"], dtype=torch.float32)
    std = torch.as_tensor(artifact["std"], dtype=torch.float32)
    if mean.numel() != len(FLOW_V3_FEATURE_NAMES) or std.numel() != len(FLOW_V3_FEATURE_NAMES):
        raise ValueError("Checkpoint normalization dimensions do not match v3 features")
    model = _FlowV3AutoencoderClassifier()
    model.load_state_dict(artifact["state_dict"])
    model.eval()
    values = (torch.from_numpy(x) - mean) / torch.where(std.abs() < 1e-6, torch.ones_like(std), std)
    with torch.no_grad():
        scores = torch.softmax(model(values)[1], dim=1)[:, 1].numpy()
    predicted = scores >= float(args.threshold)
    attack = y == 1
    tp = int(np.count_nonzero(predicted & attack))
    fp = int(np.count_nonzero(predicted & ~attack))
    fn = int(np.count_nonzero(~predicted & attack))
    tn = int(np.count_nonzero(~predicted & ~attack))
    n_attack, n_benign = tp + fn, fp + tn
    recall_lower = (1.0 - float(wilson_upper(np.asarray([fn]), np.asarray([n_attack]))[0])
                    if n_attack else 0.0)
    fpr_upper = (float(wilson_upper(np.asarray([fp]), np.asarray([n_benign]))[0])
                 if n_benign else 1.0)
    report = {
        "dataset": "official publisher-labeled whole-capture evaluation",
        "capture": "61-1", "capture_sha256": expected_capture,
        "candidate_sha256": candidate_hash,
        "candidate_manifest_sha256": sha256_file(candidate_path.with_name(
            "network_flow_v3_candidate_manifest.json")),
        "evaluator_sha256": expected_registration["evaluator_sha256"],
        "registration_sha256": sha256_file(registration_path),
        "threshold": float(args.threshold), "threshold_source": "v3 validation capture 45; fixed before test",
        "feature_version": 3, "features": list(FLOW_V3_FEATURE_NAMES),
        "counts": {"attack": n_attack, "benign": n_benign,
                   "unknown_or_invalid_excluded": int(excluded)},
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "recall": tp / n_attack if n_attack else 0.0,
        "recall_ci95_lower": recall_lower,
        "fpr": fp / n_benign if n_benign else 1.0,
        "fpr_ci95_upper": fpr_upper,
        "minimum_sample_gate_met": (n_attack >= MIN_RELEASE_ATTACK_SUPPORT
                                     and n_benign >= MIN_BENIGN_SUPPORT_ZERO_FP),
        "recall_gate_met": n_attack >= MIN_RELEASE_ATTACK_SUPPORT and recall_lower >= .80,
        "fpr_gate_met": n_benign >= MIN_BENIGN_SUPPORT_ZERO_FP and fpr_upper <= RELEASE_FPR_CI_CEILING,
        "release_policy": {
            "recall_ci95_lower_minimum": 0.80,
            "fpr_ci95_upper_maximum": RELEASE_FPR_CI_CEILING,
            "attack_support_minimum": MIN_RELEASE_ATTACK_SUPPORT,
            "benign_support_minimum_at_zero_fp": MIN_BENIGN_SUPPORT_ZERO_FP,
        },
        "capture_role": "new official MCFP source-family holdout; not used for v3 training or threshold selection",
        "label_policy": expected_registration["label_policy"],
        "research_only": True, "promotion_eligible": False,
        "enforcement_applied": False,
    }
    report["report_path"] = str(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    report["report_sha256"] = sha256_file(report_path)
    attempt.update({"state": "completed", "report_sha256": report["report_sha256"],
                    "completed_at_utc": datetime.now(timezone.utc).isoformat()})
    attempt_path.write_text(json.dumps(attempt, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_cesnet_cc25_v3(args) -> None:
    """Registered one-pass evaluation of a frozen v3 or v9 flow model on CESNET-CC25.

    The publisher's chronological `test.csv` flow partitions are used for all
    botnet captures. The separately published benign IPFIX archive is scored
    in full. Only flow statistics available to the live v3 feature contract
    are mapped; IPs, ports, labels, capture names and periodic-series fields
    never enter the model.
    """
    from integrityguard.network_flow_model import (
        FLOW_V3_FEATURE_NAMES, _FlowV3AutoencoderClassifier,
    )

    candidate_path = Path(args.candidate).resolve(strict=True)
    botnet_path = Path(args.botnet_flow_archive).resolve(strict=True)
    benign_path = Path(args.benign_archive).resolve(strict=True)
    registration_path = Path(args.registration_file or "").resolve(strict=True)
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    candidate_sha = sha256_file(candidate_path).lower()
    if candidate_sha != str(args.expected_candidate_sha256 or "").lower():
        raise ValueError("Candidate SHA-256 differs from pre-registration")
    feature_version = int(artifact.get("feature_version", -1))
    if feature_version == 3:
        feature_names = list(FLOW_V3_FEATURE_NAMES)
        if artifact.get("features") != feature_names:
            raise ValueError("Candidate v3 feature contract is invalid")
    elif feature_version == 9:
        from integrityguard import network_flow_schema_v9 as flow_v9
        feature_names = list(flow_v9.FEATURE_NAMES)
        if artifact.get("feature_names") != feature_names:
            raise ValueError("Candidate v9 feature contract is invalid")
    elif feature_version == 10:
        from integrityguard import network_flow_schema_v9 as flow_v9
        from integrityguard import network_flow_schema_v10 as flow_v10
        feature_names = list(artifact.get("feature_names") or [])
        if (artifact.get("feature_profile") != "ctu_ports_only_v10"
                or feature_names != list(flow_v10.FEATURE_NAMES[:40])):
            raise ValueError("Candidate v10 feature contract/profile is invalid")
    else:
        raise ValueError("CESNET evaluator supports only registered v3, v9, or v10 flow candidates")
    if artifact.get("classes") != ["benign", "attack"]:
        raise ValueError("Candidate class order must be [benign, attack]")
    threshold = float(args.threshold)
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Supply the frozen validation threshold")
    if not math.isclose(float(artifact.get("threshold", -1)), threshold, rel_tol=0, abs_tol=1e-12):
        raise ValueError("Threshold differs from the candidate's frozen validation threshold")
    if feature_version == 3:
        manifest_path = candidate_path.with_name("network_flow_v3_candidate_manifest.json")
    else:
        manifest_path = candidate_path.with_name("validation_weight_experiment.json")
    manifest_sha = sha256_file(manifest_path).lower()
    botnet_sha = sha256_file(botnet_path).lower()
    benign_sha = sha256_file(benign_path).lower()
    if botnet_sha != str(args.expected_sha256 or "").lower():
        raise ValueError("Botnet IP-flow archive SHA-256 differs from pre-registration")
    if benign_sha != str(args.expected_benign_sha256 or "").lower():
        raise ValueError("Benign IP-flow archive SHA-256 differs from pre-registration")

    def md5_file(path: Path) -> str:
        digest = hashlib.md5()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    botnet_md5, benign_md5 = md5_file(botnet_path), md5_file(benign_path)
    if botnet_md5 != "4df0c80a20e6d6f74d91f406d7ca4b48":
        raise ValueError("Botnet IP-flow archive differs from the publisher checksum")
    if benign_md5 != "f2e44c43391cefb1a36c780bf983563a":
        raise ValueError("Benign IP-flow archive differs from the publisher checksum")
    evaluator_sha = sha256_file(Path(__file__).resolve()).lower()
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    expected_registration = {
        "dataset": "CESNET-CC25",
        "botnet_archive_sha256": botnet_sha,
        "botnet_publisher_md5": botnet_md5,
        "benign_archive_sha256": benign_sha,
        "benign_publisher_md5": benign_md5,
        "candidate_sha256": candidate_sha,
        "candidate_manifest_sha256": manifest_sha,
        "threshold": threshold,
        "evaluator_sha256": evaluator_sha,
        "botnet_split": "all publisher test.csv members; chronological test partition per botnet sample",
        "benign_split": "all publisher benign IP-flow CSV members",
        "label_policy": "publisher botnet C&C test partition=attack; publisher benign IP-flow archive=benign; invalid flow rows excluded",
        "purpose": "one-pass independent source-family external diagnostic; no training or threshold selection on CESNET-CC25",
    }
    if feature_version == 10:
        expected_registration.update({
            "feature_version": 10,
            "feature_profile": "ctu_ports_only_v10",
            "feature_names": feature_names,
            "feature_policy": "v9 flow statistics plus observed source/destination ports and fixed destination-port indicators; TCP handshake flags excluded; IPs, labels, capture IDs, and packet-series fields excluded",
            "prior_aborted_attempt": "A prior v3 attempt read part of the archives but was aborted before scoring; no scores/metrics were emitted or used. This registration is the reserved multi-capture development candidate test.",
        })
    if any(registration.get(key) != value for key, value in expected_registration.items()):
        raise ValueError("Registration does not match hashes, split, threshold, labels, or evaluator")
    train_sources = json.dumps(artifact.get("training_captures", artifact.get("train_captures", [])),
                               ensure_ascii=False).lower()
    if "cesnet" in train_sources:
        raise ValueError("Candidate training provenance includes CESNET-CC25")

    report_path = registration_path.with_name(registration_path.stem + "-one-pass-evaluation.json")
    attempt_path = registration_path.with_name(registration_path.stem + ".attempt.json")
    if report_path.exists() or attempt_path.exists():
        raise FileExistsError("This registered CESNET evaluation has already been attempted or reported")
    attempt = {
        "dataset": "CESNET-CC25", "candidate_sha256": candidate_sha,
        "registration_sha256": sha256_file(registration_path), "state": "started",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "score_passes": 1, "source_read_partially_before_registration": True,
        "prior_attempt_note": "Previous attempt was aborted before scoring and emitted no metrics.",
    }
    with attempt_path.open("x", encoding="utf-8") as stream:
        json.dump(attempt, stream, indent=2)
        stream.flush()
        import os
        os.fsync(stream.fileno())

    mean = torch.as_tensor(artifact["mean"], dtype=torch.float32)
    if feature_version == 3:
        scale = torch.as_tensor(artifact["std"], dtype=torch.float32)
        model = _FlowV3AutoencoderClassifier()
    else:
        scale = torch.as_tensor(artifact["scale"], dtype=torch.float32)
        inferred_width = int(artifact["state_dict"]["layers.0.weight"].shape[0])
        model = MLP(len(feature_names), int(artifact.get("hidden_width") or inferred_width))
    if mean.numel() != len(feature_names) or scale.numel() != len(feature_names):
        raise ValueError(f"Candidate normalization dimensions do not match v{feature_version}")
    model.load_state_dict(artifact["state_dict"])
    model.eval()

    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
              "rows_seen": 0, "rows_scored": 0, "invalid_rows": 0}
    per_source: dict[str, dict] = {}
    latencies_ms: list[float] = []
    batch_x: list[list[float]] = []
    batch_y: list[int] = []
    batch_source: list[str] = []

    def source_counts(source: str) -> dict:
        return per_source.setdefault(source, {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
            "rows_seen": 0, "rows_scored": 0, "invalid_rows": 0})

    def score_batch() -> None:
        if not batch_x:
            return
        values = (torch.as_tensor(np.asarray(batch_x, dtype=np.float32)) - mean) / torch.where(
            scale.abs() < 1e-6, torch.ones_like(scale), scale)
        started = time.perf_counter()
        with torch.no_grad():
            outputs = model(values)
            if feature_version == 3:
                outputs = outputs[1]
            probabilities = torch.softmax(outputs, dim=1)[:, 1].numpy()
        latencies_ms.append((time.perf_counter() - started) * 1000.0)
        predicted = probabilities >= threshold
        actual = np.asarray(batch_y, dtype=np.bool_)
        if len(set(batch_source)) != 1 or len(set(batch_y)) != 1:
            raise ValueError("Evaluation batch crossed a source or label boundary")
        source = batch_source[0]
        target = source_counts(source)
        batch_counts = {
            "tp": int(np.count_nonzero(predicted & actual)),
            "fp": int(np.count_nonzero(predicted & ~actual)),
            "fn": int(np.count_nonzero(~predicted & actual)),
            "tn": int(np.count_nonzero(~predicted & ~actual)),
        }
        for key, value in batch_counts.items():
            target[key] += value
            counts[key] += value
        target["rows_scored"] += len(batch_y)
        counts["rows_scored"] += len(batch_y)
        batch_x.clear(); batch_y.clear(); batch_source.clear()

    def process_csv_rows(stream, source: str, label: int) -> None:
        reader = csv.DictReader((line.decode("utf-8", errors="replace") for line in stream))
        if not reader.fieldnames:
            return
        columns = {name.split()[-1]: name for name in reader.fieldnames}
        required = {"TIME_FIRST", "TIME_LAST", "PACKETS", "PACKETS_REV",
                    "BYTES", "BYTES_REV", "PROTOCOL"}
        if not required.issubset(columns):
            raise ValueError(f"Unexpected IPFIX schema in {source}: missing {sorted(required-set(columns))}")
        target = source_counts(source)
        for row in reader:
            counts["rows_seen"] += 1
            target["rows_seen"] += 1
            try:
                first = datetime.fromisoformat(row[columns["TIME_FIRST"]].replace("Z", "+00:00"))
                last = datetime.fromisoformat(row[columns["TIME_LAST"]].replace("Z", "+00:00"))
                duration = (last - first).total_seconds()
                if duration < 0:
                    raise ValueError("flow end precedes start")
                packets_a = float(row[columns["PACKETS"]])
                packets_b = float(row[columns["PACKETS_REV"]])
                bytes_a = float(row[columns["BYTES"]])
                bytes_b = float(row[columns["BYTES_REV"]])
                proto_number = int(row[columns["PROTOCOL"]])
                if min(packets_a, packets_b, bytes_a, bytes_b) < 0:
                    raise ValueError("negative counter")
                protocol = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(proto_number, "other")
                if feature_version == 3:
                    vector = flow_v8.feature_vector(duration, packets_a + packets_b,
                        bytes_a + bytes_b, bytes_a, bytes_b, protocol)[:len(feature_names)]
                elif feature_version == 9:
                    vector = flow_v9.from_live_flow({
                        "duration_seconds": duration,
                        "total_packets": packets_a + packets_b,
                        "total_bytes": bytes_a + bytes_b,
                        "direction_a_bytes": bytes_a,
                        "direction_b_bytes": bytes_b,
                        "protocol": protocol,
                    })
                else:
                    from integrityguard import network_flow_schema_v10 as flow_v10
                    base = flow_v9.from_live_flow({
                        "duration_seconds": duration,
                        "total_packets": packets_a + packets_b,
                        "total_bytes": bytes_a + bytes_b,
                        "direction_a_bytes": bytes_a,
                        "direction_b_bytes": bytes_b,
                        "protocol": protocol,
                    })
                    origin_port = int(row[columns["SRC_PORT"]])
                    destination_port = int(row[columns["DST_PORT"]])
                    full_vector = base + flow_v10._transport_features(
                        protocol, origin_port, destination_port)
                    vector = [full_vector[flow_v10.FEATURE_NAMES.index(name)]
                              for name in feature_names]
                if not all(math.isfinite(value) for value in vector):
                    raise ValueError("non-finite feature")
            except (KeyError, TypeError, ValueError, OverflowError):
                counts["invalid_rows"] += 1
                target["invalid_rows"] += 1
                continue
            batch_x.append(vector); batch_y.append(label); batch_source.append(source)
            if len(batch_x) >= 8192:
                score_batch()
        score_batch()

    with tarfile.open(botnet_path, mode="r|gz") as archive:
        for member in archive:
            normalized = member.name.replace("\\", "/")
            if (not member.isfile() or not normalized.startswith("botnet/") or "/._" in normalized
                    or Path(normalized).name.startswith("._")
                    or not normalized.endswith("/test.csv")):
                continue
            stream = archive.extractfile(member)
            if stream is not None:
                process_csv_rows(stream, "attack:" + normalized.rsplit("/", 2)[-2], 1)
    score_batch()
    with tarfile.open(benign_path, mode="r|gz") as archive:
        for member in archive:
            normalized = member.name.replace("\\", "/")
            if (not member.isfile() or not normalized.startswith("benign/")
                    or "/._" in normalized or Path(normalized).name.startswith("._")
                    or not normalized.lower().endswith(".csv")):
                continue
            stream = archive.extractfile(member)
            if stream is not None:
                process_csv_rows(stream, "benign:" + normalized, 0)
    score_batch()

    attacks, benign = counts["tp"] + counts["fn"], counts["fp"] + counts["tn"]
    recall_lower = (1.0 - float(wilson_upper(np.asarray([counts["fn"]]), np.asarray([attacks]))[0])
                    if attacks else 0.0)
    fpr_upper = (float(wilson_upper(np.asarray([counts["fp"]]), np.asarray([benign]))[0])
                 if benign else 1.0)
    for source_counts_value in per_source.values():
        source_attacks = source_counts_value["tp"] + source_counts_value["fn"]
        source_benign = source_counts_value["fp"] + source_counts_value["tn"]
        source_counts_value["attack"] = source_attacks
        source_counts_value["benign"] = source_benign
        source_counts_value["recall_ci95_lower"] = (
            1.0 - float(wilson_upper(np.asarray([source_counts_value["fn"]]),
                                    np.asarray([source_attacks]))[0]) if source_attacks else None)
        source_counts_value["fpr_ci95_upper"] = (
            float(wilson_upper(np.asarray([source_counts_value["fp"]]),
                               np.asarray([source_benign]))[0]) if source_benign else None)
    report = {
        "dataset": "CESNET-CC25", "candidate_sha256": candidate_sha,
        "candidate_manifest_sha256": manifest_sha, "evaluator_sha256": evaluator_sha,
        "registration_sha256": sha256_file(registration_path),
        "botnet_archive_sha256": botnet_sha, "botnet_publisher_md5": botnet_md5,
        "benign_archive_sha256": benign_sha, "benign_publisher_md5": benign_md5,
        "botnet_split": expected_registration["botnet_split"],
        "benign_split": expected_registration["benign_split"],
        "threshold": threshold, "threshold_source": "frozen candidate threshold selected on CTU-13 validation capture 45",
        "feature_version": feature_version, "features": feature_names,
        "feature_adapter": f"IPFIX timestamps, bidirectional packet/byte counters and protocol mapped to v{feature_version} flow contract; identifiers and publisher metadata excluded",
        "label_policy": expected_registration["label_policy"],
        "counts": {**counts, "attack": attacks, "benign": benign},
        "confusion": {key: counts[key] for key in ("tp", "fp", "fn", "tn")},
        "recall": counts["tp"] / attacks if attacks else 0.0,
        "recall_ci95_lower": recall_lower,
        "fpr": counts["fp"] / benign if benign else 1.0,
        "fpr_ci95_upper": fpr_upper,
        "minimum_sample_gate_met": attacks >= MIN_RELEASE_ATTACK_SUPPORT and benign >= MIN_BENIGN_SUPPORT_ZERO_FP,
        "recall_gate_met": attacks >= MIN_RELEASE_ATTACK_SUPPORT and recall_lower >= .80,
        "fpr_gate_met": benign >= MIN_BENIGN_SUPPORT_ZERO_FP and fpr_upper <= RELEASE_FPR_CI_CEILING,
        "per_source": per_source,
        "batch_inference_p95_ms": float(np.percentile(latencies_ms, 95)) if latencies_ms else None,
        "interval_note": "Per-flow Wilson intervals do not adjust for temporal, device, or capture clustering.",
        "source_provenance_note": "CESNET botnet test flows are generated in malware VMs while benign flows come from the live CESNET3 backbone; class/source domain is confounded, so passing or failing this source test alone does not establish target-network performance.",
        "research_only": True, "promotion_eligible": False, "enforcement_applied": False,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    attempt.update({"state": "completed", "finished_at_utc": datetime.now(timezone.utc).isoformat(),
                    "report_sha256": sha256_file(report_path)})
    temp_attempt = attempt_path.with_name(attempt_path.name + ".tmp")
    with temp_attempt.open("w", encoding="utf-8") as stream:
        json.dump(attempt, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp_attempt, attempt_path)
    report["report_path"] = str(report_path)
    report["report_sha256"] = sha256_file(report_path)
    print(json.dumps(report, indent=2), flush=True)


def evaluate_litnet2020_v3(args) -> None:
    """One-pass, registered external test of frozen live-v3 on LITNET-2020.

    The source is a real-world NetFlow v9 export. Only the core flow statistics
    used by the deployed v3 contract enter the model; identifiers, ports,
    flags, attack-derived columns, and source labels are excluded.
    """
    import io
    from integrityguard.network_flow_model import (
        FLOW_V3_FEATURE_NAMES, _FlowV3AutoencoderClassifier,
    )

    candidate_path = Path(args.candidate).resolve(strict=True)
    archive_path = Path(args.litnet_archive).resolve(strict=True)
    registration_path = Path(args.registration_file or "").resolve(strict=True)
    audit_path = Path(args.litnet_audit).resolve(strict=True)
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    candidate_sha = sha256_file(candidate_path).lower()
    archive_sha = sha256_file(archive_path).lower()
    audit_sha = sha256_file(audit_path).lower()
    if candidate_sha != str(args.expected_candidate_sha256 or "").lower():
        raise ValueError("Candidate SHA-256 differs from LITNET pre-registration")
    if archive_sha != str(args.expected_sha256 or "").lower():
        raise ValueError("LITNET archive SHA-256 differs from pre-registration")
    if audit_sha != str(args.expected_litnet_audit_sha256 or "").lower():
        raise ValueError("LITNET source-audit SHA-256 differs from pre-registration")
    if (artifact.get("feature_version") != 3
            or artifact.get("features") != list(FLOW_V3_FEATURE_NAMES)
            or artifact.get("classes") != ["benign", "attack"]):
        raise ValueError("Candidate is not the deployed v3 binary flow classifier")
    threshold = float(args.threshold)
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Supply the frozen validation threshold")
    if not math.isclose(float(artifact.get("threshold", -1)), threshold, rel_tol=0, abs_tol=1e-12):
        raise ValueError("Threshold differs from the candidate's frozen validation threshold")
    manifest_path = candidate_path.with_name("network_flow_v3_candidate_manifest.json")
    manifest_sha = sha256_file(manifest_path).lower()
    evaluator_sha = sha256_file(Path(__file__).resolve()).lower()
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    expected_registration = {
        "dataset": "LITNET-2020",
        "archive_sha256": archive_sha,
        "source_audit_sha256": audit_sha,
        "candidate_sha256": candidate_sha,
        "candidate_manifest_sha256": manifest_sha,
        "threshold": threshold,
        "evaluator_sha256": evaluator_sha,
        "csv_member": "allFlows.csv",
        "split": "complete publisher archive; untouched source family; no row split",
        "label_policy": "header attack_a=1 attack, 0 normal; all other labels excluded",
        "feature_policy": "td, ipkt, ibyt, opkt, obyt, pr mapped to live v3; all IDs, endpoints, ports, flags, attack-derived columns and labels excluded",
        "purpose": "one-pass external diagnostic only; no training, feature selection, or threshold tuning on LITNET-2020",
    }
    if any(registration.get(key) != value for key, value in expected_registration.items()):
        raise ValueError("LITNET registration does not match hashes, split, threshold, labels, or evaluator")
    training_provenance = json.dumps(artifact.get("train_captures", []), ensure_ascii=False).lower()
    if "litnet" in training_provenance:
        raise ValueError("Candidate training provenance includes LITNET-2020")

    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    expected_rows = {"0": 36_423_860, "1": 3_179_814}
    if (audit.get("rows") != sum(expected_rows.values())
            or audit.get("label_counts") != {"label:0": expected_rows["0"],
                                               "label:1": expected_rows["1"]}
            or audit.get("row_width_counts") != {"85": sum(expected_rows.values())}
            or audit.get("invalid_numeric_or_width") != {}
            or audit.get("archive_sha256", "").lower() != archive_sha):
        raise ValueError("LITNET archive no longer matches the completed pre-score row audit")

    mean = torch.as_tensor(artifact["mean"], dtype=torch.float32)
    std = torch.as_tensor(artifact["std"], dtype=torch.float32)
    if mean.numel() != len(FLOW_V3_FEATURE_NAMES) or std.numel() != len(FLOW_V3_FEATURE_NAMES):
        raise ValueError("Candidate normalization dimensions do not match v3")
    model = _FlowV3AutoencoderClassifier()
    model.load_state_dict(artifact["state_dict"])
    model.eval()

    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
              "rows_seen": 0, "rows_scored": 0, "unknown_labels": 0,
              "invalid_rows": 0}
    per_day: dict[str, dict] = {}
    per_attack_type: dict[str, dict] = {}
    batch_x: dict[tuple[str, int, str], list[list[float]]] = {}
    inference_batch_ms: list[float] = []

    def metrics_for(target: dict, labels: int | None = None) -> dict:
        attack_n = target["tp"] + target["fn"]
        benign_n = target["fp"] + target["tn"]
        recall = target["tp"] / attack_n if attack_n else None
        fpr = target["fp"] / benign_n if benign_n else None
        recall_lower = (1.0 - float(wilson_upper(np.asarray([target["fn"]]),
                                                 np.asarray([attack_n]))[0])
                        if attack_n else None)
        fpr_upper = (float(wilson_upper(np.asarray([target["fp"]]),
                                        np.asarray([benign_n]))[0])
                     if benign_n else None)
        return {
            **target, "attack": attack_n, "benign": benign_n,
            "recall": recall, "recall_ci95_lower_wilson": recall_lower,
            "fpr": fpr, "fpr_ci95_upper_wilson": fpr_upper,
        }

    def blank_counts() -> dict:
        return {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "rows": 0}

    def score_group(key: tuple[str, int, str], vectors: list[list[float]]) -> None:
        if not vectors:
            return
        x = (torch.as_tensor(np.asarray(vectors, dtype=np.float32)) - mean) / torch.where(
            std.abs() < 1e-6, torch.ones_like(std), std)
        started = time.perf_counter()
        with torch.no_grad():
            probabilities = torch.softmax(model(x)[1], dim=1)[:, 1].cpu().numpy()
        inference_batch_ms.append((time.perf_counter() - started) * 1000.0)
        predicted = probabilities >= threshold
        label = bool(key[1])
        target_day = per_day.setdefault(key[0], blank_counts())
        target_type = per_attack_type.setdefault(key[2], blank_counts())
        for target in (counts, target_day, target_type):
            if label:
                target["tp"] += int(np.count_nonzero(predicted))
                target["fn"] += int(len(predicted) - np.count_nonzero(predicted))
            else:
                target["fp"] += int(np.count_nonzero(predicted))
                target["tn"] += int(len(predicted) - np.count_nonzero(predicted))
            if target is not counts:
                target["rows"] += len(predicted)
        counts["rows_scored"] += len(predicted)

    def flush(key: tuple[str, int, str]) -> None:
        vectors = batch_x.pop(key, [])
        if vectors:
            score_group(key, vectors)

    def wilson_report(target: dict) -> dict:
        return metrics_for(target)

    required_header = {
        "ts_year", "ts_month", "ts_day", "td", "pr", "ipkt", "ibyt",
        "opkt", "obyt", "attack_t", "attack_a",
    }
    with zipfile.ZipFile(archive_path, "r") as archive:
        if archive.namelist() != ["allFlows.csv"]:
            raise ValueError("LITNET archive member list differs from source audit")
        with io.TextIOWrapper(archive.open("allFlows.csv", "r"),
                              encoding="utf-8-sig", errors="strict", newline="") as stream:
            reader = csv.reader(stream)
            header = next(reader, None)
            if not header or len(header) != 85 or not required_header.issubset(header):
                raise ValueError("Unexpected LITNET CSV header")
            column = {name: header.index(name) for name in required_header}
            for row in reader:
                counts["rows_seen"] += 1
                if len(row) != len(header):
                    counts["invalid_rows"] += 1
                    continue
                label_text = row[column["attack_a"]].strip()
                if label_text not in {"0", "1"}:
                    counts["unknown_labels"] += 1
                    continue
                label = int(label_text)
                day = "-".join(row[column[name]].strip().zfill(2) for name in
                               ("ts_year", "ts_month", "ts_day"))
                attack_type = row[column["attack_t"]].strip() if label else "normal"
                if not attack_type or attack_type in {"blank", "none"}:
                    counts["invalid_rows"] += 1
                    continue
                try:
                    duration = float(row[column["td"]])
                    in_packets = float(row[column["ipkt"]]); out_packets = float(row[column["opkt"]])
                    in_bytes = float(row[column["ibyt"]]); out_bytes = float(row[column["obyt"]])
                    if any(not math.isfinite(v) or v < 0 for v in
                           (duration, in_packets, out_packets, in_bytes, out_bytes)):
                        raise ValueError("invalid flow statistic")
                    protocol = row[column["pr"]].strip().lower()
                    if protocol == "icmp6":
                        protocol = "icmpv6"
                    vector = flow_v8.feature_vector(duration, in_packets + out_packets,
                        in_bytes + out_bytes, in_bytes, out_bytes,
                        protocol)[:len(FLOW_V3_FEATURE_NAMES)]
                    if not all(math.isfinite(value) for value in vector):
                        raise ValueError("non-finite model input")
                except (IndexError, TypeError, ValueError, OverflowError):
                    counts["invalid_rows"] += 1
                    continue
                key = (day, label, attack_type)
                vectors = batch_x.setdefault(key, [])
                vectors.append(vector)
                if len(vectors) >= 8192:
                    flush(key)
                if counts["rows_seen"] % 5_000_000 == 0:
                    print(f"LITNET rows read={counts['rows_seen']:,}; scored={counts['rows_scored']:,}", flush=True)
    for key in list(batch_x):
        flush(key)

    if counts["rows_seen"] != 39_603_674 or counts["rows_scored"] != 39_603_674:
        raise ValueError("Scored row totals differ from the preregistered LITNET audit")
    attacks = counts["tp"] + counts["fn"]
    benign = counts["fp"] + counts["tn"]
    report = {
        "dataset": "LITNET-2020", "candidate_sha256": candidate_sha,
        "candidate_manifest_sha256": manifest_sha, "evaluator_sha256": evaluator_sha,
        "registration_sha256": sha256_file(registration_path),
        "archive_sha256": archive_sha, "source_audit_sha256": audit_sha,
        "split": expected_registration["split"],
        "threshold": threshold,
        "threshold_source": "frozen checkpoint threshold selected on CTU-13 validation capture 45",
        "feature_version": 3, "features": list(FLOW_V3_FEATURE_NAMES),
        "feature_adapter": "LITNET NetFlow v9 td, ipkt/ibyt, opkt/obyt, pr mapped to v3; all IDs, endpoints, ports, flags, generated attack features and labels excluded",
        "label_policy": expected_registration["label_policy"],
        "counts": {**counts, "attack": attacks, "benign": benign},
        "confusion": {key: counts[key] for key in ("tp", "fp", "fn", "tn")},
        "recall": counts["tp"] / attacks if attacks else None,
        "recall_ci95_lower_wilson": metrics_for(counts)["recall_ci95_lower_wilson"],
        "fpr": counts["fp"] / benign if benign else None,
        "fpr_ci95_upper_wilson": metrics_for(counts)["fpr_ci95_upper_wilson"],
        "minimum_sample_gate_met": attacks >= MIN_RELEASE_ATTACK_SUPPORT and benign >= MIN_BENIGN_SUPPORT_ZERO_FP,
        "recall_gate_met": attacks >= MIN_RELEASE_ATTACK_SUPPORT and metrics_for(counts)["recall_ci95_lower_wilson"] >= .80,
        "fpr_gate_met": benign >= MIN_BENIGN_SUPPORT_ZERO_FP and metrics_for(counts)["fpr_ci95_upper_wilson"] <= RELEASE_FPR_CI_CEILING,
        "per_day": {day: wilson_report(day_counts) for day, day_counts in sorted(per_day.items())},
        "per_attack_type": {name: wilson_report(type_counts) for name, type_counts in sorted(per_attack_type.items())},
        "batch_inference_p95_ms": float(np.percentile(inference_batch_ms, 95)) if inference_batch_ms else None,
        "interval_note": "Wilson intervals treat flows as independent and do not adjust for temporal, exporter, or event clustering; not a target-network release CI.",
        "label_quality_note": "Published LITNET labels include rule-based flow attribution; external diagnostic only, not incident-adjudicated target-network evidence.",
        "research_only": True, "promotion_eligible": False, "enforcement_applied": False,
    }
    report_path = registration_path.with_name(registration_path.stem + "-one-pass-evaluation.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["report_path"] = str(report_path)
    report["report_sha256"] = sha256_file(report_path)
    print(json.dumps(report, indent=2), flush=True)


def load_capture(capture_id: str, path: Path, *, include_raw_labels: bool = False):
    if not path.is_file():
        raise FileNotFoundError(f"Missing fixed-split capture {capture_id}: {path}")
    if capture_id in CTU_IDSEVAL6_TRAIN_MEMBERS:
        expected_path = (DATA / "official-ctu-idseval-6" / "zeek.zip").resolve()
        if path.resolve() != expected_path:
            raise ValueError("Unexpected CTU-IDSEVAL-6 training archive path")
        zeek_sha = sha256_file(path).lower()
        if zeek_sha != CTU_IDSEVAL6_ZEEK_SHA256:
            raise ValueError("CTU-IDSEVAL-6 Zeek archive SHA-256 mismatch; training stopped")
        md5 = hashlib.md5()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                md5.update(chunk)
        if md5.hexdigest() != CTU_IDSEVAL6_ZEEK_MD5:
            raise ValueError("CTU-IDSEVAL-6 Zeek archive differs from publisher checksum")
        labels_path = DATA / "official-ctu-idseval-6" / "labels.zip"
        if not labels_path.is_file() or sha256_file(labels_path).lower() != CTU_IDSEVAL6_LABELS_SHA256:
            raise ValueError("CTU-IDSEVAL-6 publisher label archive is missing or changed")
        labels_md5 = hashlib.md5()
        with labels_path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                labels_md5.update(chunk)
        if labels_md5.hexdigest() != CTU_IDSEVAL6_LABELS_MD5:
            raise ValueError("CTU-IDSEVAL-6 label archive differs from publisher checksum")

        member_name = f"zeek/{CTU_IDSEVAL6_TRAIN_MEMBERS[capture_id]}"
        features, labels, udp, raw_labels = [], [], [], []
        excluded = 0
        explicit_rows = 0
        with zipfile.ZipFile(path, "r") as archive:
            if member_name not in archive.namelist():
                raise ValueError(f"Missing registered CTU-IDSEVAL-6 training capture: {member_name}")
            with archive.open(member_name, "r") as stream:
                fields = None
                for raw in stream:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("#fields\t"):
                        fields = line.split("\t")[1:]
                        continue
                    if not line or line.startswith("#") or fields is None:
                        continue
                    values = line.split("\t")
                    if len(values) != len(fields):
                        excluded += 1
                        continue
                    row = dict(zip(fields, values))
                    label = (row.get("label") or "").strip().lower()
                    if label not in {"benign", "malicious"}:
                        excluded += 1
                        continue
                    explicit_rows += 1
                    try:
                        vector = feature_from_zeek_mapping(row)
                    except (TypeError, ValueError, OverflowError):
                        excluded += 1
                        continue
                    features.append(vector)
                    labels.append(int(label == "malicious"))
                    udp.append(int(vector[5] > 0.5))
                    raw_labels.append(f"publisher:CTU-IDSEVAL-6:{label}")
        if not labels or (not any(labels) and capture_id != "ctu6-b"):
            raise ValueError(f"CTU-IDSEVAL-6 capture {capture_id} has no usable explicit attack labels")
        if capture_id == "ctu6-b" and any(labels):
            raise ValueError("CTU-IDSEVAL-6 benign-user capture unexpectedly contains attack labels")
        result = (np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int64),
                  np.asarray(udp, dtype=np.bool_), excluded)
        print(f"CTU-IDSEVAL-6 {capture_id} label audit: explicit={explicit_rows} "
              f"scored={len(labels)} excluded={excluded}; only publisher benign/malicious included",
              flush=True)
        return result + (raw_labels,) if include_raw_labels else result
    if capture_id == "sme11-win7ad1":
        # This source was already consumed as a one-pass independent test for
        # the previous candidate. It is development data now and must never be
        # described as independent evidence again.
        if path.resolve() != CTU_ADDITIONAL_TRAIN_CAPTURES[capture_id].resolve():
            raise ValueError("Unexpected CTU-SME-11 training archive path")
        archive_sha = sha256_file(path).upper()
        if archive_sha != CTU_SME11_WIN7AD1_SHA256.upper():
            raise ValueError("CTU-SME-11 archive SHA-256 mismatch; training stopped")
        md5 = hashlib.md5()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                md5.update(chunk)
        if md5.hexdigest() != CTU_SME11_WIN7AD1_MD5:
            raise ValueError("CTU-SME-11 archive differs from the publisher checksum")

        features, labels, udp, raw_labels = [], [], [], []
        excluded = 0
        explicit_rows = 0
        with tarfile.open(path, mode="r|bz2") as archive:
            for member in archive:
                if not member.isfile() or not member.name.endswith("/zeek/conn.log.labeled"):
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                fields = None
                for raw in stream:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("#fields\t"):
                        fields = line.split("\t")[1:]
                        continue
                    if not line or line.startswith("#") or fields is None:
                        continue
                    values = line.split("\t")
                    row = dict(zip(fields, values))
                    label = (row.get("label") or "").strip().lower()
                    if label not in {"benign", "malicious"}:
                        excluded += 1
                        continue
                    explicit_rows += 1
                    if len(values) != len(fields):
                        excluded += 1
                        continue
                    try:
                        vector = feature_from_zeek_mapping(row)
                    except (TypeError, ValueError, OverflowError):
                        excluded += 1
                        continue
                    features.append(vector)
                    labels.append(int(label == "malicious"))
                    udp.append(int(vector[5] > 0.5))
                    raw_labels.append(f"publisher:CTU-SME-11:{label}")
        if not labels or not any(labels) or all(labels):
            raise ValueError("CTU-SME-11 training source must contain usable explicit benign and malicious flows")
        result = (np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int64),
                  np.asarray(udp, dtype=np.bool_), excluded)
        print(f"CTU-SME-11 label audit: explicit={explicit_rows} scored={len(labels)} excluded={excluded}; "
              "only publisher labels benign/malicious included; background/unknown excluded", flush=True)
        return result + (raw_labels,) if include_raw_labels else result
    if capture_id == "normal12":
        if not CTU_NORMAL12_LABEL_CONFIG.is_file():
            raise FileNotFoundError(f"Missing publisher label rules: {CTU_NORMAL12_LABEL_CONFIG}")
        label_config_sha = sha256_file(CTU_NORMAL12_LABEL_CONFIG)
        if label_config_sha != CTU_NORMAL12_LABEL_CONFIG_SHA256:
            raise ValueError("CTU-Normal-12 labels.config changed; review provenance before training")
        features, labels, udp = [], [], []
        excluded = 0
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or not {"SrcAddr", "Label"}.issubset(reader.fieldnames):
                raise ValueError("CTU-Normal-12 flow file is missing SrcAddr/Label columns")
            for row in reader:
                # Publisher labels.config: Background srcIP=all, overridden by
                # Benign srcIP=10.0.0.46. All other rows remain Background.
                if (row.get("SrcAddr") or "").strip() != CTU_NORMAL12_HOST:
                    excluded += 1
                    continue
                # The capture is benign-only; reject unexpected nonempty labels
                # instead of silently applying this host-level label rule.
                if (row.get("Label") or "").strip():
                    excluded += 1
                    continue
                try:
                    vector = from_ctu_row(row)
                except (TypeError, ValueError, OverflowError):
                    excluded += 1
                    continue
                features.append(vector)
                labels.append(0)
                udp.append(int(vector[5] > 0.5))
        if not labels:
            raise ValueError("CTU-Normal-12 has no flows covered by the verified benign label rule")
        result = (np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int64),
                  np.asarray(udp, dtype=np.bool_), excluded)
        return result + (["publisher:Benign:SrcAddr=10.0.0.46"] * len(labels),) if include_raw_labels else result
    features, labels, udp, raw_labels = [], [], [], []
    excluded = 0
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "Label" not in reader.fieldnames:
            raise ValueError(f"Capture {capture_id} has no Label column")
        for row in reader:
            target = label_for_ctu(row.get("Label", ""))
            if target is None:
                excluded += 1
                continue
            try:
                vector = from_ctu_row(row)
            except (TypeError, ValueError, OverflowError):
                excluded += 1
                continue
            features.append(vector)
            labels.append(target)
            udp.append(int(vector[5] > 0.5))
            raw_labels.append(str(row.get("Label", "")).strip())
    if not labels:
        raise ValueError(f"Capture {capture_id} contains no usable explicit labels")
    result = (np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int64),
              np.asarray(udp, dtype=np.bool_), excluded)
    return result + (raw_labels,) if include_raw_labels else result


class MLP(nn.Module):
    def __init__(self, n_features: int, hidden_width: int = 128):
        super().__init__()
        if hidden_width < 64 or hidden_width % 2:
            raise ValueError("MLP hidden width must be an even integer >= 64")
        self.layers = nn.Sequential(
            nn.Linear(n_features, hidden_width), nn.ReLU(), nn.Dropout(0.20),
            nn.Linear(hidden_width, hidden_width // 2), nn.ReLU(), nn.Dropout(0.10),
            nn.Linear(hidden_width // 2, 2),
        )

    def forward(self, x):
        return self.layers(x)


def wilson_upper(successes: np.ndarray, totals: np.ndarray, z=1.959963984540054):
    totals = np.maximum(totals.astype(np.float64), 1.0)
    p = successes.astype(np.float64) / totals
    z2 = z * z
    den = 1.0 + z2 / totals
    center = p + z2 / (2.0 * totals)
    spread = z * np.sqrt((p * (1.0 - p) + z2 / (4.0 * totals)) / totals)
    return (center + spread) / den


def score_curve(probabilities: np.ndarray, labels: np.ndarray):
    """Exact empirical curve at unique score thresholds, descending."""
    order = np.argsort(-probabilities, kind="mergesort")
    sorted_scores = probabilities[order]
    sorted_labels = labels[order]
    ends = np.r_[np.flatnonzero(np.diff(sorted_scores)), len(sorted_scores) - 1]
    tp_cumulative = np.cumsum(sorted_labels == 1)[ends]
    fp_cumulative = np.cumsum(sorted_labels == 0)[ends]
    thresholds = sorted_scores[ends]
    positives = int(np.count_nonzero(labels == 1))
    negatives = int(np.count_nonzero(labels == 0))
    thresholds = np.r_[np.nextafter(thresholds[0], np.inf), thresholds]
    tp_cumulative = np.r_[0, tp_cumulative]
    fp_cumulative = np.r_[0, fp_cumulative]
    recall = tp_cumulative / max(positives, 1)
    fpr = fp_cumulative / max(negatives, 1)
    fpr_hi = wilson_upper(fp_cumulative, np.full_like(fp_cumulative, negatives))
    return thresholds, recall, fpr, fpr_hi, tp_cumulative, fp_cumulative


def select_joint_capture_threshold(scores: np.ndarray, capture_ids: list[str],
                                   capture_labels: list[np.ndarray], fpr_ceiling: float):
    """Pick one threshold whose Wilson FPR bound passes on every validation capture."""
    if not capture_labels or len(capture_ids) != len(capture_labels) or not len(scores):
        return None
    thresholds = np.unique(scores)
    thresholds = np.append(thresholds, np.nextafter(thresholds[-1], np.inf))
    curves = []
    offset = 0
    for labels in capture_labels:
        local_scores = scores[offset:offset + len(labels)]
        offset += len(labels)
        order = np.argsort(-local_scores, kind="mergesort")
        sorted_scores = local_scores[order]
        sorted_labels = labels[order]
        ends = np.r_[np.flatnonzero(np.diff(sorted_scores)), len(sorted_scores) - 1]
        local_thresholds = sorted_scores[ends]
        tp_curve = np.cumsum(sorted_labels == 1)[ends]
        fp_curve = np.cumsum(sorted_labels == 0)[ends]
        curves.append((local_thresholds, tp_curve, fp_curve,
                       int(np.count_nonzero(labels == 1)), int(np.count_nonzero(labels == 0))))

    per_capture = {}
    recall_lowers, eligible = [], np.ones(len(thresholds), dtype=bool)
    recall_values = []
    for capture_id, (local_thresholds, tp_curve, fp_curve, n_attack, n_benign) in zip(capture_ids, curves):
        positions = np.searchsorted(-local_thresholds, -thresholds, side="right") - 1
        predicted_tp = np.where(positions >= 0, tp_curve[np.maximum(positions, 0)], 0)
        predicted_fp = np.where(positions >= 0, fp_curve[np.maximum(positions, 0)], 0)
        fn = n_attack - predicted_tp
        fpr_upper = wilson_upper(predicted_fp, np.full(len(thresholds), n_benign))
        recall_lower = 1.0 - wilson_upper(fn, np.full(len(thresholds), n_attack))
        recall = predicted_tp / max(n_attack, 1)
        eligible &= fpr_upper <= fpr_ceiling
        recall_lowers.append(recall_lower)
        recall_values.append(recall)

    if not eligible.any():
        return None
    min_lower = np.min(np.stack(recall_lowers), axis=0)
    mean_recall = np.mean(np.stack(recall_values), axis=0)
    candidate_indices = np.flatnonzero(eligible)
    selected = candidate_indices[np.lexsort((mean_recall[candidate_indices],
                                              min_lower[candidate_indices]))[-1]]
    for capture_id, (local_thresholds, tp_curve, fp_curve, n_attack, n_benign) in zip(capture_ids, curves):
        position = int(np.searchsorted(-local_thresholds, -thresholds[selected], side="right") - 1)
        tp = int(tp_curve[position]) if position >= 0 else 0
        fp = int(fp_curve[position]) if position >= 0 else 0
        fn, tn = n_attack - tp, n_benign - fp
        per_capture[capture_id] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": tp / n_attack if n_attack else None,
            "recall_ci95_lower": (1.0 - float(wilson_upper(np.asarray([fn]),
                np.asarray([n_attack]))[0])) if n_attack else None,
            "fpr": fp / n_benign if n_benign else None,
            "fpr_ci95_upper": float(wilson_upper(np.asarray([fp]),
                np.asarray([n_benign]))[0]) if n_benign else None,
            "sample_gate_met": (n_attack >= MIN_RELEASE_ATTACK_SUPPORT
                                and n_benign >= MIN_BENIGN_SUPPORT_ZERO_FP),
        }
    return {"threshold": float(thresholds[selected]), "minimum_recall_ci95_lower": float(min_lower[selected]),
            "mean_recall": float(mean_recall[selected]), "per_capture": per_capture}


def predict(model, x, device):
    model.eval()
    result = []
    with torch.no_grad():
        for start in range(0, len(x), 65536):
            logits = model(torch.from_numpy(x[start:start + 65536]).to(device))
            result.extend(torch.softmax(logits, dim=1)[:, 1].cpu().numpy().tolist())
    return np.asarray(result, dtype=np.float64)


def predict_candidate_artifact(artifact, x, device):
    """Score one model or a saved ensemble using its own training normalization."""
    if artifact.get("ensemble_type") == "max_probability":
        scores = []
        for member in artifact["members"]:
            width = int(member["state_dict"]["layers.0.weight"].shape[0])
            model = MLP(len(member.get("feature_names", artifact.get("feature_names", FEATURE_NAMES))), width)
            model.load_state_dict(member["state_dict"])
            model.eval().to(device)
            mean = np.asarray(member["mean"], dtype=np.float32)
            scale = np.asarray(member["scale"], dtype=np.float32)
            normalized = np.clip((x - mean) / scale, -10.0, 10.0).astype(np.float32)
            scores.append(predict(model, normalized, device))
        return np.maximum.reduce(scores)

    width = int(artifact["state_dict"]["layers.0.weight"].shape[0])
    model = MLP(len(artifact.get("feature_names", FEATURE_NAMES)), width)
    model.load_state_dict(artifact["state_dict"])
    model.eval().to(device)
    mean = np.asarray(artifact["mean"], dtype=np.float32)
    scale = np.asarray(artifact["scale"], dtype=np.float32)
    normalized = np.clip((x - mean) / scale, -10.0, 10.0).astype(np.float32)
    return predict(model, normalized, device)


def evaluate_ctu_normal12_benign_diagnostic(args) -> None:
    """Run a preregistered one-pass benign-only FPR diagnostic, never a release test."""
    import os

    registration_path = Path(args.registration_file).resolve(strict=True)
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    if registration.get("status") != "preregistered_pending_review" \
            or registration.get("diagnostic_only") is not True:
        raise ValueError("Registration is not a pending diagnostic-only run")

    candidate_path = Path(registration["candidate"]["path"]).resolve(strict=True)
    manifest_path = Path(registration["candidate"]["manifest_path"]).resolve(strict=True)
    capture_path = Path(registration["source"]["capture_path"]).resolve(strict=True)
    labels_path = Path(registration["source"]["labels_config_path"]).resolve(strict=True)
    evaluator_path = Path(__file__).resolve(strict=True)
    schema_path = ROOT / "integrityguard" / "network_flow_schema_v9.py"
    expected_hashes = [
        (candidate_path, registration["candidate"]["sha256"]),
        (manifest_path, registration["candidate"]["manifest_sha256"]),
        (capture_path, registration["source"]["capture_sha256"]),
        (labels_path, registration["source"]["labels_config_sha256"]),
        (evaluator_path, registration["evaluator"]["sha256"]),
        (schema_path, registration["evaluator"]["feature_schema_sha256"]),
    ]
    # Only source identity is read before this point; labels and model scores
    # are untouched until every registered hash has passed.
    for path, expected in expected_hashes:
        if sha256_file(path).lower() != str(expected).lower():
            raise ValueError(f"SHA-256 mismatch for registered input: {path}")

    threshold = float(registration["decision"]["threshold"])
    if threshold != 0.7156407237052917:
        raise ValueError("Refusing any threshold other than the preregistered frozen value")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    scheme = next((item for item in manifest.get("schemes", [])
                   if item.get("name") == "class_balanced"), None)
    if (manifest.get("feature_version") != 9
            or manifest.get("feature_profile") != "full_v8"
            or not scheme
            or scheme.get("selected_at_fpr_ci_ceiling", {}).get("threshold") != threshold
            or "normal12" in manifest.get("split", {}).get("train", [])):
        raise ValueError("Candidate manifest no longer matches preregistered model/split/threshold")

    configure_feature_schema(9)
    artifact = torch.load(candidate_path, map_location="cpu", weights_only=True)
    from integrityguard import network_flow_schema_v9 as flow_v9
    if (artifact.get("feature_version") != 9
            or artifact.get("feature_names") != list(flow_v9.FEATURE_NAMES)
            or artifact.get("classes") != ["benign", "attack"]):
        raise ValueError("Checkpoint feature or class contract differs from registration")
    if not math.isclose(float(artifact.get("threshold", float("nan"))), threshold,
                        rel_tol=0, abs_tol=1e-12):
        raise ValueError("Checkpoint threshold differs from preregistered frozen threshold")

    report_path = registration_path.with_name("ctu-normal12-benign-diagnostic-report.json")
    marker_path = registration_path.with_name(registration_path.stem + ".attempt.json")
    registration_sha = sha256_file(registration_path)
    if marker_path.exists() or report_path.exists():
        raise FileExistsError("This registration has already been consumed or reported; refusing a second score")
    attempt = {
        "registration_sha256": registration_sha,
        "state": "started",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "score_passes": 1,
    }
    try:
        # Exclusive create is the one-shot boundary. It is deliberately before
        # load_capture, which is the first operation that parses labels/counts.
        with marker_path.open("x", encoding="utf-8") as stream:
            json.dump(attempt, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise FileExistsError("This registration has already been consumed; refusing a second score")

    def persist_attempt(state: str, error_type: str | None = None) -> None:
        attempt["state"] = state
        attempt["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        if error_type:
            attempt["error_type"] = error_type
        temp_path = marker_path.with_name(marker_path.name + ".tmp")
        with temp_path.open("w", encoding="utf-8") as stream:
            json.dump(attempt, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, marker_path)

    try:
        # This loader accepts only the registered benign host; Background and
        # unknown rows are excluded. No attack/reserved source is loaded here.
        x, y, _udp, excluded, raw_labels = load_capture(
            "normal12", capture_path, include_raw_labels=True)
        if not len(y) or np.any(y != 0):
            raise ValueError("Benign-only diagnostic source yielded non-benign or no scored rows")
        if set(raw_labels) != {"publisher:Benign:SrcAddr=10.0.0.46"}:
            raise ValueError("Unexpected label provenance in benign-only diagnostic")

        scores = predict_candidate_artifact(
            artifact, x, torch.device("cuda" if torch.cuda.is_available() else "cpu"))
        predicted = scores >= threshold
        fp = int(np.count_nonzero(predicted))
        tn = int(len(predicted) - fp)
        fpr = fp / len(predicted)
        fpr_upper = float(wilson_upper(np.asarray([fp]), np.asarray([len(predicted)]))[0])
        report = {
            "purpose": "one-pass benign-only CTU-Normal-12 FPR diagnostic",
            "diagnostic_only": True,
            "release_gate_result": "not_evaluated",
            "recall": None,
            "recall_ci95_lower": None,
            "attack_support": 0,
            "candidate_sha256": registration["candidate"]["sha256"],
            "candidate_manifest_sha256": registration["candidate"]["manifest_sha256"],
            "capture_sha256": registration["source"]["capture_sha256"],
            "labels_config_sha256": registration["source"]["labels_config_sha256"],
            "evaluator_sha256": registration["evaluator"]["sha256"],
            "feature_schema_sha256": registration["evaluator"]["feature_schema_sha256"],
            "registration_sha256": registration_sha,
            "threshold": threshold,
            "threshold_source": "frozen CTU v9 validation manifest; no tuning on Normal-12",
            "feature_version": 9,
            "feature_profile": "full_v8",
            "label_policy": "only SrcAddr=10.0.0.46 labeled Benign by publisher labels.config; all other Background/unknown excluded",
            "confusion_benign_only": {"fp": fp, "tn": tn},
            "benign_flows_scored": int(len(predicted)),
            "unknown_or_invalid_excluded": int(excluded),
            "fpr": fpr,
            "fpr_ci95_upper_wilson": fpr_upper,
            "fpr_interval_caveat": "Wilson per-flow interval on one capture is descriptive; flow correlation means it does not establish independent network-level FPR.",
            "research_only": True,
            "promotion_eligible": False,
            "enforcement_applied": False,
        }
        if report_path.exists():
            raise FileExistsError("Diagnostic report already exists; refusing to overwrite")
        with report_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        persist_attempt("completed")
        print(json.dumps(report, indent=2), flush=True)
    except BaseException as error:
        try:
            persist_attempt("aborted", type(error).__name__)
        except BaseException:
            # The original exclusive marker remains, so a failed audit update
            # still blocks any accidental second scoring attempt.
            pass
        raise


def build_ctu13_ensemble(args) -> None:
    """Build a development-only max-score ensemble with a joint whole-capture gate."""
    configure_feature_schema(args.ctu_feature_version)
    member_paths = [Path(args.candidate).resolve(), Path(args.candidate_secondary).resolve()]
    loaded = [torch.load(path, map_location="cpu", weights_only=True) for path in member_paths]
    for artifact in loaded:
        feature_names = artifact.get("feature_names")
        if (artifact.get("feature_version") != FEATURE_VERSION
                or not isinstance(feature_names, list) or not feature_names
                or len(set(feature_names)) != len(feature_names)
                or any(name not in FEATURE_NAMES for name in feature_names)
                or artifact.get("feature_profile") != args.ctu_feature_profile
                or artifact.get("classes") != ["benign", "attack"]
                or artifact.get("ensemble_type")):
            raise ValueError("Ensemble members must be compatible single CTU-13 MLP checkpoints")
    selected_feature_names = list(loaded[0]["feature_names"])
    if any(list(artifact["feature_names"]) != selected_feature_names for artifact in loaded[1:]):
        raise ValueError("Ensemble members must use the same registered feature subset")
    selected_indices = [FEATURE_NAMES.index(name) for name in selected_feature_names]
    validation_ids = [str(capture_id) for capture_id in args.ctu_validation_captures]
    if len(set(validation_ids)) != len(validation_ids):
        raise ValueError("Ensemble development capture IDs must be unique")
    training_captures = sorted({capture for artifact in loaded
                                for capture in artifact.get("training_captures", [])})
    if set(training_captures) & set(validation_ids):
        raise ValueError("An ensemble development capture appears in member training provenance")
    if set(training_captures) & {"46", "47"}:
        raise ValueError("Consumed independent-test captures cannot be used as ensemble members")

    if not args.registration_file:
        raise ValueError("Development ensemble requires a preregistration file")
    registration_path = Path(args.registration_file).resolve(strict=True)
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    if registration.get("status") != "preregistered_development_only" \
            or registration.get("ensemble_type") != "maximum_probability" \
            or registration.get("validation_capture_ids") != validation_ids \
            or registration.get("dev_fpr_ci_ceiling") != args.ctu_dev_fpr_ci_ceiling:
        raise ValueError("Ensemble registration does not match this development invocation")
    if registration.get("evaluator_sha256", "").upper() != sha256_file(Path(__file__)).upper():
        raise ValueError("Ensemble evaluator hash differs from its preregistration")
    registered_candidates = registration.get("candidate_members", [])
    if len(registered_candidates) != len(member_paths):
        raise ValueError("Ensemble registration has a different member count")
    for item, path, artifact in zip(registered_candidates, member_paths, loaded):
        if Path(item.get("path", "")).resolve() != path \
                or item.get("sha256", "").upper() != sha256_file(path).upper():
            raise ValueError("Ensemble member path or SHA-256 differs from preregistration")
        if item.get("feature_profile") != artifact.get("feature_profile") \
                or item.get("training_captures") != artifact.get("training_captures"):
            raise ValueError("Ensemble member provenance differs from preregistration")
    registered_validation = registration.get("validation_captures", {})
    if set(registered_validation) != set(validation_ids):
        raise ValueError("Registration must pin a SHA-256 for every whole development capture")

    validation_sha256, validation_counts, validation_raw_labels = {}, {}, {}
    capture_labels, score_parts = [], []
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    for capture_id in validation_ids:
        validation_path = CTU_VALIDATION_CAPTURE_PATHS[capture_id]
        validation_sha = sha256_file(validation_path).upper()
        if validation_sha != str(registered_validation[capture_id]).upper():
            raise ValueError(f"Pinned development capture {capture_id} SHA-256 mismatch")
        x, y, _udp, excluded, raw_labels = load_capture(
            capture_id, validation_path, include_raw_labels=True)
        x_selected = x[:, selected_indices]
        member_scores = [predict_candidate_artifact(artifact, x_selected, device)
                         for artifact in loaded]
        scores = np.maximum.reduce(member_scores)
        validation_sha256[capture_id] = validation_sha
        validation_counts[capture_id] = {
            "attack": int(np.count_nonzero(y == 1)),
            "benign": int(np.count_nonzero(y == 0)),
            "unknown_or_invalid_excluded": int(excluded),
        }
        validation_raw_labels[capture_id] = np.asarray(raw_labels, dtype=object)
        capture_labels.append(y)
        score_parts.append(scores)
    all_scores = np.concatenate(score_parts)
    all_labels = np.concatenate(capture_labels)
    validation_point = select_joint_capture_threshold(
        all_scores, validation_ids, capture_labels, args.ctu_dev_fpr_ci_ceiling)
    if validation_point is None:
        raise ValueError("No shared ensemble threshold meets the per-capture development FPR CI ceiling")
    threshold = float(validation_point["threshold"])
    validation_per_label = {}
    offset = 0
    for capture_id, labels in zip(validation_ids, capture_labels):
        raw_labels = validation_raw_labels[capture_id]
        local_scores = all_scores[offset:offset + len(labels)]
        offset += len(labels)
        predicted = local_scores >= threshold
        local = {}
        for label in sorted(set(raw_labels)):
            selected = raw_labels == label
            attack = labels == 1
            local[label] = {
                "flows": int(np.count_nonzero(selected)),
                "detected_attacks": int(np.count_nonzero(selected & attack & predicted)),
                "false_positives": int(np.count_nonzero(selected & ~attack & predicted)),
            }
        validation_per_label[capture_id] = local
    members = []
    training_hashes = {}
    for path, artifact in zip(member_paths, loaded):
        source_manifest_path = path.parent / "validation_weight_experiment.json"
        source_manifest = (json.loads(source_manifest_path.read_text(encoding="utf-8"))
                           if source_manifest_path.is_file() else {})
        member_training_hashes = source_manifest.get("sha256", {}).get("train", {})
        members.append({"candidate_sha256": sha256_file(path),
            "state_dict": artifact["state_dict"], "mean": artifact["mean"],
            "scale": artifact["scale"], "hidden_width": int(
                artifact["state_dict"]["layers.0.weight"].shape[0]),
            "training_captures": artifact.get("training_captures", []),
            "training_sha256": member_training_hashes,
            "training_config": artifact.get("training_config", {})})
        training_hashes.update(member_training_hashes)
    out_dir = ROOT / "outputs" / "network-eval" / "ctu13-max-ensemble-dev-20261120"
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / "candidate-max-ensemble.pt"
    ensemble_artifact = {
        "ensemble_type": "max_probability",
        "feature_version": FEATURE_VERSION, "feature_names": selected_feature_names,
        "feature_profile": args.ctu_feature_profile,
        "classes": ["benign", "attack"], "members": members,
        "member_candidate_sha256": [member["candidate_sha256"] for member in members],
        "training_captures": training_captures, "training_sha256": training_hashes,
        "validation_sha256": validation_sha256,
        "threshold": threshold, "validation_operating_point": validation_point,
        "validation_capture_ids": validation_ids,
        "dev_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
        "registration_sha256": sha256_file(registration_path),
        "research_only": True, "promotion_eligible": False,
    }
    torch.save(ensemble_artifact, output_path)
    report = {"candidate": output_path.name,
        "candidate_sha256": sha256_file(output_path),
        "ensemble_type": "maximum of member attack probabilities",
        "member_candidate_sha256": ensemble_artifact["member_candidate_sha256"],
        "training_captures": training_captures, "training_sha256": training_hashes,
        "validation_capture_ids": validation_ids, "validation_sha256": validation_sha256,
        "validation_counts": validation_counts,
        "validation_operating_point": validation_point,
        "validation_per_publisher_label": validation_per_label,
        "dev_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
        "selection_rule": "maximize minimum per-capture lower 95% Wilson recall CI subject to upper 95% Wilson FPR CI <= dev ceiling on every capture",
        "registration_sha256": sha256_file(registration_path),
        "promotion_eligible": False,
        "research_only": True}
    report_path = out_dir / "validation-assessment.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def train_one(name, scheme, x_train, y_train, udp_train, x_val, y_val, mean, scale, device,
              *, seed=SEED, epochs=EPOCHS, patience=PATIENCE, hidden_width=128,
              learning_rate=3e-4, focal_gamma=0.0, benign_focal_gamma=None, capture_ids=None,
              capture_weighting="none", validation_capture_ids=None,
              validation_capture_labels=None, selection_metric="development_nll",
              dev_fpr_ci_ceiling=FPR_CEILING, history_path=None, history_context=None):
    seed_everything(seed)
    model = MLP(len(FEATURE_NAMES), hidden_width).to(device)
    if scheme.get("use_class_balance"):
        counts = np.bincount(y_train, minlength=2).astype(np.float64)
        class_weights = len(y_train) / (2.0 * np.maximum(counts, 1.0))
    else:
        class_weights = np.ones(2, dtype=np.float64)
    sample_weights = class_weights[y_train]
    if capture_weighting != "none":
        if capture_ids is None:
            raise ValueError("Capture IDs are required when capture weighting is enabled")
        sample_weights *= capture_distribution_weights(y_train, capture_ids, capture_weighting)
    sample_weights[y_train == 1] *= float(scheme.get("attack_multiplier", 1.0))
    udp_boost = float(scheme.get("udp_attack_multiplier", 1.0))
    sample_weights[(y_train == 1) & udp_train] *= udp_boost
    sample_weights /= sample_weights.mean()

    ds = TensorDataset(torch.from_numpy(x_train), torch.from_numpy(y_train),
                       torch.from_numpy(sample_weights.astype(np.float32)))
    generator = torch.Generator().manual_seed(seed)
    loader = DataLoader(ds, batch_size=BATCH_SIZE, shuffle=True, generator=generator,
                        num_workers=0, pin_memory=(device.type == "cuda"))
    x_val_tensor = torch.from_numpy(x_val).to(device)
    y_val_tensor = torch.from_numpy(y_val).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    best_loss, best_epoch, stale = float("inf"), 0, 0
    best_selection_key = (-float("inf"), -float("inf"), -float("inf"))
    best_selection_point = None
    best_state = None
    loss_fn = nn.CrossEntropyLoss(reduction="none")
    history_context = dict(history_context or {})
    history_started = time.perf_counter()
    for epoch in range(1, epochs + 1):
        model.train()
        train_loss_total, train_items = 0.0, 0
        for bx, by, bw in loader:
            bx, by, bw = bx.to(device), by.to(device), bw.to(device)
            optimizer.zero_grad(set_to_none=True)
            per_item = loss_fn(model(bx), by)
            if focal_gamma > 0 or (benign_focal_gamma is not None and benign_focal_gamma > 0):
                pt = torch.exp(-per_item)
                if benign_focal_gamma is None:
                    gamma_by_item = focal_gamma
                else:
                    gamma_by_item = torch.where(
                        by == 1,
                        torch.full_like(per_item, focal_gamma),
                        torch.full_like(per_item, benign_focal_gamma),
                    )
                per_item = per_item * torch.pow(1.0 - pt, gamma_by_item)
            loss = (per_item * bw).mean()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            optimizer.step()
            train_loss_total += float(loss.detach().item()) * len(by)
            train_items += len(by)
        model.eval()
        with torch.no_grad():
            val_loss = float(loss_fn(model(x_val_tensor), y_val_tensor).mean().item())
        epoch_selection_point = None
        if selection_metric == "joint_dev_gate":
            if not validation_capture_ids or not validation_capture_labels:
                raise ValueError("Joint development-gate selection requires per-capture validation labels")
            epoch_probabilities = predict(model, x_val, device)
            epoch_selection_point = select_joint_capture_threshold(
                epoch_probabilities, validation_capture_ids,
                validation_capture_labels, dev_fpr_ci_ceiling)
            selection_key = (
                epoch_selection_point["minimum_recall_ci95_lower"] if epoch_selection_point else -1.0,
                epoch_selection_point["mean_recall"] if epoch_selection_point else -1.0,
                -val_loss,
            )
            improved = selection_key > best_selection_key
        else:
            selection_key = (-1.0, -1.0, -val_loss)
            improved = val_loss < best_loss - 1e-5
        if improved:
            best_selection_key = selection_key
            best_selection_point = epoch_selection_point
            best_loss, best_epoch, stale = val_loss, epoch, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            stale += 1
        if history_path is not None:
            event = {**history_context, "event": "epoch", "scheme": name,
                     "epoch": epoch, "total_epochs": epochs,
                     "train_loss": train_loss_total / max(train_items, 1),
                     "development_nll": val_loss, "best_epoch": best_epoch,
                     "best_development_nll": best_loss, "patience_used": stale,
                     "selection_metric": selection_metric,
                     "development_threshold": (epoch_selection_point["threshold"]
                                               if epoch_selection_point else None),
                     "development_min_recall_ci95_lower": (
                         epoch_selection_point["minimum_recall_ci95_lower"]
                         if epoch_selection_point else None),
                     "development_mean_recall": (epoch_selection_point["mean_recall"]
                                                  if epoch_selection_point else None),
                     "best_development_min_recall_ci95_lower": (
                         best_selection_point["minimum_recall_ci95_lower"]
                         if best_selection_point else None),
                     "elapsed_seconds": time.perf_counter() - history_started,
                     "timestamp_utc": datetime.now(timezone.utc).isoformat()}
            with Path(history_path).open("a", encoding="utf-8") as history_stream:
                history_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
                history_stream.flush()
        if epoch == 1 or epoch % 5 == 0:
            print(f"{name} epoch={epoch}/{epochs} train_loss={train_loss_total / max(train_items, 1):.6f} "
                  f"development_nll={val_loss:.6f} best_epoch={best_epoch} patience={stale} "
                  f"min_recall_ci_lower={selection_key[0]:.6f}", flush=True)
        if stale >= patience:
            break
    if best_state is None:
        raise RuntimeError(f"No checkpoint produced for scheme {name}")
    model.load_state_dict(best_state)
    model.to(device)
    probabilities = predict(model, x_val, device)
    curve = score_curve(probabilities, y_val)
    eligible = np.flatnonzero(curve[3] <= dev_fpr_ci_ceiling)
    selected_idx = int(eligible[np.argmax(curve[1][eligible])]) if len(eligible) else None
    selected = None if selected_idx is None else {
        "threshold": float(curve[0][selected_idx]),
        "recall": float(curve[1][selected_idx]),
        "fpr": float(curve[2][selected_idx]),
        "fpr_ci95_upper": float(curve[3][selected_idx]),
        "tp": int(curve[4][selected_idx]), "fp": int(curve[5][selected_idx]),
        "fn": int(np.count_nonzero(y_val == 1) - curve[4][selected_idx]),
        "tn": int(np.count_nonzero(y_val == 0) - curve[5][selected_idx]),
    }
    return model, {"name": name, "scheme": scheme, "best_epoch": best_epoch,
                  "validation_loss": best_loss, "selection_metric": selection_metric,
                  "selected_at_fpr_ci_ceiling": selected,
                  "threshold_curve": curve, "probabilities": probabilities}


def main(argv=None):
    global FEATURE_NAMES
    parser = argparse.ArgumentParser(description="Unified whole-capture network-model training and evaluation")
    parser.add_argument("--dataset", choices=("ctu13", "iot23"), default="ctu13")
    parser.add_argument("--action", choices=("train", "evaluate", "ensemble"), default="train")
    parser.add_argument("--split", choices=tuple(IOT_SPLITS), default="multifamily-to-3")
    parser.add_argument("--feature-version", type=int, choices=(9, 10), default=10)
    parser.add_argument("--ctu-feature-version", type=int, choices=(8, 9, 10), default=8,
                        help="CTU flow contract; v9 tracks missing duration; v10 adds observed ports (CTU profile excludes unavailable TCP flags)")
    parser.add_argument("--ctu-feature-profile",
                        choices=("full_v8", "core_v3", "base_derived", "no_udp_heuristics",
                                 "ctu_ports_only_v10", "no_udp_heuristics_v10"),
                        default="full_v8",
                        help="CTU-13 feature ablation; reduced profiles use v8 fields but select a fixed subset before fitting")
    parser.add_argument("--model", choices=("extra_trees", "random_forest", "hist_gradient_boosting", "mlp"), default="extra_trees")
    parser.add_argument("--max-per-class", type=int, default=50_000)
    parser.add_argument("--validation-max-per-class", type=int, default=None)
    parser.add_argument("--trees", type=int, default=700)
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--min-leaf", type=int, default=2)
    parser.add_argument("--max-features", type=float, default=.8)
    parser.add_argument("--ctu-focal-gamma", type=float, default=0.0,
                        help="CTU-13 MLP focal-loss gamma; 0 preserves weighted cross entropy")
    parser.add_argument("--ctu-benign-focal-gamma", type=float, default=None,
                        help="optional CTU MLP focal gamma for benign examples only; when omitted, use --ctu-focal-gamma for both classes")
    parser.add_argument("--ctu-learning-rate", type=float, default=3e-4,
                        help="CTU-13 MLP AdamW learning rate")
    parser.add_argument("--ctu-hidden-width", type=int, choices=(64, 128, 256, 512), default=128,
                        help="CTU-13 MLP first hidden-layer width")
    parser.add_argument("--ctu-epochs", type=int, default=EPOCHS,
                        help="maximum CTU-13 MLP epochs")
    parser.add_argument("--ctu-additional-train-captures", nargs="*",
                        choices=tuple(CTU_ADDITIONAL_TRAIN_CAPTURES), default=[],
                        help="additional explicitly labeled whole captures; 45 remains unavailable for training")
    parser.add_argument("--ctu-allow-consumed-capture-training", nargs="*",
                        choices=tuple(sorted(CTU_CONSUMED_TRAIN_ONLY_CAPTURES)), default=[],
                        help="explicitly allow previously evaluated captures as development training data; they then cannot be validation or independent evidence")
    parser.add_argument("--ctu-validation-captures", nargs="+",
                        choices=tuple(CTU_VALIDATION_CAPTURE_PATHS), default=["45"],
                        help="whole development captures; a shared threshold must satisfy the FPR bound on every listed capture")
    parser.add_argument("--ctu-dev-fpr-ci-ceiling", type=float, default=0.0025,
                        help="CTU development-only Wilson upper-FPR ceiling per validation capture (default: 0.25%%); release gate is 0.25%% per independent test capture")
    parser.add_argument("--ctu-checkpoint-selection", choices=("joint_dev_gate", "development_nll"),
                        default="joint_dev_gate",
                        help="select CTU checkpoint by the joint per-capture dev operating point (default) or development NLL")
    parser.add_argument("--ctu-capture-weighting", choices=("none", "equal", "sqrt"),
                        default="none", help="rebalance capture influence within each class for CTU-13 MLP")
    parser.add_argument("--ctu-weight-schemes", nargs="+", choices=tuple(WEIGHT_SCHEMES),
                        default=list(WEIGHT_SCHEMES),
                        help="CTU-13 weighting experiments to run; defaults to all preregistered schemes")
    parser.add_argument("--focal-gamma", type=float, default=0.0,
                        help="MLP focal-loss gamma; 0 preserves weighted cross entropy")
    parser.add_argument("--learning-rate", type=float, default=3e-4,
                        help="IoT-23 MLP AdamW learning rate")
    parser.add_argument("--hidden-width", type=int, choices=(64, 128, 256, 512), default=128,
                        help="first hidden-layer width for the IoT-23 MLP")
    parser.add_argument("--capture-weighting", choices=("equal", "sqrt", "proportional"),
                        default="equal", help="per-capture training weight mass within each class")
    parser.add_argument("--fpr-ci-ceiling", type=float, default=RELEASE_FPR_CI_CEILING,
                        help="two-sided 95% Wilson upper-FPR ceiling for generic candidate selection/evaluation; current release gate: 0.25% per independent capture")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--include-clean", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--capture", choices=("36-1", "43-1", "52-1", "60-1", "45", "46", "47", "61-1",
                                               "sme11-win7ad1", "ctu-idseval-6",
                                               "ctu-normal12-benign-diagnostic",
                                               "iscx2017-thursday", "apex-ids2026",
                                               "cesnet-cc25", "litnet-2020"), default=None)
    parser.add_argument("--candidate", default=None)
    parser.add_argument("--candidate-secondary", default=None,
                        help="second CTU-13 MLP candidate for --action ensemble")
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--expected-candidate-sha256", default=None,
                        help="candidate SHA-256 pinned before the one-pass live-v3 source test")
    parser.add_argument("--botnet-flow-archive", default=str(
        ROOT / "data" / "external" / "cesnet-cc25" / "cesnet-cc25-botnet-ipflows.tar.gz"))
    parser.add_argument("--benign-archive", default=str(
        ROOT / "data" / "external" / "cesnet-cc25" / "cesnet-cc25-benign-ipflows.tar.gz"))
    parser.add_argument("--expected-benign-sha256", default=None)
    parser.add_argument("--litnet-archive", default=str(
        ROOT / "data" / "external" / "litnet-2020" / "ALLinONE.zip"))
    parser.add_argument("--litnet-audit", default=str(
        ROOT / "outputs" / "network-eval" / "official-litnet2020" / "source-row-audit.json"))
    parser.add_argument("--expected-litnet-audit-sha256", default=None)
    parser.add_argument("--registration-file", default=None,
                        help="pre-existing JSON registration binding candidate, capture, threshold, and evaluator")
    parser.add_argument("--run-after-prereg-review", action="store_true",
                        help="explicitly enable a pending preregistered one-pass diagnostic after review")
    parser.add_argument("--threshold", type=float, default=None,
                        help="frozen CTU-13 validation threshold for --action evaluate")
    args = parser.parse_args(argv)
    if args.max_per_class < 1 or (args.validation_max_per_class is not None and args.validation_max_per_class < 1):
        parser.error("sample caps must be positive")
    if (not 0 < args.fpr_ci_ceiling < 1
            or not 0 < args.ctu_dev_fpr_ci_ceiling < 1
            or args.trees < 1 or args.epochs < 1
            or args.min_leaf < 1 or not math.isfinite(args.focal_gamma) or args.focal_gamma < 0
            or not math.isfinite(args.learning_rate) or args.learning_rate <= 0
            or not math.isfinite(args.ctu_focal_gamma) or args.ctu_focal_gamma < 0
            or (args.ctu_benign_focal_gamma is not None
                and (not math.isfinite(args.ctu_benign_focal_gamma) or args.ctu_benign_focal_gamma < 0))
            or not math.isfinite(args.ctu_learning_rate) or args.ctu_learning_rate <= 0
            or args.ctu_epochs < 1):
        parser.error("FPR ceiling, trees, and min_leaf must be positive valid values")
    if args.dataset == "ctu13" and args.ctu_hidden_width < 64:
        parser.error("CTU-13 hidden width must be at least 64")
    if args.dataset != "ctu13" and args.ctu_additional_train_captures:
        parser.error("--ctu-additional-train-captures applies only to CTU-13")
    if args.dataset != "ctu13" and args.ctu_capture_weighting != "none":
        parser.error("--ctu-capture-weighting applies only to CTU-13")
    if args.dataset != "ctu13" and args.ctu_benign_focal_gamma is not None:
        parser.error("--ctu-benign-focal-gamma applies only to CTU-13")
    if ((args.focal_gamma > 0 or args.learning_rate != 3e-4 or args.hidden_width != 128)
            and (args.dataset != "iot23" or args.model != "mlp")):
        parser.error("non-default focal loss, learning rate and hidden width apply only to IoT-23 MLP")
    if args.capture_weighting != "equal" and args.dataset != "iot23":
        parser.error("non-default capture weighting is available only for the IoT-23 runner")
    if args.dataset == "iot23":
        if args.action == "evaluate":
            if not args.candidate or not args.capture:
                parser.error("--action evaluate requires --candidate and --capture")
            evaluate_iot23_candidate(args)
            return
        if args.action == "ensemble":
            parser.error("--action ensemble is currently available only for --dataset ctu13")
        run_iot23(args)
        return
    if args.action == "ensemble":
        if not args.candidate or not args.candidate_secondary:
            parser.error("CTU-13 --action ensemble requires --candidate and --candidate-secondary")
        build_ctu13_ensemble(args)
        return
    if args.action == "evaluate":
        if args.capture == "ctu-normal12-benign-diagnostic":
            if not args.registration_file or not args.run_after_prereg_review:
                parser.error("CTU-Normal-12 diagnostic requires --registration-file and --run-after-prereg-review after preregistration review")
            evaluate_ctu_normal12_benign_diagnostic(args)
            return
        if args.capture == "litnet-2020":
            if not args.candidate or not args.expected_sha256:
                parser.error("LITNET-2020 evaluation requires candidate and preregistered archive SHA-256")
            if (not args.expected_candidate_sha256 or not args.expected_litnet_audit_sha256
                    or args.registration_file is None or args.threshold is None):
                parser.error("LITNET-2020 evaluation requires pre-registered candidate, source-audit, evaluator hashes, and frozen threshold")
            candidate_header = torch.load(args.candidate, map_location="cpu", weights_only=True)
            if candidate_header.get("feature_version") != 3:
                parser.error("LITNET-2020 currently has a registered evaluator only for the live v3 checkpoint")
            evaluate_litnet2020_v3(args)
            return
        if args.capture == "cesnet-cc25":
            if not args.candidate or not args.expected_sha256 or not args.expected_benign_sha256:
                parser.error("CESNET-CC25 evaluation requires candidate and both pre-registered archive SHA-256 values")
            if (not args.expected_candidate_sha256 or args.registration_file is None
                    or args.threshold is None):
                parser.error("CESNET-CC25 evaluation requires pre-registered candidate hash, threshold, and registration file")
            candidate_header = torch.load(args.candidate, map_location="cpu", weights_only=True)
            if candidate_header.get("feature_version") not in (3, 9, 10):
                parser.error("CESNET-CC25 evaluator supports only frozen v3, v9, or v10 candidates")
            evaluate_cesnet_cc25_v3(args)
            return
        if args.capture == "apex-ids2026":
            if not args.candidate:
                parser.error("--action evaluate --capture apex-ids2026 requires --candidate")
            if not args.expected_sha256 or args.threshold is None:
                parser.error("APEX-IDS2026 diagnostic requires the pinned archive SHA-256 and frozen validation threshold")
            evaluate_apex_ids2026(args)
            return
        if args.capture == "iscx2017-thursday":
            if not args.candidate:
                parser.error("--action evaluate --capture iscx2017-thursday requires --candidate")
            if not args.expected_sha256 or args.threshold is None:
                parser.error("CIC-IDS-2017 diagnostic requires the pinned capture SHA-256 and frozen validation threshold")
            evaluate_iscx2017_thursday(args)
            return
        if args.capture == "ctu-idseval-6":
            if not args.candidate:
                parser.error("--action evaluate --capture ctu-idseval-6 requires --candidate")
            if not args.expected_sha256 or args.threshold is None:
                parser.error("CTU-IDSEVAL-6 evaluation requires the pinned Zeek SHA-256 and frozen validation threshold")
            evaluate_ctu_idseval6_candidate(args)
            return
        if args.capture not in {*CTU_EVAL_CAPTURES, *CTU_SME11_EVAL_ARCHIVES} or not args.candidate:
            parser.error("--action evaluate requires --candidate and a supported whole capture")
        if not args.expected_sha256 or args.threshold is None:
            parser.error("CTU-13 evaluation requires --expected-sha256 and validation --threshold")
        if args.capture == "61-1":
            try:
                candidate_header = torch.load(args.candidate, map_location="cpu", weights_only=True)
            except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
                parser.error(f"Could not inspect CTU-MCFP candidate: {error}")
            if candidate_header.get("feature_version") == 3:
                if not args.expected_candidate_sha256 or not args.registration_file:
                    parser.error("v3 CTU-MCFP evaluation requires --expected-candidate-sha256 and --registration-file")
                evaluate_live_v3_candidate(args)
                return
        if args.capture in CTU_SME11_EVAL_ARCHIVES:
            candidate_header = torch.load(args.candidate, map_location="cpu", weights_only=True)
            if candidate_header.get("feature_version") == 3:
                if not args.expected_candidate_sha256 or not args.registration_file:
                    parser.error("v3 CTU-SME-11 evaluation requires --expected-candidate-sha256 and --registration-file")
                evaluate_ctu_sme11_live_v3(args)
            else:
                evaluate_ctu_sme11_candidate(args)
        else:
            evaluate_ctu13_candidate(args)
        return

    ctu_train_captures = {**TRAIN_CAPTURES,
                          **{cid: CTU_ADDITIONAL_TRAIN_CAPTURES[cid]
                             for cid in args.ctu_additional_train_captures}}
    configure_feature_schema(args.ctu_feature_version)
    ctu_full_feature_names = tuple(FEATURE_NAMES)
    if args.ctu_feature_version == 8:
        # Preserve the established v8 feature-profile definitions exactly.
        ctu_profile_indices_by_name = {
            "full_v8": tuple(range(len(ctu_full_feature_names))),
            "core_v3": tuple(range(8)),
            "base_derived": tuple(range(11)),
            "no_udp_heuristics": tuple(range(11)) + (12,),
        }
    elif args.ctu_feature_version == 9:
        if args.ctu_feature_profile not in {"full_v8", "no_udp_heuristics"}:
            raise ValueError("CTU schema v9 supports only full_v8 and no_udp_heuristics profiles")
        # Schema v9 appends duration_missing at index 17. Keep the non-UDP
        # features 0-10 and 12 plus duration_missing; exclude the UDP-specific
        # heuristic flags at indices 11 and 13-16.
        ctu_profile_indices_by_name = {
            "full_v8": tuple(range(len(ctu_full_feature_names))),
            "no_udp_heuristics": tuple(range(11)) + (12, 17),
        }
        if (len(ctu_full_feature_names) <= 17
                or ctu_full_feature_names[17] != "duration_missing"):
            raise ValueError("CTU schema v9 feature 17 must be duration_missing")
    elif args.ctu_feature_version == 10:
        if args.ctu_feature_profile not in {"ctu_ports_only_v10", "no_udp_heuristics_v10"}:
            raise ValueError("CTU schema v10 requires a supported v10 feature profile")
        # NetFlow CTU rows contain endpoint ports but not Zeek's packet-history
        # flags. Exclude v10's six TCP flag features rather than fabricate them.
        ctu_profile_indices_by_name = {
            "ctu_ports_only_v10": tuple(range(40)),
            # Remove five hand-engineered UDP flags derived from known CTU
            # attack/benign duration patterns; retain measured flow statistics,
            # duration_missing and observed endpoint-port indicators.
            "no_udp_heuristics_v10": tuple(
                i for i in range(40) if i not in {11, 13, 14, 15, 16}),
        }
        if len(ctu_full_feature_names) != 46:
            raise ValueError("CTU schema v10 feature contract changed unexpectedly")
    else:
        raise ValueError(f"Unsupported CTU feature schema: {args.ctu_feature_version}")
    ctu_profile_indices = ctu_profile_indices_by_name[args.ctu_feature_profile]
    if max(ctu_profile_indices) >= len(ctu_full_feature_names):
        raise ValueError("Selected CTU feature profile exceeds the configured schema")
    ctu_selected_feature_names = tuple(ctu_full_feature_names[i] for i in ctu_profile_indices)
    ctu_feature_profile_contract = {
        "profile": args.ctu_feature_profile,
        "schema_version": FEATURE_VERSION,
        "selected_indices": list(ctu_profile_indices),
        "selected_features": list(ctu_selected_feature_names),
        "excluded_indices": [i for i in range(len(ctu_full_feature_names))
                             if i not in ctu_profile_indices],
        "excluded_features": [name for i, name in enumerate(ctu_full_feature_names)
                              if i not in ctu_profile_indices],
        "definition": (
            "v9 no_udp_heuristics keeps indices 0-10, 12, and duration_missing index 17; "
            "excludes UDP-specific heuristic indices 11 and 13-16."
            if FEATURE_VERSION == 9 and args.ctu_feature_profile == "no_udp_heuristics"
            else "v10 no_udp_heuristics_v10 removes UDP-specific heuristic indices 11 and 13-16; "
            "retains measured statistics, duration_missing, and observed port features; "
            "unavailable TCP flags are excluded."
            if FEATURE_VERSION == 10 and args.ctu_feature_profile == "no_udp_heuristics_v10"
            else "v10 port features mapped from observed CTU NetFlow endpoint ports; six unobserved handshake flags excluded."
            if FEATURE_VERSION == 10
            else "Existing CTU schema v8 profile definition."
            if FEATURE_VERSION == 8
            else "All schema-v9 features."
        ),
    }
    ctu_validation_captures = {cid: CTU_VALIDATION_CAPTURE_PATHS[cid]
                               for cid in args.ctu_validation_captures}
    if len(ctu_validation_captures) != len(args.ctu_validation_captures):
        raise ValueError("CTU validation capture IDs must be unique")
    overlap = set(ctu_train_captures) & set(ctu_validation_captures)
    if overlap:
        raise ValueError(f"CTU captures cannot be in both train and validation: {sorted(overlap)}")
    consumed_in_train = set(ctu_train_captures) & CTU_CONSUMED_TRAIN_ONLY_CAPTURES
    if consumed_in_train - set(args.ctu_allow_consumed_capture_training):
        raise ValueError("Previously evaluated CTU captures require explicit --ctu-allow-consumed-capture-training")
    if set(args.ctu_allow_consumed_capture_training) - consumed_in_train:
        raise ValueError("Every consumed-capture training allowance must name a selected training capture")
    if "45" in ctu_train_captures:
        raise ValueError("CTU capture 45 is reserved for validation and cannot enter training")

    started = time.time()
    ctu_is_default = (args.ctu_focal_gamma == 0.0 and args.ctu_benign_focal_gamma is None
                      and args.ctu_learning_rate == 3e-4
                      and args.ctu_hidden_width == 128 and args.ctu_epochs == EPOCHS
                      and args.seed == SEED and not args.ctu_additional_train_captures
                      and args.ctu_capture_weighting == "none"
                      and not args.ctu_allow_consumed_capture_training
                      and args.ctu_validation_captures == ["45"])
    ctu_run_config = {
        "feature_version": FEATURE_VERSION,
        "feature_profile": args.ctu_feature_profile,
        "feature_profile_contract": ctu_feature_profile_contract,
        "focal_gamma": args.ctu_focal_gamma,
        "benign_focal_gamma": args.ctu_benign_focal_gamma,
        "learning_rate": args.ctu_learning_rate,
        "hidden_width": args.ctu_hidden_width,
        "epochs": args.ctu_epochs,
        "seed": args.seed,
        "additional_train_captures": args.ctu_additional_train_captures,
        "allow_consumed_capture_training": args.ctu_allow_consumed_capture_training,
        "capture_weighting": args.ctu_capture_weighting,
        "validation_captures": args.ctu_validation_captures,
        "dev_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
        "checkpoint_selection": args.ctu_checkpoint_selection,
        "weight_schemes": args.ctu_weight_schemes,
    }
    ctu_run_fingerprint = hashlib.sha256(json.dumps(
        ctu_run_config, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:10]
    ctu_run_name = ("train-v9-validation-only" if ctu_is_default else
                    f"ctu-v{FEATURE_VERSION}-{ctu_run_fingerprint}-"
                    f"val{'-'.join(args.ctu_validation_captures)}")
    ctu_output = DATA / ctu_run_name
    ctu_output.mkdir(parents=True, exist_ok=True)
    seed_everything(args.seed)
    print(f"Fixed split: train captures {','.join(ctu_train_captures)}; validation captures {','.join(ctu_validation_captures)}; other release-test sources are not loaded.")
    print(f"Feature schema v{FEATURE_VERSION}: {len(FEATURE_NAMES)} features")
    raw_train, labels_train, udp_train, capture_ids_train = [], [], [], []
    source_hashes, source_counts, source_label_rule_hashes = {}, {}, {}
    source_label_provenance = {}
    for capture_id, path in ctu_train_captures.items():
        x, y, udp, excluded = load_capture(capture_id, path)
        raw_train.append(x); labels_train.append(y); udp_train.append(udp)
        capture_ids_train.append(np.full(len(y), str(capture_id), dtype=object))
        source_hashes[capture_id] = sha256_file(path)
        if capture_id == "normal12":
            source_label_rule_hashes[capture_id] = sha256_file(CTU_NORMAL12_LABEL_CONFIG)
            source_label_provenance[capture_id] = {
                "publisher": "CTU-MCFP CTU-Normal-12 labels.config",
                "accepted_label_rule": f"Benign SrcAddr={CTU_NORMAL12_HOST}; all others excluded as Background",
                "label_rule_sha256": source_label_rule_hashes[capture_id],
            }
        elif capture_id in {"46", "47"}:
            source_label_provenance[capture_id] = {
                "publisher": "CTU-MCFP CTU-13 detailed bidirectional flow labels",
                "source_url": {
                    "46": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/detailed-bidirectional-flow-labels/capture20110815-2.binetflow",
                    "47": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/detailed-bidirectional-flow-labels/capture20110816.binetflow",
                }[capture_id],
                "accepted_labels": ["From-Botnet-*", "From-Normal-*"],
                "excluded_labels": "Background, To-Background, unknown, missing, or invalid rows",
                "prior_role": "previously evaluated independent source; consumed and reused only for development training",
            }
        elif capture_id == "sme11-win7ad1":
            source_label_provenance[capture_id] = {
                "publisher": "CTU-SME-11 Zenodo record 7958259; expert-provided Zeek conn.log.labeled labels",
                "source_url": "https://zenodo.org/records/7958259",
                "accepted_labels": ["benign", "malicious"],
                "excluded_labels": "background, unknown, missing, or incomplete-feature rows",
                "archive_sha256": source_hashes[capture_id],
                "publisher_md5": CTU_SME11_WIN7AD1_MD5,
                "prior_role": "consumed independent evaluation; now development training only",
            }
        elif capture_id in CTU_IDSEVAL6_TRAIN_MEMBERS:
            source_label_rule_hashes[capture_id] = CTU_IDSEVAL6_LABELS_SHA256
            source_label_provenance[capture_id] = {
                "publisher": "CTU-IDSEVAL-6 Zenodo record 21027042; source family consumed as prior independent test",
                "source_url": "https://zenodo.org/records/21027042",
                "member": CTU_IDSEVAL6_TRAIN_MEMBERS[capture_id],
                "accepted_labels": ["Benign", "Malicious"],
                "excluded_labels": "Background, unknown, missing, or invalid feature rows",
                "zeek_archive_sha256": CTU_IDSEVAL6_ZEEK_SHA256,
                "label_archive_sha256": CTU_IDSEVAL6_LABELS_SHA256,
                "prior_role": "consumed independent evaluation; development training only",
            }
        source_counts[capture_id] = {"attack": int((y == 1).sum()), "benign": int((y == 0).sum()),
                                     "unknown_or_invalid_excluded": int(excluded)}
        print(f"train {capture_id}: attack={(y==1).sum()} benign={(y==0).sum()} excluded={excluded}")
    x_train = np.concatenate(raw_train)[:, ctu_profile_indices]; y_train = np.concatenate(labels_train)
    udp_train = np.concatenate(udp_train)
    capture_ids_train = np.concatenate(capture_ids_train)
    raw_val, labels_val, udp_val = [], [], []
    val_hashes, val_counts = {}, {}
    for capture_id, path in ctu_validation_captures.items():
        x, y, udp, excluded = load_capture(capture_id, path)
        raw_val.append(x); labels_val.append(y); udp_val.append(udp)
        val_hashes[capture_id] = sha256_file(path)
        val_counts[capture_id] = {"attack": int((y == 1).sum()), "benign": int((y == 0).sum()),
                                  "unknown_or_invalid_excluded": int(excluded)}
        print(f"validation {capture_id}: attack={(y==1).sum()} benign={(y==0).sum()} excluded={excluded}")
    raw_val = np.concatenate(raw_val)[:, ctu_profile_indices]
    y_val = np.concatenate(labels_val); udp_val = np.concatenate(udp_val)
    FEATURE_NAMES = ctu_selected_feature_names

    # Fit all preprocessing statistics on training captures only.
    mean = np.median(x_train, axis=0)
    q25, q75 = np.percentile(x_train, [25, 75], axis=0)
    scale = np.maximum(q75 - q25, 1e-6)
    x_train = np.clip((x_train - mean) / scale, -10.0, 10.0).astype(np.float32)
    x_val = np.clip((raw_val - mean) / scale, -10.0, 10.0).astype(np.float32)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"device={device}; train={len(y_train)} validation={len(y_val)}")
    print("Explicit train class counts:", {"attack": int((y_train == 1).sum()), "benign": int((y_train == 0).sum())})
    selected_weight_schemes = {name: WEIGHT_SCHEMES[name] for name in args.ctu_weight_schemes}
    print("Weight schemes:", ", ".join(selected_weight_schemes))

    training_history_path = DATA_ROOT / "network-training-history.jsonl"
    training_history_path.parent.mkdir(parents=True, exist_ok=True)
    training_run_id = uuid.uuid4().hex
    history_context = {
        "run_id": training_run_id,
        "dataset": "CTU-13",
        "feature_version": FEATURE_VERSION,
        "feature_profile": args.ctu_feature_profile,
        "train_captures": list(ctu_train_captures),
        "train_capture_sha256": source_hashes,
        "development_captures": list(ctu_validation_captures),
        "development_capture_sha256": val_hashes,
        "training_config": {"seed": args.seed, "epochs": args.ctu_epochs,
                            "learning_rate": args.ctu_learning_rate,
                            "hidden_width": args.ctu_hidden_width,
                            "focal_gamma": args.ctu_focal_gamma,
                            "benign_focal_gamma": (args.ctu_benign_focal_gamma
                                                    if args.ctu_benign_focal_gamma is not None
                                                    else args.ctu_focal_gamma),
                            "dev_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
                            "release_fpr_ci_ceiling": args.fpr_ci_ceiling,
                            "checkpoint_selection": args.ctu_checkpoint_selection,
                            "weight_schemes": list(selected_weight_schemes)},
    }
    with training_history_path.open("a", encoding="utf-8") as history_stream:
        history_stream.write(json.dumps({**history_context, "event": "run_started",
                                         "timestamp_utc": datetime.now(timezone.utc).isoformat()},
                                        separators=(",", ":")) + "\n")
        history_stream.flush()

    curves_path = ctu_output / "validation_curves.csv"
    summary = []
    with curves_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["scheme", "threshold", "recall", "fpr", "fpr_ci95_upper", "tp", "fp", "fn", "tn"])
        for name, scheme in selected_weight_schemes.items():
            print(f"\n=== Fit {name} ===", flush=True)
            model, result = train_one(name, scheme, x_train, y_train, udp_train,
                                      x_val, y_val, mean, scale, device,
                                      seed=args.seed, epochs=args.ctu_epochs,
                                      hidden_width=args.ctu_hidden_width,
                                      learning_rate=args.ctu_learning_rate,
                                      focal_gamma=args.ctu_focal_gamma,
                                      benign_focal_gamma=args.ctu_benign_focal_gamma,
                                      capture_ids=capture_ids_train,
                                      capture_weighting=args.ctu_capture_weighting,
                                      validation_capture_ids=list(ctu_validation_captures),
                                      validation_capture_labels=labels_val,
                                      selection_metric=args.ctu_checkpoint_selection,
                                      dev_fpr_ci_ceiling=args.ctu_dev_fpr_ci_ceiling,
                                      history_path=training_history_path,
                                      history_context=history_context)
            joint_point = select_joint_capture_threshold(
                result["probabilities"], list(ctu_validation_captures),
                labels_val, args.ctu_dev_fpr_ci_ceiling)
            # The validation operating point is accepted only when this one
            # threshold meets the bound independently on every capture.
            result["selected_at_fpr_ci_ceiling"] = joint_point
            thresholds, recall, fpr, fpr_hi, tp, fp = result.pop("threshold_curve")
            probs = result.pop("probabilities")
            # Persist an auditable, research-only candidate for each scheme.
            checkpoint_path = ctu_output / f"{name}.pt"
            validation_threshold = result["selected_at_fpr_ci_ceiling"]
            torch.save({"state_dict": {k: v.cpu() for k, v in model.state_dict().items()},
                        "feature_names": list(FEATURE_NAMES), "feature_version": FEATURE_VERSION,
                        "feature_profile": args.ctu_feature_profile,
                        "normalization": "training_median_iqr", "mean": mean.tolist(),
                        "scale": scale.tolist(), "classes": ["benign", "attack"],
                        "training_captures": list(ctu_train_captures),
                        "training_sha256": source_hashes,
                        "training_label_rule_sha256": source_label_rule_hashes,
                        "training_label_provenance": source_label_provenance,
                        "validation_sha256": val_hashes,
                        "validation_capture": list(ctu_validation_captures), "scheme": scheme,
                        "training_config": {"seed": args.seed, "epochs": args.ctu_epochs,
                            "learning_rate": args.ctu_learning_rate,
                            "hidden_width": args.ctu_hidden_width,
                            "focal_gamma": args.ctu_focal_gamma,
                            "benign_focal_gamma": (args.ctu_benign_focal_gamma
                                                    if args.ctu_benign_focal_gamma is not None
                                                    else args.ctu_focal_gamma),
                            "capture_weighting": args.ctu_capture_weighting,
                            "dev_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
                            "checkpoint_selection": args.ctu_checkpoint_selection,
                            "release_fpr_ci_ceiling": args.fpr_ci_ceiling},
                        "threshold": (validation_threshold["threshold"]
                                      if validation_threshold is not None else None),
                        "validation_operating_point": validation_threshold,
                        "research_only": True, "promotion_eligible": False}, checkpoint_path)
            # Exact curve can contain up to one row per validation flow; retain
            # all unique thresholds in the CSV so the operating point is auditable.
            for i in range(len(thresholds)):
                writer.writerow([name, float(thresholds[i]), float(recall[i]), float(fpr[i]),
                                 float(fpr_hi[i]), int(tp[i]), int(fp[i]),
                                 int((y_val == 1).sum() - tp[i]), int((y_val == 0).sum() - fp[i])])
            chosen = result["selected_at_fpr_ci_ceiling"]
            summary.append({"name": name, "scheme": scheme, "best_epoch": result["best_epoch"],
                            "validation_loss": result["validation_loss"],
                            "dev_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
                            "selected_at_fpr_ci_ceiling": chosen,
                            "validation_per_capture_at_selected_threshold": (
                                chosen["per_capture"] if chosen is not None else None),
                            "checkpoint": checkpoint_path.name,
                            "checkpoint_sha256": sha256_file(checkpoint_path)})
            print(f"best_epoch={result['best_epoch']} val_loss={result['validation_loss']:.6f}")
            print(f"best development point under per-capture Wilson upper-FPR <= "
                  f"{args.ctu_dev_fpr_ci_ceiling * 100:.3g}%:", chosen)

    manifest = {
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": "official CTU publisher-labeled captures plus optional CTU-Normal-12, CTU-SME-11, and consumed CTU-IDSEVAL-6 development captures",
        "feature_version": FEATURE_VERSION,
        "feature_profile": args.ctu_feature_profile,
        "feature_profile_contract": ctu_feature_profile_contract,
        "feature_names": list(FEATURE_NAMES),
        "label_mapping": {"attack": "Label starts flow=From-Botnet-",
                          "benign": "Label starts flow=From-Normal-; CTU-Normal-12 uses only the publisher labels.config rule SrcAddr=10.0.0.46",
                          "unknown_excluded": "all other labels, including Background/To-Background"},
        "label_rule_sha256": source_label_rule_hashes,
        "label_provenance_by_capture": source_label_provenance,
        "source_provenance": ({"normal12": {
            "capture_url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-12/2013-12-17_capture1.binetflow",
            "readme_url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-12/README.md",
            "label_config_url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-12/labels.config",
            "host": CTU_NORMAL12_HOST,
            "mapping": "publisher labels.config defaults all source IPs to Background and overrides SrcAddr=10.0.0.46 to Benign",
            "label_config_sha256": CTU_NORMAL12_LABEL_CONFIG_SHA256,
        }} if "normal12" in ctu_train_captures else {}),
        "split": {"train": list(ctu_train_captures), "validation": list(ctu_validation_captures),
                  "independent_test": "not loaded or evaluated by this script"},
        "sha256": {"train": source_hashes, "validation": val_hashes},
        "counts": {"train": source_counts, "validation": val_counts},
        "dev_threshold_selection": {
            "upper_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
            "scope": "each whole validation capture; development-only candidate selection",
            "minimum_sample_gate_for_release": {
                "attacks": MIN_RELEASE_ATTACK_SUPPORT,
                "benign_zero_fp": MIN_BENIGN_SUPPORT_ZERO_FP,
            },
            "release_test_upper_fpr_ci_ceiling": args.fpr_ci_ceiling,
        },
        "selection_rule": ("select one threshold maximizing minimum per-capture recall CI lower bound, "
                           f"subject to Wilson 95% upper FPR <= {args.ctu_dev_fpr_ci_ceiling:.6g} "
                           "on every whole validation capture; this is development-only and does not change "
                           "the 0.25% independent-test release gate"),
        "schemes": summary,
        "runtime_classifier_supported": False,
        "runtime_status": "Research candidate only; app packet parser emits v10 transport features, but the production classifier loader currently runs the separate v3 candidate.",
        "training_config": {"seed": args.seed, "epochs": args.ctu_epochs,
            "learning_rate": args.ctu_learning_rate,
            "hidden_width": args.ctu_hidden_width,
            "focal_gamma": args.ctu_focal_gamma,
            "benign_focal_gamma": (args.ctu_benign_focal_gamma
                                   if args.ctu_benign_focal_gamma is not None
                                   else args.ctu_focal_gamma),
            "capture_weighting": args.ctu_capture_weighting,
            "dev_fpr_ci_ceiling": args.ctu_dev_fpr_ci_ceiling,
            "checkpoint_selection": args.ctu_checkpoint_selection,
            "additional_train_captures": list(args.ctu_additional_train_captures),
            "allow_consumed_capture_training": list(args.ctu_allow_consumed_capture_training),
            "validation_captures": list(ctu_validation_captures),
            "weight_schemes": list(selected_weight_schemes),
            "run_fingerprint": ctu_run_fingerprint,
            "feature_profile": args.ctu_feature_profile,
            "feature_version": FEATURE_VERSION},
        "warning": "Research experiment only; validation results are not an independent test and do not authorize blocking.",
        "elapsed_seconds": round(time.time() - started, 2),
    }
    manifest_path = ctu_output / "validation_weight_experiment.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    with training_history_path.open("a", encoding="utf-8") as history_stream:
        history_stream.write(json.dumps({**history_context, "event": "run_completed",
                                         "checkpoint_sha256_by_scheme": {
                                             item["name"]: item["checkpoint_sha256"] for item in summary},
                                         "manifest_path": str(manifest_path),
                                         "manifest_sha256": sha256_file(manifest_path),
                                         "timestamp_utc": datetime.now(timezone.utc).isoformat()},
                                        separators=(",", ":")) + "\n")
        history_stream.flush()
    print(f"\nWrote {curves_path}")
    print(f"Wrote {manifest_path}")
    print("No independent test capture was opened; no checkpoint is promotion-eligible.")


if __name__ == "__main__":
    main()
