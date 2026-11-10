# -*- coding: utf-8 -*-
"""
Три специализированные ветви и блок объединения:
  * GraphEncoder  — графовая нейросеть по графу компонентов (структурный уровень);
  * WeightAE      — автокодировщик портретов слоёв с поддержкой MLP/CNN/LSTM/Transformer;
  * BehaviorNet   — классификатор поведенческих аномалий (поведенческий уровень);
  * fusion        — совместное решение о классе нарушения.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

from .features import BEHAV_DIM, PARAM_DIM, STRUCT_DIM
from .spec import CLASSES

# ──────────────────────────────────────────────
# Графовая ветвь
# ──────────────────────────────────────────────

class GraphLayer(nn.Module):
    """Передача сообщений по направленному графу."""

    def __init__(self, dim):
        super().__init__()
        self.self_ = nn.Linear(dim, dim)
        self.out   = nn.Linear(dim, dim, bias=False)
        self.in_   = nn.Linear(dim, dim, bias=False)
        self.norm  = nn.LayerNorm(dim)

    def forward(self, h, a_out, a_in):
        return self.norm(h + F.relu(self.self_(h) + self.out(a_out @ h) + self.in_(a_in @ h)))


class GraphEncoder(nn.Module):
    def __init__(self, hidden, n_layers=3, drop=0.1):
        super().__init__()
        self.inp = nn.Sequential(nn.Linear(STRUCT_DIM, hidden), nn.ReLU(), nn.Dropout(drop))
        self.layers = nn.ModuleList(GraphLayer(hidden) for _ in range(n_layers))
        self.node_head = nn.Linear(hidden, 1)
        self.pool = nn.Sequential(nn.Linear(2 * hidden, hidden), nn.ReLU())

    def forward(self, x, adj, mask):
        m = mask[..., None]
        a_out = adj / adj.sum(-1, keepdim=True).clamp(min=1)
        a_in  = adj.transpose(1, 2) / adj.transpose(1, 2).sum(-1, keepdim=True).clamp(min=1)
        h = self.inp(x) * m
        for layer in self.layers:
            h = layer(h, a_out, a_in) * m
        mean = h.sum(1) / m.sum(1).clamp(min=1)
        mx   = h.masked_fill(m == 0, -1e9).max(1).values
        return self.pool(torch.cat([mean, mx], -1)), self.node_head(h).squeeze(-1)

# ──────────────────────────────────────────────
# Весовые энкодеры для разных архитектур
# ──────────────────────────────────────────────

class _MlpLayerEncoder(nn.Module):
    """MLP-портрет: каждый слой — вектор статистик PARAM_DIM."""
    def __init__(self, latent: int):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(PARAM_DIM, 48), nn.ReLU(), nn.Linear(48, latent))
        self.dec = nn.Sequential(nn.Linear(latent, 48), nn.ReLU(), nn.Linear(48, PARAM_DIM))

    def forward(self, p, mask):
        # p: [B, L, PARAM_DIM],  mask: [B, L]
        z   = self.enc(p)
        err = ((self.dec(z) - p) ** 2).mean(-1) * mask  # [B, L]
        return z, err


class _CnnLayerEncoder(nn.Module):
    """CNN-портрет: 1D-свёртки вдоль оси слоёв для захвата последовательных паттернов."""
    def __init__(self, latent: int):
        super().__init__()
        # проекция признаков слоя → канальное пространство
        self.proj  = nn.Linear(PARAM_DIM, 32)
        # три временны́е свёртки с расширением (dilated)
        self.conv1 = nn.Conv1d(32, 32, kernel_size=3, padding=1, dilation=1)
        self.conv2 = nn.Conv1d(32, 32, kernel_size=3, padding=2, dilation=2)
        self.conv3 = nn.Conv1d(32, latent, kernel_size=1)
        # декодер для реконструкции
        self.dec   = nn.Sequential(nn.Linear(latent, 48), nn.ReLU(), nn.Linear(48, PARAM_DIM))

    def forward(self, p, mask):
        # p: [B, L, D]
        h = F.relu(self.proj(p))             # [B, L, 32]
        h = h.transpose(1, 2)                # [B, 32, L] — Conv1d ожидает [B, C, L]
        h = F.relu(self.conv1(h))
        h = F.relu(self.conv2(h))
        z = self.conv3(h).transpose(1, 2)    # [B, L, latent]
        err = ((self.dec(z) - p) ** 2).mean(-1) * mask
        return z, err


class _LstmLayerEncoder(nn.Module):
    """LSTM-портрет: двунаправленный LSTM по последовательности слоёв."""
    def __init__(self, latent: int):
        super().__init__()
        self.proj = nn.Linear(PARAM_DIM, 32)
        self.lstm = nn.LSTM(32, latent // 2, num_layers=2, batch_first=True,
                            bidirectional=True, dropout=0.1)
        self.dec  = nn.Sequential(nn.Linear(latent, 48), nn.ReLU(), nn.Linear(48, PARAM_DIM))

    def forward(self, p, mask):
        h = F.relu(self.proj(p))
        # pack_padded_sequence для правильной обработки переменной длины
        lengths = mask.sum(-1).long().clamp(min=1).cpu()
        packed  = nn.utils.rnn.pack_padded_sequence(h, lengths, batch_first=True, enforce_sorted=False)
        out, _  = self.lstm(packed)
        z, _    = nn.utils.rnn.pad_packed_sequence(out, batch_first=True,
                                                   total_length=p.shape[1])  # [B, L, latent]
        err = ((self.dec(z) - p) ** 2).mean(-1) * mask
        return z, err


class _TransformerLayerEncoder(nn.Module):
    """Transformer-портрет: self-attention над последовательностью слоёв."""
    def __init__(self, latent: int):
        super().__init__()
        d_model = max(latent, 32)
        self.proj = nn.Linear(PARAM_DIM, d_model)
        enc_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=4,
                                               dim_feedforward=d_model * 2,
                                               dropout=0.1, batch_first=True,
                                               norm_first=True)
        self.transformer = nn.TransformerEncoder(enc_layer, num_layers=2)
        self.to_latent   = nn.Linear(d_model, latent)
        self.dec         = nn.Sequential(nn.Linear(latent, 48), nn.ReLU(), nn.Linear(48, PARAM_DIM))

    def forward(self, p, mask):
        # key_padding_mask: True → игнорировать (обратная маска)
        pad_mask = (mask == 0)      # [B, L]
        h = self.proj(p)            # [B, L, d_model]
        h = self.transformer(h, src_key_padding_mask=pad_mask)
        z = self.to_latent(h)       # [B, L, latent]
        err = ((self.dec(z) - p) ** 2).mean(-1) * mask
        return z, err


# ──────────────────────────────────────────────
# WeightAE — агрегирующий автокодировщик
# ──────────────────────────────────────────────

ARCH_ENCODERS = {
    "mlp":         _MlpLayerEncoder,
    "cnn":         _CnnLayerEncoder,
    "lstm":        _LstmLayerEncoder,
    "transformer": _TransformerLayerEncoder,
}


class WeightAE(nn.Module):
    """Автокодировщик портретов слоёв с поддержкой MLP / CNN / LSTM / Transformer.

    arch='auto' — автовыбор по числу слоёв:
        1–3  → mlp  (мелкие сети)
        4–8  → cnn  (средние, свёрточные и ResNet-подобные)
        9–24 → lstm (глубокие)
        25+  → transformer (очень глубокие / Transformer-модели)
    """

    _AUTO_THRESHOLDS = [(4, "mlp"), (9, "cnn"), (25, "lstm"), (10**9, "transformer")]

    def __init__(self, hidden: int, latent: int = 16, arch: str = "auto"):
        super().__init__()
        self.arch   = arch
        self.latent = latent
        # инициализируем все четыре энкодера — выбор делается в forward()
        self.encoders = nn.ModuleDict({k: cls(latent) for k, cls in ARCH_ENCODERS.items()})
        self.head = nn.Sequential(nn.Linear(2 * latent + 2, hidden), nn.ReLU())

    def _pick_arch(self, n_layers: int) -> str:
        if self.arch != "auto":
            return self.arch
        for thresh, name in self._AUTO_THRESHOLDS:
            if n_layers < thresh:
                return name
        return "transformer"

    def forward(self, p, mask):
        # p: [B, L, PARAM_DIM],  mask: [B, L]
        n_layers  = int(mask.sum(-1).max().item())
        arch_name = self._pick_arch(n_layers)
        encoder   = self.encoders[arch_name]

        z, err = encoder(p, mask)             # [B, L, latent], [B, L]

        m     = mask[..., None]
        n     = mask.sum(1).clamp(min=1)
        zmean = (z * m).sum(1) / n[:, None]   # [B, latent]
        zmax  = z.masked_fill(m == 0, -1e9).max(1).values

        e_mean = err.sum(1) / n
        e_max  = err.max(1).values
        e      = torch.stack([e_mean, e_max], -1)

        emb = self.head(torch.cat([zmean, zmax, torch.log1p(e.detach())], -1))
        return emb, err, e_mean

# ──────────────────────────────────────────────
# BehaviorNet
# ──────────────────────────────────────────────

class HybridDetector(nn.Module):
    def __init__(self, hidden=64, use=(True, True, True), drop=0.15):
        super().__init__()
        self.hidden = hidden
        self.use    = tuple(bool(u) for u in use)
        for name, dim in (("s", STRUCT_DIM), ("p", PARAM_DIM), ("b", BEHAV_DIM)):
            self.register_buffer(f"{name}_mu", torch.zeros(dim))
            self.register_buffer(f"{name}_sd", torch.ones(dim))
        self.gnn   = GraphEncoder(hidden, drop=drop)
        self.ae    = WeightAE(hidden)
        self.behav = nn.Sequential(nn.Linear(BEHAV_DIM, hidden), nn.ReLU(), nn.Dropout(drop),
                                   nn.Linear(hidden, hidden), nn.ReLU())
        self.level_heads = nn.ModuleList(nn.Linear(hidden, 1) for _ in range(3))
        self.fusion = nn.Sequential(nn.Linear(3 * hidden, hidden), nn.ReLU(), nn.Dropout(drop),
                                    nn.Linear(hidden, len(CLASSES)))

    def set_norm(self, samples):
        for name, t in (("s", torch.cat([s["x"] for s in samples])),
                        ("p", torch.cat([s["layers"] for s in samples])),
                        ("b", torch.stack([s["behav"] for s in samples]))):
            getattr(self, f"{name}_mu").copy_(t.mean(0))
            getattr(self, f"{name}_sd").copy_(t.std(0).clamp(min=1e-3))

    def forward(self, b):
        x  = ((b["x"]      - self.s_mu) / self.s_sd).clamp(-8, 8)
        p  = ((b["layers"] - self.p_mu) / self.p_sd).clamp(-8, 8)
        bh = ((b["behav"]  - self.b_mu) / self.b_sd).clamp(-8, 8)
        g,  node_logits = self.gnn(x, b["adj"], b["mask"])
        pe, layer_err, recon = self.ae(p, b["lmask"])
        be = self.behav(bh)
        embs   = [e * float(u) for e, u in zip((g, pe, be), self.use)]
        levels = torch.cat([h(e) for h, e in zip(self.level_heads, embs)], -1)
        return {"logits": self.fusion(torch.cat(embs, -1)), "levels": levels,
                "node_logits": node_logits, "layer_err": layer_err, "recon": recon}


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def collate(samples):
    n = max(s["x"].shape[0] for s in samples)
    l = max(s["layers"].shape[0] for s in samples)
    bs = len(samples)
    out = {"x": torch.zeros(bs, n, STRUCT_DIM), "adj": torch.zeros(bs, n, n), "mask": torch.zeros(bs, n),
           "layers": torch.zeros(bs, l, PARAM_DIM), "lmask": torch.zeros(bs, l),
           "behav": torch.stack([s["behav"] for s in samples]), "node_y": torch.zeros(bs, n)}
    for i, s in enumerate(samples):
        k, m = s["x"].shape[0], s["layers"].shape[0]
        out["x"][i, :k], out["adj"][i, :k, :k], out["mask"][i, :k] = s["x"], s["adj"], 1
        out["layers"][i, :m], out["lmask"][i, :m] = s["layers"], 1
        if "node_y" in s:
            out["node_y"][i, :k] = s["node_y"]
    if "y" in samples[0]:
        out["y"]      = torch.tensor([s["y"] for s in samples])
        out["levels"] = torch.stack([s["levels"] for s in samples])
    return out


def save_detector(model: HybridDetector, path, extra: dict):
    torch.save({"state": model.state_dict(), "hidden": model.hidden, "use": list(model.use), **extra}, path)


def load_detector(path) -> tuple[HybridDetector, dict]:
    ck = torch.load(path, map_location="cpu", weights_only=True)
    model = HybridDetector(ck["hidden"], ck["use"])
    model.load_state_dict(ck["state"])
    return model.eval(), ck
