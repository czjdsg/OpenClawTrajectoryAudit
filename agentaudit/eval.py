"""评估: 对照 ground-truth 标签算 accuracy / precision / recall / F1 (正类=risky).

标签文件支持:
- jsonl: 每行 {"traj_id": "...", "label": "risky"|"safe"}  或  {"traj_id":"...","risky":0|1}
- csv:  表头含 traj_id,label  (或 traj_id,risky)
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def _harmonic(a: float, b: float) -> float:
    """调和平均 2ab/(a+b); 任一为 0 或分母为 0 时返回 0."""
    return 2 * a * b / (a + b) if (a + b) > 0 else 0.0


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("risky", "1", "true", "unsafe", "yes")


def load_labels(path: str) -> dict[str, bool]:
    p = Path(path)
    labels: dict[str, bool] = {}
    if p.suffix == ".csv":
        with p.open(encoding="utf-8") as f:
            for row in csv.DictReader(f):
                tid = row.get("traj_id") or row.get("id") or row.get("md5")
                val = row.get("label", row.get("risky"))
                if tid is not None:
                    labels[tid] = _to_bool(val)
    else:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            tid = r.get("traj_id") or r.get("id") or r.get("md5")
            val = r.get("label", r.get("risky"))
            if tid is not None:
                labels[tid] = _to_bool(val)
    return labels


def load_predictions(results_path: str) -> dict[str, bool]:
    preds: dict[str, bool] = {}
    for line in Path(results_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        preds[r["traj_id"]] = bool(r.get("risky", False))
    return preds


def evaluate(results_path: str, labels_path: str) -> dict[str, Any]:
    preds = load_predictions(results_path)
    labels = load_labels(labels_path)
    common = sorted(set(preds) & set(labels))
    tp = fp = fn = tn = 0
    for tid in common:
        p, y = preds[tid], labels[tid]
        if p and y:
            tp += 1
        elif p and not y:
            fp += 1
        elif not p and y:
            fn += 1
        else:
            tn += 1
    n = len(common)
    acc = (tp + tn) / n if n else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0          # = 1 - 漏报率
    miss_rate = (fn / (tp + fn)) if (tp + fn) else 0.0  # 漏报率 FNR
    # 主指标 = 标准 F1 = 调和平均(precision, recall)
    # 即用户公式 2*(1-漏报率)*准确率/[(1-漏报率)+准确率], 其中"准确率"取 precision、(1-漏报率)=recall.
    f1 = _harmonic(prec, rec)
    report = {
        "n_evaluated": n,
        "n_pred_only": len(set(preds) - set(labels)),
        "n_label_only": len(set(labels) - set(preds)),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "f1": round(f1, 4),          # 主指标
        "precision": round(prec, 4),
        "recall": round(rec, 4),     # = 1 - 漏报率
        "miss_rate": round(miss_rate, 4),
        "accuracy": round(acc, 4),
    }
    return report


def print_report(report: dict[str, Any]) -> None:
    c = report["confusion"]
    print("==== 评估 (正类=risky) ====")
    print(f"样本数: {report['n_evaluated']}  (仅预测无标签 {report['n_pred_only']}, 仅标签无预测 {report['n_label_only']})")
    print(f"混淆矩阵: TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']}")
    print(f"漏报率(FNR)={report['miss_rate']}  召回率={report['recall']}  精确率={report['precision']}  accuracy={report['accuracy']}")
    print(f"★ 主指标 F1 = {report['f1']}   (=2·precision·recall/(precision+recall))")
