"""Local detector sidecar for agent-understudy.

Loads token-classification models lazily and serves them over HTTP on 127.0.0.1:

  GET  /health                      -> {"models": {id: {...status}}}
  POST /pull   {"model": id}        -> downloads weights into $AGENT_UNDERSTUDY_HOME/models/<id>
  POST /detect {"text": str, "models": [id, ...]}
       -> {"results": {id: {"spans": [{start, end, label, score, source}], "ms": float} | {"error": str}}}

Offsets in responses are UTF-16 code units so the TypeScript side can slice JS strings directly.
Labels are already mapped onto the unified set (SECRET, EMAIL, PHONE, PERSON, ADDRESS, ACCOUNT, URL, DATE, IP, ID).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

# Metal asserts when two threads encode GPU work at once; all MPS/CUDA models share this lock.
GPU_LOCK = threading.Lock()

HOME = Path(os.environ.get("AGENT_UNDERSTUDY_HOME", Path.home() / ".agent-understudy"))
MODELS_DIR = HOME / "models"


def utf16_offsets(text: str) -> list[int]:
    """Maps a code-point index to a UTF-16 index (len + 1 entries)."""
    out = [0]
    for ch in text:
        out.append(out[-1] + (2 if ord(ch) > 0xFFFF else 1))
    return out


def best_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def merge_adjacent(spans: list[dict], text: str) -> list[dict]:
    """Joins same-label spans separated only by spaces/commas (GIVEN_NAME + SURNAME -> PERSON)."""
    spans = sorted(spans, key=lambda s: s["start"])
    out: list[dict] = []
    for s in spans:
        if out and out[-1]["label"] == s["label"] and re.fullmatch(r"[ ,]{0,2}", text[out[-1]["end"] : s["start"]]):
            prev = out[-1]
            prev["end"] = max(prev["end"], s["end"])
            prev["score"] = min(prev["score"], s["score"])
            prev["source"] = prev["source"] if prev["source"] == s["source"] else f'{prev["source"]}+{s["source"]}'
            prev["parts"] = prev.get("parts", []) + s.get("parts", [])
        else:
            out.append({**s, "parts": list(s.get("parts", []))})
    return out


def merge_parts(parts: list[dict], text: str) -> list[dict]:
    """Joins touching or space-separated parts of the same kind ("de la" + "Cruz" -> family "de la Cruz")."""
    out: list[dict] = []
    for p in sorted(parts, key=lambda p: p["start"]):
        if out and out[-1]["kind"] == p["kind"] and re.fullmatch(r" ?", text[out[-1]["end"] : p["start"]]):
            out[-1]["end"] = max(out[-1]["end"], p["end"])
        else:
            out.append(dict(p))
    return out


def chunks(text: str, size: int = 1500, overlap: int = 200):
    """Yields (offset, piece) windows, breaking on newlines or spaces where possible."""
    if len(text) <= size:
        yield 0, text
        return
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            cut = max(text.rfind("\n", start + size // 2, end), text.rfind(" ", start + size // 2, end))
            if cut > start:
                end = cut
        yield start, text[start:end]
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)


def dedupe(spans: list[dict]) -> list[dict]:
    """Overlapping windows report the same entity twice; keep the higher-scoring copy."""
    spans = sorted(spans, key=lambda s: (s["start"], -s["end"]))
    out: list[dict] = []
    for s in spans:
        if out and s["start"] < out[-1]["end"] and s["label"] == out[-1]["label"]:
            if s["score"] > out[-1]["score"]:
                out[-1] = {**s, "start": min(s["start"], out[-1]["start"]), "end": max(s["end"], out[-1]["end"])}
            else:
                out[-1]["end"] = max(out[-1]["end"], s["end"])
            continue
        out.append(s)
    return out


@dataclass
class ModelSpec:
    id: str
    repo: str
    license: str
    size: str
    note: str
    loader: Callable[["ModelSpec", Path], Callable[[str], list[dict]]]
    allow_patterns: list[str] | None = None
    pipeline: object | None = field(default=None, repr=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    device: str | None = None
    error: str | None = None

    @property
    def path(self) -> Path:
        return MODELS_DIR / self.id

    @property
    def pulled(self) -> bool:
        return (self.path / ".complete").exists()


# ---- loaders: each returns detect(text) -> spans with code-point offsets ---------------------------

PF_LABELS = {
    "account_number": "ACCOUNT", "private_address": "ADDRESS", "private_email": "EMAIL",
    "private_person": "PERSON", "private_phone": "PHONE", "private_url": "URL",
    "private_date": "DATE", "secret": "SECRET",
}


def load_privacy_filter(spec: ModelSpec, path: Path):
    # Without Triton, OPF's MoE fallback copies expert weights per token; swap in a grouped forward
    # (identical spans, ~7x faster). CPU and MPS run it at the same speed, so keep the GPU free.
    os.environ.setdefault("OPF_MOE_TRITON", "0")
    import opf_fast
    from opf import OPF

    if os.environ["OPF_MOE_TRITON"] == "0":
        opf_fast.install()
    device = "cuda" if os.environ["OPF_MOE_TRITON"] != "0" else "cpu"
    opf = OPF(model=str(path / "original"), device=device)  # type: ignore[arg-type]
    spec.device = device

    def detect(text: str) -> list[dict]:
        r = opf.redact(text)
        # OPF has no span scores; Viterbi-decoded spans are its committed decisions.
        return [
            {"start": s.start, "end": s.end, "label": PF_LABELS[s.label], "score": 0.9, "source": s.label}
            for s in r.detected_spans
            if s.label in PF_LABELS
        ]

    return detect


def hf_token_classifier(label_map: dict[str, str | None]):
    def load(spec: ModelSpec, path: Path):
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

        tok = AutoTokenizer.from_pretrained(path)
        model = AutoModelForTokenClassification.from_pretrained(path)
        spec.device = best_device()
        # No pipeline stride: it batches every overflow window at once (17 GB on MPS for 60k chars).
        # Feed bounded chunks one at a time instead; 1200 chars stays under 512 tokens even for dense code.
        pipe = pipeline(
            "token-classification", model=model, tokenizer=tok, aggregation_strategy="max", device=spec.device,
        )

        def detect(text: str) -> list[dict]:
            spans = []
            for off, piece in chunks(text, size=1200, overlap=150):
                for e in pipe(piece):
                    native = e["entity_group"]
                    label = label_map.get(native)
                    if not label:
                        continue
                    spans.append((off, e, native, label))
            out = []
            for off, e, native, label in spans:
                start, end = off + int(e["start"]), off + int(e["end"])
                while start < end and text[start].isspace():
                    start += 1
                # Taggers often swallow the sentence's closing punctuation.
                while end > start and (text[end - 1].isspace() or text[end - 1] in ".,;:!?)"):
                    end -= 1
                span = {"start": start, "end": end, "label": label, "score": float(e["score"]), "source": native}
                if native in PART_KINDS:
                    span["parts"] = [{"start": start, "end": end, "kind": PART_KINDS[native]}]
                out.append(span)
            merged = merge_adjacent(dedupe(out), text)
            for m in merged:
                if m.get("parts"):
                    m["parts"] = merge_parts(m["parts"], text)
            return merged

        return detect

    return load


# Sub-entity kinds the TypeScript side uses to build structure-preserving surrogates
# (a given name becomes a given name, a house number keeps its digit count).
PART_KINDS = {
    "GIVEN_NAME": "given", "GIVENNAME": "given", "SURNAME": "family",
    "STREET_NAME": "street", "STREET": "street", "BUILDING_NUMBER": "number", "BUILDINGNUM": "number",
    "CITY": "city", "ZIP_CODE": "zip", "ZIPCODE": "zip",
}

MASKER_LABELS = {
    "GIVEN_NAME": "PERSON", "SURNAME": "PERSON", "STREET_NAME": "ADDRESS", "BUILDING_NUMBER": "ADDRESS",
    "CITY": "ADDRESS", "ZIP_CODE": "ADDRESS", "EMAIL": "EMAIL", "PHONE": "PHONE", "CREDIT_CARD": "ACCOUNT",
    "GOVERNMENT_ID": "ID", "DATE": "DATE", "AGE": None,
}
PIIRANHA_LABELS = {
    "ACCOUNTNUM": "ACCOUNT", "CREDITCARDNUMBER": "ACCOUNT", "BUILDINGNUM": "ADDRESS", "CITY": "ADDRESS",
    "STREET": "ADDRESS", "ZIPCODE": "ADDRESS", "DATEOFBIRTH": "DATE", "DRIVERLICENSENUM": "ID",
    "IDCARDNUM": "ID", "SOCIALNUM": "ID", "TAXNUM": "ID", "EMAIL": "EMAIL", "GIVENNAME": "PERSON",
    "SURNAME": "PERSON", "PASSWORD": "SECRET", "TELEPHONENUM": "PHONE", "USERNAME": None,
}
GLINER_LABELS = {
    "person": "PERSON", "email": "EMAIL", "phone number": "PHONE", "street address": "ADDRESS",
    "bank account number": "ACCOUNT", "credit card number": "ACCOUNT", "social security number": "ID",
    "passport number": "ID", "password": "SECRET", "api key": "SECRET", "date of birth": "DATE",
}


def load_gliner(spec: ModelSpec, path: Path):
    from gliner import GLiNER

    model = GLiNER.from_pretrained(str(path))
    spec.device = best_device()
    try:
        model = model.to(spec.device)
    except Exception:
        spec.device = "cpu"
    labels = list(GLINER_LABELS)

    def detect(text: str) -> list[dict]:
        spans = []
        for off, piece in chunks(text, size=1200, overlap=150):
            for e in model.predict_entities(piece, labels, threshold=0.4):
                spans.append({
                    "start": off + int(e["start"]), "end": off + int(e["end"]),
                    "label": GLINER_LABELS[e["label"]], "score": float(e["score"]), "source": e["label"],
                })
        return dedupe(spans)

    return detect


MODELS: dict[str, ModelSpec] = {
    m.id: m
    for m in [
        ModelSpec(
            "privacy-filter", "openai/privacy-filter", "Apache-2.0", "2.8 GB",
            "OpenAI Privacy Filter: 8 labels incl. secrets, 128k context, Viterbi decoding",
            load_privacy_filter, allow_patterns=["original/*", "README.md"],
        ),
        ModelSpec(
            "masker", "divergentlabs/masker", "Apache-2.0", "0.56 GB",
            "DeBERTa-v3 PII tagger (names, addresses, contact, IDs), 23 languages",
            hf_token_classifier(MASKER_LABELS),
        ),
        ModelSpec(
            "gliner-pii", "nvidia/gliner-PII", "NVIDIA Open Model License", "1.2 GB",
            "Zero-shot GLiNER tuned for PII; labels chosen at query time",
            load_gliner,
        ),
        ModelSpec(
            "piiranha", "iiiorg/piiranha-v1-detect-personal-information", "CC-BY-NC-ND-4.0 (non-commercial)", "1.1 GB",
            "mDeBERTa PII tagger incl. passwords/usernames; non-commercial license, opt-in only",
            hf_token_classifier(PIIRANHA_LABELS),
        ),
    ]
}


def pull(spec: ModelSpec) -> None:
    from huggingface_hub import snapshot_download

    spec.path.mkdir(parents=True, exist_ok=True)
    snapshot_download(spec.repo, local_dir=spec.path, allow_patterns=spec.allow_patterns)
    (spec.path / ".complete").write_text(time.strftime("%Y-%m-%dT%H:%M:%S"))


def ensure_loaded(spec: ModelSpec):
    if spec.pipeline is None:
        if not spec.pulled:
            raise RuntimeError(f"model {spec.id} is not pulled; run: understudy models pull {spec.id}")
        spec.pipeline = spec.loader(spec, spec.path)
    return spec.pipeline


def run(spec: ModelSpec, text: str) -> dict:
    t0 = time.perf_counter()
    try:
        # privacy-filter runs on CPU (see load_privacy_filter); everything else may be on the GPU.
        lock = spec.lock if spec.id == "privacy-filter" else GPU_LOCK
        with lock:
            detect = ensure_loaded(spec)
            spans = detect(text)
        spec.error = None
    except Exception as e:  # report per model; other models still vote
        spec.error = f"{type(e).__name__}: {e}"
        return {"error": spec.error}
    u = utf16_offsets(text)
    for s in spans:
        s["start"], s["end"] = u[s["start"]], u[s["end"]]
        for p in s.get("parts") or []:
            p["start"], p["end"] = u[p["start"]], u[p["end"]]
        if not s.get("parts"):
            s.pop("parts", None)
    return {"spans": spans, "ms": round((time.perf_counter() - t0) * 1000, 1)}


def status() -> dict:
    return {
        m.id: {
            "repo": m.repo, "license": m.license, "size": m.size, "note": m.note, "pulled": m.pulled,
            "loaded": m.pipeline is not None, "device": m.device, "error": m.error,
        }
        for m in MODELS.values()
    }


LAST_REQUEST = time.monotonic()


def _exit_when_idle(seconds: int) -> None:
    # Engines start this sidecar on demand and nobody stops it: it leaves once no engine has asked for a while.
    while True:
        time.sleep(min(30, seconds))
        if time.monotonic() - LAST_REQUEST > seconds:
            os._exit(0)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet; never log request bodies
        pass

    def reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"ok": True, "models": status()})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        global LAST_REQUEST
        LAST_REQUEST = time.monotonic()
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        except json.JSONDecodeError:
            return self.reply(400, {"error": "bad json"})
        if self.path == "/detect":
            ids = body.get("models") or [m.id for m in MODELS.values() if m.pulled]
            unknown = [i for i in ids if i not in MODELS]
            if unknown:
                return self.reply(400, {"error": f"unknown models: {unknown}"})
            # "texts" batches many strings into one call; "text" is the single-string form.
            texts = body["texts"] if isinstance(body.get("texts"), list) else [body.get("text", "")]
            per_text: list[dict[str, dict]] = [{} for _ in texts]

            def model_worker(i: str) -> None:
                for k, t in enumerate(texts):
                    per_text[k][i] = run(MODELS[i], t)

            threads = [threading.Thread(target=model_worker, args=(i,)) for i in ids]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            if isinstance(body.get("texts"), list):
                return self.reply(200, {"batch": per_text})
            return self.reply(200, {"results": per_text[0]})
        if self.path == "/pull":
            spec = MODELS.get(body.get("model", ""))
            if not spec:
                return self.reply(400, {"error": "unknown model"})
            try:
                pull(spec)
            except Exception as e:
                return self.reply(500, {"error": f"{type(e).__name__}: {e}"})
            return self.reply(200, {"ok": True, "model": status()[spec.id]})
        if self.path == "/load":
            spec = MODELS.get(body.get("model", ""))
            if not spec:
                return self.reply(400, {"error": "unknown model"})
            r = run(spec, "warmup")
            return self.reply(200 if "spans" in r else 500, {"model": status()[spec.id], **r})
        self.reply(404, {"error": "not found"})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("AGENT_UNDERSTUDY_SIDECAR_PORT", 8791)))
    ap.add_argument("--preload", nargs="*", default=[], help="model ids to load at startup")
    ap.add_argument("--idle-exit", type=int, default=0, help="exit after this many seconds without a request (0 = never)")
    args = ap.parse_args()
    # Bind first: a second sidecar started at the same moment exits here instead of loading models for nothing.
    ThreadingHTTPServer.request_queue_size = 128
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    if args.idle_exit > 0:
        threading.Thread(target=_exit_when_idle, args=(args.idle_exit,), daemon=True).start()
    # Serve /health while preloading, so engines can watch the models come up.
    server = threading.Thread(target=srv.serve_forever, daemon=True)
    server.start()
    print(json.dumps({"listening": f"127.0.0.1:{args.port}"}), flush=True)
    for i in args.preload:
        if i in MODELS and MODELS[i].pulled:
            run(MODELS[i], "warmup")
    server.join()


if __name__ == "__main__":
    main()
