"""Grouped-expert MoE forward for OPF on machines without Triton (Apple Silicon, plain CPU).

OPF's non-Triton path gathers a full copy of each selected expert's weights per token before a
batched matmul, which is slow and memory-heavy. This forward groups tokens by expert and runs one
matmul per active expert instead. Same math (routing, SwiGLU, bias, gate scaling), different order.
"""

from __future__ import annotations

import torch
from opf._model import model as opf_model


def _grouped_forward(self: opf_model.MLPBlock, x: torch.Tensor) -> torch.Tensor:
    if x.dim() != 3 or getattr(self, "world_size", 1) > 1:
        return _original_forward(self, x)
    batch_shape = x.shape[:-1]
    t = self.norm(x).reshape(-1, x.shape[-1])
    g = torch.nn.functional.linear(t.float(), self.gate.weight.float(), self.gate.bias.float())
    experts = torch.topk(g, k=self.experts_per_token, dim=-1, sorted=True)
    # Same scaling as upstream: softmax / k, then * k after the weighted sum -> plain softmax weights.
    weights = torch.softmax(experts.values, dim=1)
    idx = experts.indices

    tf = t.float()
    out = torch.zeros_like(tf)
    flat_e = idx.reshape(-1)
    flat_tok = torch.arange(t.shape[0], device=t.device).repeat_interleave(idx.shape[1])
    flat_w = weights.reshape(-1)
    order = torch.argsort(flat_e)
    flat_e, flat_tok, flat_w = flat_e[order], flat_tok[order], flat_w[order]
    counts = torch.bincount(flat_e, minlength=self.num_experts).tolist()
    start = 0
    for e, n in enumerate(counts):
        if not n:
            continue
        tok = flat_tok[start : start + n]
        w = flat_w[start : start + n].unsqueeze(1)
        h = tf[tok] @ self.mlp1_weight[e].float() + self.mlp1_bias[e].float()
        h = opf_model.swiglu(h, limit=self.swiglu_limit, packed=self.packed_geglu)
        h = h @ self.mlp2_weight[e].float() + self.mlp2_bias[e].float()
        out.index_add_(0, tok, h * w)
        start += n
    return x + out.to(x.dtype).reshape(*batch_shape, -1)


_original_forward = opf_model.MLPBlock.forward


def install() -> None:
    opf_model.MLPBlock.forward = _grouped_forward
