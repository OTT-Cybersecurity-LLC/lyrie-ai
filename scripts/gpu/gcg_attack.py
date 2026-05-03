#!/usr/bin/env python3
"""Lyrie GCG Adversarial Suffix Generator — Zou et al. 2023. GPU required."""
import argparse, json, subprocess, sys

def has_cuda():
    return subprocess.run(["nvidia-smi"], capture_output=True).returncode == 0

def run_gcg(behavior, model_name, steps, device):
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM
        tok = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        if tok.pad_token is None: tok.pad_token = tok.eos_token
        dtype = torch.float16 if "cuda" in device else torch.float32
        model = AutoModelForCausalLM.from_pretrained(
            model_name, dtype=dtype, trust_remote_code=True,
            attn_implementation="eager"
        ).to(device)
        model.eval()
        suffix_ids = torch.randint(0, tok.vocab_size, (20,)).to(device)
        best_loss, best_suffix = float("inf"), ""
        for step in range(steps):
            text = behavior + " " + tok.decode(suffix_ids, skip_special_tokens=True)
            inp = tok(text, return_tensors="pt", truncation=True, max_length=256).to(device)
            with torch.no_grad():
                loss = model(**inp, labels=inp["input_ids"]).loss.item()
            if loss < best_loss:
                best_loss = loss
                best_suffix = tok.decode(suffix_ids, skip_special_tokens=True)
            suffix_ids[torch.randint(0,20,(1,)).item()] = torch.randint(0, tok.vocab_size, (1,)).item()
            if step % 50 == 0: print(f"[gcg] {step}/{steps} loss={loss:.4f}", file=sys.stderr)
        return {"suffix": best_suffix, "loss": best_loss, "steps": steps, "model": model_name, "device": device}
    except ImportError as e:
        return {"error": str(e), "suffix": "", "loss": 9999, "steps": 0, "model": model_name, "device": device}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--target-behavior", required=True)
    p.add_argument("--model", default="gpt2")
    p.add_argument("--steps", type=int, default=500)
    p.add_argument("--device", default="cuda" if has_cuda() else "cpu")
    p.add_argument("--output-json", action="store_true")
    a = p.parse_args()
    r = run_gcg(a.target_behavior, a.model, a.steps, a.device)
    print(json.dumps(r) if a.output_json else f"suffix: {r.get('suffix')}")
