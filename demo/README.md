# Custos demo

## Interactive live demo

Start the browser demo from PowerShell:

```powershell
.\demo\start_live_demo.ps1
```

Then open [http://127.0.0.1:8000/demo](http://127.0.0.1:8000/demo). The page fetches the live Treasury reference, keeps its health state refreshed, and executes real intent requests against the gateway. The **Sync live market** action aligns only the in-memory simulated claims to the just-fetched reference, so every displayed scenario remains meaningful while the market observation is real.

Run the complete demonstration from the repository root:

```powershell
python demo/run_local_demo.py
```

It calls the real FastAPI gateway routes in-process and presents four deterministic outcomes:

1. Stale claim → `CUSTOS-E300`
2. Recent but drifted yield → `CUSTOS-E301`
3. Under-backed claim → `CUSTOS-E302`
4. Healthy claim → signed `ALLOW`, independently verified with Ed25519

The runner writes the successful attestation to `demo/attestation.json` and prints the
gateway's public key. Verify it again in a separate command, passing that key
**out of band** — the `public_key` field inside the record authenticates nothing:

```powershell
python demo/verify_attestation.py demo/attestation.json --public-key <key from the run above, or GET /v1/pubkey>
```

`run_local_demo.py` substitutes only a fixed 400 bps observation, so the demo is repeatable. The production gateway retains its live Treasury client and fails closed with `CUSTOS-E300` if that source is unreachable.

For the live network version, start the gateway and use the existing HTTP client:

```powershell
python -m uvicorn gateway.server:app
python demo/run_demo.py
```
