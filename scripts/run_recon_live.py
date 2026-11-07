"""Phase 2 live check: run the Recon Agent against the real sandboxed Juice Shop and
print the AttackSurfaceMap for manual spot-checking (08_BUILD_ROADMAP.md, Phase 2).

Usage:  python scripts/run_recon_live.py [base_url]
        (default base_url = http://127.0.0.1:3000)
"""
from __future__ import annotations

import asyncio
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agents import recon  # noqa: E402

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"


async def main() -> int:
    surface = await recon.recon(BASE_URL)
    eps = surface.endpoints
    print(f"target          : {surface.target_base_url}")
    print(f"endpoints found : {len(eps)}")
    print(f"by method       : {dict(Counter(e.method for e in eps))}")

    # Spot-check: a few recognizable Juice Shop endpoints should be present.
    expected = ["/rest/basket", "/rest/user/login", "/api/Products", "/rest/products/search"]
    print("\nspot-check (known Juice Shop endpoints):")
    for frag in expected:
        hit = any(frag in e.url for e in eps)
        print(f"  [{'x' if hit else ' '}] {frag}")

    print("\nsample endpoints:")
    for e in eps[:20]:
        p = ", ".join(f"{x.name}:{x.location}:{x.type}" for x in e.params) or "-"
        print(f"  {e.method:6} {e.url}   params=({p})")

    ok = len(eps) >= 10 and all(any(f in e.url for e in eps) for f in expected)
    print("\nRESULT:", "PASS — non-trivial, spot-checkable AttackSurfaceMap" if ok
          else "map smaller than expected (see above)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
