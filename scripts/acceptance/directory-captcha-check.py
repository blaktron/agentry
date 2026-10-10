#!/usr/bin/env python3
"""Pin the frontend contract used by the directory's Turnstile adapter."""
import hashlib
import json
from pathlib import Path
import sys

# Known-good source in the exact compose image. The protected renderBody slot
# and controller lifecycle are compatibility hooks, not a stable upstream API.
# An image upgrade must review these contracts and the real widget browser test.
EXPECTED = {
    '/captcha/CaptchaStage.ts': '398e1a8af811ad2852c43c13dafabbbc51601a4d88e1cc973995c1baf968222d',
    '/captcha/controllers/CaptchaController.ts': '0a767dab0bc18808f64afa6ba2a41cb9fced9a7d642c180c6049786f465f450c',
    '/captcha/controllers/turnstile.ts': 'cea293657226389a87aaa64a59aee77a470a0969530fdf957e12072836a260f9',
}
found = {}
for path in Path(sys.argv[1]).rglob('*.map'):
    raw = path.read_text()
    if 'CaptchaStage.ts' not in raw:
        continue
    data = json.loads(raw)
    for name, source in zip(data.get('sources', []), data.get('sourcesContent', [])):
        for suffix, wanted in EXPECTED.items():
            if name.endswith(suffix):
                actual = hashlib.sha256(source.encode()).hexdigest()
                assert actual == wanted, 'pinned CAPTCHA interface changed: review ' + suffix
                found[suffix] = actual
assert found == EXPECTED, 'pinned image lacks a required CAPTCHA frontend contract'
print('PASS pinned CAPTCHA renderer/controller contracts; review required on image upgrade')
