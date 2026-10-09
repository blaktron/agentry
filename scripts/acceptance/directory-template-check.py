"""Compare the pinned upstream flow around the two deliberate CSP bootstraps."""
import hashlib
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[2]
upstream = Path(sys.argv[1]).read_text()
header = Path(sys.argv[2]).read_bytes()
assert hashlib.sha256(header).hexdigest() == '4846ec799cb183ae35207a537bc340c70d0618c497ccf0771225f5f8b250b9ff', 'pinned header_js.html changed; review its bootstrap contract'
config = re.search(r'<script data-id="flow-config">.*?</script>', upstream, re.S)
assert config and hashlib.sha256(config.group().encode()).hexdigest() == 'cecb4998614ad709fff860d033e972f3de528c4fc54fcabc1ab19734bdcecabc', 'pinned flow bootstrap changed; review its runtime values'
ours = (root / 'deploy/compose/authentik/templates/if/flow.html').read_text().split('{# agentry:begin remembered-browser')[0]
assert ours.count('{% include "agentry/directory_config.html" %}') == 1
ours = ours.replace('{% include "agentry/directory_config.html" %}', '{% include "base/header_js.html" %}', 1)
ours, count = re.subn(r'<script id="agentry-flow-data" type="application/json">.*?</script>\n', '', ours, count=1, flags=re.S)
assert count == 1, 'the flow has no non-executable runtime data'
ours, count = re.subn(r'<script data-id="flow-config">.*?</script>', lambda _: config.group(), ours, count=1, flags=re.S)
assert count == 1 and ours == upstream, 'the flow changed outside the two reviewed CSP bootstraps'
print('ok   pinned flow unchanged except reviewed data-only CSP bootstraps')
