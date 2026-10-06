"""Prepare only the reviewed SOC integration files; do not mutate the target repository."""
from pathlib import Path
import difflib
import hashlib
import json

source = Path('/home/geonug/kdt-linux/autonomous-soc-agent')
stage = Path('/tmp/soc-network-integration')
out = Path(__file__).resolve().parent
paths = ['README.md', 'pyproject.toml', 'uv.lock',
         'src/soc_agent/assessment/prompts.py', 'src/soc_agent/assessment/validator.py']
for folder in ['src/soc_agent/security_ai/network/v4', 'tests/unit/security_ai/network_v4',
               'tests/fixtures/network_v4', 'examples/network_v4']:
    paths.extend(str(p.relative_to(stage)) for p in sorted((stage/folder).rglob('*'))
                 if p.is_file() and '__pycache__' not in p.parts)
paths.extend(['tests/integration/test_network_security_ai_v4.py', 'docs/network-security-ai-v4.md'])
changes = []
patch = ''
for name in paths:
    a, b = source/name, stage/name
    old = a.read_bytes() if a.exists() else b''
    new = b.read_bytes()
    if a.exists() and old == new:
        continue
    changes.append({'path': name, 'status': 'modified' if a.exists() else 'added',
                    'old_sha256': hashlib.sha256(old).hexdigest() if a.exists() else None,
                    'new_sha256': hashlib.sha256(new).hexdigest(), 'bytes': len(new)})
    patch += f'diff --git a/{name} b/{name}\n'
    if not a.exists():
        patch += 'new file mode 100644\n'
    patch += ''.join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True),
                                        fromfile='a/'+name if a.exists() else '/dev/null',
                                        tofile='b/'+name))
(out/'autonomous_soc_network_v4.patch').write_text(patch)
(out/'network_v4_change_plan.json').write_text(json.dumps(
    {'source_root': str(source), 'staging_root': str(stage), 'changes': changes}, indent=2))
print(f'{len(changes)} reviewed file changes, {len(patch.splitlines())} patch lines')
