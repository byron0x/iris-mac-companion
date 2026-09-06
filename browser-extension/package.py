#!/usr/bin/env python3
"""Create a store submission archive from an explicit runtime allowlist."""
from pathlib import Path
import hashlib,json,zipfile
root=Path(__file__).resolve().parent
manifest=json.loads((root/'manifest.json').read_text())
# Chrome assigns a publisher-controlled store identity on first upload. This key is for local testing.
manifest.pop('key',None)
out=root.parent/'dist';out.mkdir(exist_ok=True)
archive=out/f"IRIS-Browser-Companion-{manifest['version']}.zip"
files=['audit.mjs','service.mjs','worker.js','review.js','review.html','review.css','LICENSE','protection.mjs','scam-guard.mjs','warning.html','warning.js','data/crypto-phishing.json','data/source.json','data/SCAMSNIFFER-LICENSE']
files += ['assets/'+p.name for p in sorted((root/'assets').iterdir()) if p.is_file()]
files += ['browser-scan.mjs', 'account-access.mjs']
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
 z.writestr('manifest.json',json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
 for file in files:z.write(root/file,file)
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
(Path(str(archive)+'.sha256')).write_text(digest+'  '+archive.name+'\n')
print(str(archive))
print('SHA-256: '+digest)
