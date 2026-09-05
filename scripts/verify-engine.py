#!/usr/bin/env python3
"""Exercise the actual packaged scanner using harmless, temporary fixtures only."""
import hashlib, pathlib, subprocess, tempfile, os
base = pathlib.Path(__file__).resolve().parent.parent
contents = base / 'dist' / 'IRIS Mac Companion.app' / 'Contents'
scanner = contents / 'Helpers' / 'clamscan'
certificates = contents / 'Resources' / 'ClamAV' / 'etc' / 'certs'
with tempfile.TemporaryDirectory(prefix='iris-engine-check-') as directory:
    root = pathlib.Path(directory)
    sample = root / 'sample.txt'
    sample.write_text('IRIS harmless scanner verification fixture')
    signature = root / 'fixture.hdb'
    signature.write_text(f'{hashlib.md5(sample.read_bytes()).hexdigest()}:{sample.stat().st_size}:IRIS.Harmless.Test\n')
    for should_match in (True, False):
        if not should_match: sample.write_text('Different harmless content')
        result = subprocess.run([str(scanner), '--cvdcertsdir='+str(certificates), '--database='+str(signature), '--no-summary', str(sample)], capture_output=True, text=True, env={**os.environ, 'CVD_CERTS_DIR': str(certificates)})
        assert result.returncode == (1 if should_match else 0), result.stderr
        assert ('IRIS.Harmless.Test' in result.stdout) == should_match, result.stdout
print('PASS: actual ClamAV runtime detected the matching harmless fixture and accepted the nonmatching fixture.')
