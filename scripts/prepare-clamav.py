#!/usr/bin/env python3
"""Prepare verified upstream ClamAV as relocatable, separately signed executables.
Only library search paths change; preserve the exact corresponding source archive.
"""
import hashlib, os, pathlib, shutil, subprocess, tempfile, urllib.request
BASE = pathlib.Path(__file__).resolve().parent.parent
CACHE = BASE / '.build' / 'upstream'
CACHE.mkdir(parents=True, exist_ok=True)
RELEASE = 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/'

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def download(name, digest):
    file = CACHE / name
    if not file.exists():
        with urllib.request.urlopen(RELEASE + name) as response, file.open('wb') as output:
            shutil.copyfileobj(response, output)
    if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
        raise RuntimeError('Upstream checksum mismatch: ' + name)
    return file

pkg = download('clamav-1.5.4.macos.universal.pkg', 'df7fa753e2f9f67f3bc99b2a40a3be7ef559088c68ad6bdf66b4b5764e965bd6')
source = download('clamav-1.5.4.tar.gz', '1af1117a228f1b5bc7fa91a0dabc37848a99e7d25188e9be8043332ce721dfd3')
bundle = pathlib.Path(os.environ.get('IRIS_APP_BUNDLE', str(BASE / 'dist' / 'IRIS Mac Companion.app')))
target = BASE / '.build' / 'ClamAV-runtime'
legacy = bundle / 'Contents' / 'Frameworks' / 'ClamAV'
if legacy.exists(): shutil.rmtree(legacy)
if target.exists(): shutil.rmtree(target)
with tempfile.TemporaryDirectory(prefix='iris-clam-build-') as stage:
    expanded = pathlib.Path(stage) / 'expanded'
    run('/usr/sbin/pkgutil', '--expand-full', str(pkg), str(expanded))
    for part in ('programs', 'libraries', 'documentation'):
        payload = expanded / f'clamav-1.5.4.macos.universal-{part}.pkg' / 'Payload' / 'usr' / 'local' / 'clamav'
        run('/usr/bin/ditto', str(payload), str(target))
    # Ship only the three CLI tools used by IRIS; no upload or daemon tools.
    for file in (target / 'bin').iterdir():
        if file.name not in ('clamscan', 'freshclam', 'sigtool'): file.unlink()
    for extra in ('sbin', 'include', 'share/man', 'lib/pkgconfig', 'lib/cmake'):
        folder = target / extra
        if folder.exists(): shutil.rmtree(folder)
    for archive in (target / "lib").rglob("*.a"): archive.unlink()
    macho = []
    for file in target.rglob('*'):
        if not file.is_file() or file.is_symlink(): continue
        if 'Mach-O' not in run('/usr/bin/file', str(file)): continue
        run('/usr/bin/codesign', '--verify', '--strict', '-R', '=anchor apple generic and certificate leaf[subject.OU] = "DE8Y96K9QP"', str(file))
        paths = run('/usr/bin/otool', '-l', str(file))
        if '/usr/local/clamav/lib' in paths:
            relative = '@loader_path/../Frameworks' if file.parent.name == 'bin' else '@loader_path'
            run('/usr/bin/install_name_tool', '-rpath', '/usr/local/clamav/lib', relative, str(file))
        macho.append(file)
    # Ad-hoc for local tests. release.sh replaces these with Developer ID signatures.
    for file in macho: run('/usr/bin/codesign', '--force', '--sign', '-', str(file))
    helpers = bundle / 'Contents' / 'Helpers'
    frameworks = bundle / 'Contents' / 'Frameworks'
    resources = bundle / 'Contents' / 'Resources' / 'ClamAV'
    for folder in (helpers, frameworks, resources): folder.mkdir(parents=True, exist_ok=True)
    run('/usr/bin/ditto', str(target / 'bin'), str(helpers))
    run('/usr/bin/ditto', str(target / 'lib'), str(frameworks))
    for name in ('etc', 'share'):
        if (target / name).exists(): run('/usr/bin/ditto', str(target / name), str(resources / name))
    run(str(helpers / 'clamscan'), '--version')
shutil.copy2(source, BASE / 'dist' / source.name)
print('ClamAV runtime and corresponding source prepared.')
