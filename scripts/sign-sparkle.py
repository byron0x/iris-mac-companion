#!/usr/bin/env python3
"""Sign Sparkle's nested code from the inside out without changing entitlements."""
import pathlib, subprocess, sys
framework = pathlib.Path(sys.argv[1])
identity = sys.argv[2]
assert framework.is_dir() and framework.name == 'Sparkle.framework'
args = ['codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', identity]
for path in sorted(framework.rglob('*'), key=lambda p: len(p.parts), reverse=True):
    if path.is_symlink(): continue
    if path.is_file() and 'Mach-O' in subprocess.check_output(['file',str(path)],text=True):
        subprocess.run(args + ['--preserve-metadata=entitlements',str(path)],check=True)
    elif path.is_dir() and path.suffix in ('.app','.xpc'):
        subprocess.run(args + ['--preserve-metadata=entitlements',str(path)],check=True)
subprocess.run(args + [str(framework)],check=True)
subprocess.run(['codesign','--verify','--deep','--strict',str(framework)],check=True)
