#!/usr/bin/env python3
"""Reject ZIP layout that can corrupt signed macOS bundles during extraction."""
import pathlib, stat, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    assert archive.testzip() is None, 'Corrupt ZIP member'
    names = archive.namelist()
    assert len(set(names)) == len(names), 'Duplicate ZIP members'
    for entry in archive.infolist():
        path = pathlib.PurePosixPath(entry.filename)
        assert path.parts[0] == 'IRIS Mac Companion.app' and '..' not in path.parts, 'Unexpected ZIP path'
        assert not any(part.startswith('._') or part == '__MACOSX' for part in path.parts), 'AppleDouble sidecar inside release'
        if stat.S_ISLNK(entry.external_attr >> 16):
            target = archive.read(entry).decode('utf-8')
            assert not target.startswith('/'), 'Absolute symlink in app'
            # Resolve components without requiring the files to exist on disk.
            parts = list(path.parent.parts)
            for part in pathlib.PurePosixPath(target).parts:
                if part == '..':
                    assert len(parts) > 1, 'Symlink escapes app'
                    parts.pop()
                elif part != '.': parts.append(part)
    assert 'IRIS Mac Companion.app/Contents/MacOS/IRISCompanion' in names
print('PASS: ZIP integrity, paths, symlinks and metadata-free bundle.')
