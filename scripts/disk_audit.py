"""Find exact file duplicates and report potential savings by volume."""

import argparse
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time


@dataclass(frozen=True)
class File:
    path: Path
    size: int
    volume: str
    signature: tuple


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink)


def inventory(roots, minimum, issues, skipped, excluded=()):
    seen = set()
    identities = set()
    pending = list(reversed(roots))
    while pending:
        path = pending.pop()
        key = str(path)
        if key in seen or os.path.normcase(key) in excluded:
            continue
        seen.add(key)
        try:
            info = path.lstat()
            # Skip Windows junctions, symlinks and cloud placeholders.
            attributes = getattr(info, 'st_file_attributes', 0)
            unsafe = (stat.FILE_ATTRIBUTE_REPARSE_POINT | stat.FILE_ATTRIBUTE_OFFLINE
                      | 0x00400000 | 0x00040000)  # Windows recall-on-access/open flags
            if stat.S_ISLNK(info.st_mode) or attributes & unsafe:
                skipped['links_or_offline'] += 1
            elif stat.S_ISDIR(info.st_mode):
                if path.name.casefold() in {'$recycle.bin', 'system volume information'}:
                    skipped['system_directories'] += 1
                    continue
                with os.scandir(path) as entries:
                    pending.extend(path / entry.name for entry in entries)
            elif stat.S_ISREG(info.st_mode) and info.st_size >= minimum:
                if info.st_nlink > 1:
                    skipped['hard_links'] += 1
                    continue
                identity = (info.st_dev, info.st_ino)
                if info.st_ino:
                    if identity in identities:
                        continue
                    identities.add(identity)
                volume = path.drive.upper() or str(info.st_dev)
                yield File(path, info.st_size, volume, signature(info))
        except OSError as error:
            issues.append({'path': str(path), 'error': str(error)})


def hash_file(file, limit, issues):
    digest = hashlib.sha256()
    try:
        with file.path.open('rb') as stream:
            if signature(os.fstat(stream.fileno())) != file.signature:
                raise OSError('File changed since inventory')
            if limit is None:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            else:
                digest.update(stream.read(limit))
            if (signature(os.fstat(stream.fileno())) != file.signature
                    or signature(file.path.lstat()) != file.signature):
                raise OSError('File changed during hashing')
    except OSError as error:
        issues.append({'path': str(file.path), 'error': str(error)})
        return None
    return digest.hexdigest()


def candidates(buckets, cross_volume):
    return ((key, files) for key, files in buckets.items()
            if len(files) > 1 and (not cross_volume or
                                   len({file.volume for file in files}) > 1))


def compare(same_size, cross_volume, issues):
    groups = []
    prefixes = defaultdict(list)
    for file in same_size:
        digest = hash_file(file, 64 * 1024, issues)
        if digest is not None:
            prefixes[digest].append(file)
    for _, same_prefix in candidates(prefixes, cross_volume):
        hashes = defaultdict(list)
        for file in same_prefix:
            digest = hash_file(file, None, issues)
            if digest is not None:
                hashes[digest].append(file)
        for digest, files in candidates(hashes, cross_volume):
            by_volume = defaultdict(list)
            size = files[0].size
            for file in sorted(files, key=lambda item: str(item.path)):
                by_volume[file.volume].append(str(file.path))
            groups.append({'sha256': digest, 'size_bytes': size,
                           'duplicate_bytes': (len(files) - 1) * size,
                           'paths_by_volume': dict(by_volume)})
    return groups


def report(config, count, skipped, issues, groups):
    totals = defaultdict(lambda: {'minimum_bytes': 0, 'maximum_bytes': 0})
    for group in groups:
        by_volume = group['paths_by_volume']
        size = group['size_bytes']
        for volume, paths in by_volume.items():
            minimum = (len(paths) - 1) * size
            maximum = len(paths) * size if len(by_volume) > 1 else minimum
            totals[volume]['minimum_bytes'] += minimum
            totals[volume]['maximum_bytes'] += maximum
    groups.sort(key=lambda group: (-group['duplicate_bytes'], group['sha256']))
    return {**config, 'files_considered': count,
            'duplicate_bytes': sum(group['duplicate_bytes'] for group in groups),
            'by_volume': dict(sorted(totals.items())), 'groups': groups,
            'skipped': skipped, 'issues': issues}


def checkpoint_key(files):
    metadata = sorted((str(file.path), file.volume, file.signature) for file in files)
    return hashlib.sha256(json.dumps(metadata).encode('ascii')).hexdigest()


def partial_report(path):
    # Read-only connection lets a second CLI inspect committed groups during a scan.
    uri = path.absolute().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as db:
        config = db.execute('SELECT config FROM scan').fetchone()
        if config is None:
            raise ValueError('Checkpoint has no scan configuration')
        groups = []
        for (saved,) in db.execute('SELECT result FROM comparisons'):
            groups.extend(json.loads(saved))
    return {**report(json.loads(config[0]), None, {}, [], groups), 'partial': True}


def audit(roots, minimum, cross_volume, progress=False, checkpoint=None):
    config = {'roots': [str(root) for root in roots], 'minimum_size_bytes': minimum,
              'cross_volume_only': cross_volume}
    if checkpoint is None:
        return scan(roots, config, progress, None, ())
    excluded = {os.path.normcase(str(checkpoint) + suffix)
                for suffix in ('', '-journal', '-wal', '-shm')}
    with closing(sqlite3.connect(str(checkpoint))) as db:
        with db:
            db.execute('CREATE TABLE IF NOT EXISTS scan (id INTEGER PRIMARY KEY, config TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS comparisons '
                       '(size INTEGER PRIMARY KEY, fingerprint TEXT, result TEXT)')
            db.execute('INSERT OR IGNORE INTO scan VALUES (1, ?)', (json.dumps(config),))
            existing = db.execute('SELECT config FROM scan WHERE id = 1').fetchone()[0]
            if json.loads(existing) != config:
                raise ValueError('Checkpoint options differ. Use the original options or a new file.')
        return scan(roots, config, progress, db, excluded)


def scan(roots, config, progress, db, excluded):
    issues = []
    skipped = dict.fromkeys(('links_or_offline', 'system_directories', 'hard_links'), 0)
    sizes = defaultdict(list)
    count = 0
    last_update = time.monotonic()
    if progress:
        print('Inventory: starting', file=sys.stderr, flush=True)
    files = inventory(roots, config['minimum_size_bytes'], issues, skipped, excluded)
    for count, file in enumerate(files, 1):
        sizes[file.size].append(file)
        if progress and time.monotonic() - last_update >= 5:
            print(f'Inventory: {count:,} eligible files found', file=sys.stderr, flush=True)
            last_update = time.monotonic()

    groups = []
    cross_volume = config['cross_volume_only']
    size_groups = list(candidates(sizes, cross_volume))
    total = len(size_groups)
    if db is not None:
        # Drop results whose candidate membership or metadata changed on disk.
        with db:
            for size, fingerprint in db.execute('SELECT size, fingerprint FROM comparisons').fetchall():
                files = sizes.get(size, [])
                if len(files) < 2 or fingerprint != checkpoint_key(files):
                    db.execute('DELETE FROM comparisons WHERE size = ?', (size,))
    if progress:
        print(f'Inventory complete: {count:,} eligible files', file=sys.stderr, flush=True)
        print(f'Comparison: 0/{total:,} groups checked', file=sys.stderr, flush=True)
        last_update = time.monotonic()
    for completed, (size, same_size) in enumerate(size_groups, 1):
        saved = None
        if db is not None:
            fingerprint = checkpoint_key(same_size)
            saved = db.execute('SELECT result FROM comparisons WHERE size = ? AND fingerprint = ?',
                               (size, fingerprint)).fetchone()
        if saved is not None:
            groups.extend(json.loads(saved[0]))
        else:
            issue_count = len(issues)
            found = compare(same_size, cross_volume, issues)
            groups.extend(found)
            if db is not None and len(issues) == issue_count:
                with db:
                    db.execute('INSERT OR REPLACE INTO comparisons VALUES (?, ?, ?)',
                               (size, fingerprint, json.dumps(found)))
        if progress and (completed == total or time.monotonic() - last_update >= 5):
            print(f'Comparison: {completed:,}/{total:,} groups checked ({completed / total:.0%})',
                  file=sys.stderr, flush=True)
            last_update = time.monotonic()
    return report(config, count, skipped, issues, groups)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', nargs='*', help='Directories or volume roots, e.g. C:/ D:/')
    parser.add_argument('--min-size', type=int, default=1, metavar='BYTES')
    parser.add_argument('--cross-volume-only', action='store_true')
    parser.add_argument('--progress', action='store_true', help='Show scan progress on stderr')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--checkpoint', type=Path, help='Save comparison results and reuse them on restart')
    mode.add_argument('--partial-report', type=Path, help='Read committed results from a checkpoint')
    args = parser.parse_args()
    if args.partial_report:
        if args.roots or args.cross_volume_only or args.min_size != 1 or args.progress:
            parser.error('--partial-report takes only a checkpoint path')
        try:
            print(json.dumps(partial_report(args.partial_report), indent=2))
        except (sqlite3.Error, ValueError) as error:
            parser.error(str(error))
        return 0
    if not args.roots:
        parser.error('At least one scan root is required')
    if args.min_size < 1:
        parser.error('--min-size must be at least 1')
    roots = [Path(os.path.abspath(root)) for root in args.roots]
    checkpoint = args.checkpoint.absolute() if args.checkpoint else None
    try:
        report = audit(roots, args.min_size, args.cross_volume_only, args.progress, checkpoint)
    except (sqlite3.Error, ValueError) as error:
        parser.error(str(error))
    except KeyboardInterrupt:
        if checkpoint is not None:
            print('Interrupted. Use --partial-report to read saved groups.', file=sys.stderr)
        return 130
    print(json.dumps(report, indent=2))
    return 1 if report['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
