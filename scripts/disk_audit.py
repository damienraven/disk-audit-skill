"""Find exact file duplicates and report potential savings by volume."""

import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


@dataclass(frozen=True)
class File:
    path: Path
    size: int
    volume: str
    signature: tuple


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink)


def inventory(roots, minimum, issues, skipped):
    seen = set()
    identities = set()
    pending = list(reversed(roots))
    while pending:
        path = pending.pop()
        key = str(path)
        if key in seen:
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


def audit(roots, minimum, cross_volume):
    issues = []
    skipped = dict.fromkeys(('links_or_offline', 'system_directories', 'hard_links'), 0)
    sizes = defaultdict(list)
    for file in inventory(roots, minimum, issues, skipped):
        sizes[file.size].append(file)

    groups = []
    totals = defaultdict(lambda: {'minimum_bytes': 0, 'maximum_bytes': 0})
    for _, same_size in candidates(sizes, cross_volume):
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
                for volume, paths in by_volume.items():
                    minimum_bytes = (len(paths) - 1) * size
                    maximum_bytes = len(paths) * size if len(by_volume) > 1 else minimum_bytes
                    totals[volume]['minimum_bytes'] += minimum_bytes
                    totals[volume]['maximum_bytes'] += maximum_bytes
                groups.append({'sha256': digest, 'size_bytes': size,
                               'duplicate_bytes': (len(files) - 1) * size,
                               'paths_by_volume': dict(by_volume)})
    groups.sort(key=lambda group: (-group['duplicate_bytes'], group['sha256']))
    return {'roots': [str(root) for root in roots], 'minimum_size_bytes': minimum,
            'cross_volume_only': cross_volume, 'files_considered': sum(map(len, sizes.values())),
            'duplicate_bytes': sum(group['duplicate_bytes'] for group in groups),
            'by_volume': dict(sorted(totals.items())), 'groups': groups,
            'skipped': skipped, 'issues': issues}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', nargs='+', help='Directories or volume roots, e.g. C:/ D:/')
    parser.add_argument('--min-size', type=int, default=1, metavar='BYTES')
    parser.add_argument('--cross-volume-only', action='store_true')
    args = parser.parse_args()
    if args.min_size < 1:
        parser.error('--min-size must be at least 1')
    roots = [Path(os.path.abspath(root)) for root in args.roots]
    report = audit(roots, args.min_size, args.cross_volume_only)
    print(json.dumps(report, indent=2))
    return 1 if report['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
