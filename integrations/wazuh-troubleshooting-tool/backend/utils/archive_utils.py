"""
Helpers for reading a file out of a tar archive that might live on a slow
filesystem (e.g. a Vagrant/VirtualBox shared folder like /home/vagrant).

Extracting a single member directly from an archive on a slow shared
filesystem can take a very long time, because tar has to make many small
read/seek calls to walk the archive, and each one can carry real latency
on that kind of filesystem. Copying the whole archive to local disk once
with a single sequential read is much faster, then extracting from that
local copy is fast because it's on real disk.

Reusable by any future use case that needs to read something out of an
installer archive, a backup tarball, etc.
"""

import os
from executor import run_command


def extract_from_archive(archive_path, member_path, local_cache_dir="/tmp"):
    """
    Extract a single member from a tar archive and return its contents as
    text. The archive is copied to `local_cache_dir` once (skipped if a
    copy is already there) before extracting.
    """
    local_copy = os.path.join(local_cache_dir, os.path.basename(archive_path))

    run_command(f"[ -f {local_copy} ] || cp {archive_path} {local_copy}")

    return run_command(f"tar -axf {local_copy} {member_path} -O") or ""
