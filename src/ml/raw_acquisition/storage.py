"""Bounded reviewed-file acquisition; never invoked by status/manifest queries."""

import hashlib
import os
import re
import stat
import struct
import tempfile
import time
import urllib.request
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlsplit

HOSTS = frozenset(
    {"mcfp.felk.cvut.cz", "cse-cic-ids2018.s3.ca-central-1.amazonaws.com", "zenodo.org"}
)


@dataclass(frozen=True)
class DownloadSpec:
    url: str
    filename: str
    expected_bytes: int
    max_bytes: int
    content_types: tuple[str, ...]
    timeout_seconds: int = 300
    publisher_sha256: str | None = None
    allow_missing_content_type: bool = False

    def __post_init__(self):
        url = urlsplit(self.url)
        if (
            url.scheme != "https"
            or url.hostname not in HOSTS
            or url.username
            or url.password
            or url.fragment
            or url.port not in (None, 443)
        ):
            raise ValueError("UNREVIEWED_SOURCE_URL")
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.filename)
            or ".." in self.filename
        ):
            raise ValueError("INVALID_DOWNLOAD_NAME")
        if not self.filename.endswith(
            (".pcap", ".bz2", ".zip", ".csv", ".json", ".binetflow")
        ):
            raise ValueError("UNSUPPORTED_RAW_FORMAT")
        if (
            type(self.expected_bytes) is not int
            or type(self.max_bytes) is not int
            or not 0 < self.expected_bytes <= self.max_bytes <= 8 * 1024**3
        ):
            raise ValueError("DOWNLOAD_SIZE_LIMIT")
        if (
            type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 300
        ):
            raise ValueError("DOWNLOAD_TIMEOUT_LIMIT")
        if self.publisher_sha256 is not None and not re.fullmatch(
            "[a-f0-9]{64}", self.publisher_sha256
        ):
            raise ValueError("INVALID_PUBLISHER_DIGEST")


@dataclass(frozen=True)
class FileReceipt:
    filename: str
    size_bytes: int
    sha256: str
    content_type: str
    publisher_digest_verified: bool


def private_directory(path: Path) -> Path:
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("SYMLINK_STORAGE_DENIED")
    if not path.exists():
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    info = path.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("PRIVATE_STORAGE_REQUIRED")
    return path


def _prefix_valid(name: str, prefix: bytes) -> bool:
    if name.endswith(".bz2"):
        return prefix.startswith(b"BZh")
    if name.endswith(".zip"):
        return prefix.startswith(b"PK\x03\x04")
    if name.endswith(".pcap"):
        return prefix[:4] in (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        )
    if name.endswith(".json"):
        return prefix.lstrip()[:1] in (b"[", b"{")
    try:
        header = set(prefix.split(b"\n", 1)[0].decode("ascii").strip().split(","))
    except UnicodeDecodeError:
        return False
    return {
        "StartTime",
        "Dur",
        "Proto",
        "SrcAddr",
        "Sport",
        "DstAddr",
        "Dport",
        "Label",
    } <= header


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("DOWNLOAD_REDIRECT_DENIED")


def save_response(
    spec: DownloadSpec,
    directory: Path,
    response: BinaryIO,
    *,
    final_url: str,
    content_length: int | None,
    content_type: str | None,
) -> FileReceipt:
    """A response must belong to the exact human-reviewed URL; no implicit retries.

    Missing MIME is UNKNOWN, permitted only when explicitly reviewed and an independent
    format prefix matches. This receipt proves local bytes, not label authority.
    """
    if final_url != spec.url:
        raise ValueError("SOURCE_REDIRECT_MISMATCH")
    media = content_type.split(";", 1)[0].strip().lower() if content_type else None
    if media not in spec.content_types and not (
        media is None and spec.allow_missing_content_type
    ):
        raise ValueError("CONTENT_TYPE_MISMATCH")
    if content_length is None or content_length != spec.expected_bytes:
        raise ValueError("CONTENT_LENGTH_MISMATCH")
    root = private_directory(directory)
    target = root / spec.filename
    if target.exists() or target.is_symlink():
        raise FileExistsError("DOWNLOAD_ALREADY_EXISTS")
    handle, temporary = tempfile.mkstemp(prefix=".download-", dir=root)
    staging = Path(temporary)
    total = 0
    sha = hashlib.sha256()
    prefix = b""
    started = time.monotonic()
    try:
        with os.fdopen(handle, "wb") as out:
            while True:
                if time.monotonic() - started > spec.timeout_seconds:
                    raise TimeoutError("DOWNLOAD_DEADLINE")
                block = response.read(min(65536, spec.max_bytes - total + 1))
                if not block:
                    break
                total += len(block)
                if total > spec.max_bytes or total > spec.expected_bytes:
                    raise ValueError("DOWNLOAD_SIZE_LIMIT")
                if len(prefix) < 1024:
                    prefix = (prefix + block)[:1024]
                sha.update(block)
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        if total != spec.expected_bytes or not _prefix_valid(spec.filename, prefix):
            raise ValueError("RAW_FORMAT_OR_TRUNCATION")
        checksum = sha.hexdigest()
        if spec.publisher_sha256 and checksum != spec.publisher_sha256:
            raise ValueError("DOWNLOAD_DIGEST_MISMATCH")
        os.link(
            staging, target
        )  # Atomic no-clobber publication, never replace existing data.
        return FileReceipt(
            spec.filename,
            total,
            checksum,
            media or "UNKNOWN",
            spec.publisher_sha256 is not None,
        )
    finally:
        staging.unlink(missing_ok=True)


def fetch_reviewed_file(spec: DownloadSpec, directory: Path) -> FileReceipt:
    """Call only after explicit approval of this exact file/size/destination plan."""
    request = urllib.request.Request(
        spec.url,
        headers={
            "User-Agent": "SOC-Approved-Dataset-Acquisition/1.0",
            "Accept-Encoding": "identity",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=min(10, spec.timeout_seconds)) as response:
        if response.status != 200:
            raise ValueError("DOWNLOAD_HTTP_STATUS")
        size = response.headers.get("Content-Length")
        return save_response(
            spec,
            directory,
            response,
            final_url=response.url,
            content_length=int(size) if size is not None else None,
            content_type=response.headers.get("Content-Type"),
        )


def inspect_zip(
    path: Path, *, max_expanded_bytes: int, max_members: int = 64
) -> tuple[tuple[str, str], ...]:
    """Validate and stream-hash members. Extract nothing and execute nothing."""
    if not 1 <= max_expanded_bytes <= 512 * 1024**2 or not 1 <= max_members <= 64:
        raise ValueError("ARCHIVE_LIMIT")
    if path.is_symlink() or not path.is_file():
        raise ValueError("REGULAR_ARCHIVE_REQUIRED")
    size = path.stat().st_size
    if size > 256 * 1024**2:
        raise ValueError("ARCHIVE_COMPRESSED_LIMIT")
    # Bound central-directory allocation before ZipFile reads untrusted metadata.
    with path.open("rb") as raw:
        raw.seek(max(0, size - 65557))
        tail = raw.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError("ARCHIVE_DIRECTORY_MISSING")
    (
        _,
        disk,
        central_disk,
        disk_entries,
        entries,
        directory_bytes,
        directory_offset,
        comment,
    ) = struct.unpack("<4s4H2LH", tail[offset : offset + 22])
    if (
        disk
        or central_disk
        or disk_entries != entries
        or entries > max_members
        or directory_bytes > 65536
        or directory_offset + directory_bytes > size - 22
        or offset + 22 + comment != len(tail)
    ):
        raise ValueError("ARCHIVE_DIRECTORY_LIMIT")
    receipts = []
    seen = set()
    total = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > max_members:
            raise ValueError("ARCHIVE_MEMBER_LIMIT")
        for entry in entries:
            name = entry.filename
            p = PurePosixPath(name)
            mode = entry.external_attr >> 16
            if (
                p.is_absolute()
                or "\\" in name
                or ".." in p.parts
                or ":" in name
                or "\x00" in name
                or name in seen
            ):
                raise ValueError("ARCHIVE_PATH_DENIED")
            seen.add(name)
            if (
                stat.S_ISLNK(mode)
                or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))
                or entry.flag_bits & 1
            ):
                raise ValueError("ARCHIVE_SPECIAL_FILE_DENIED")
            if entry.is_dir():
                continue
            if not name.endswith((".pcap", ".csv", ".txt", ".json", ".binetflow")):
                raise ValueError("ARCHIVE_MEMBER_TYPE_DENIED")
            total += entry.file_size
            if total > max_expanded_bytes:
                raise ValueError("ARCHIVE_EXPANSION_LIMIT")
            sha = hashlib.sha256()
            actual = 0
            with archive.open(entry) as stream:
                while block := stream.read(min(65536, entry.file_size - actual + 1)):
                    actual += len(block)
                    if actual > entry.file_size:
                        raise ValueError("ARCHIVE_SIZE_MISMATCH")
                    sha.update(block)
            if actual != entry.file_size:
                raise ValueError("ARCHIVE_SIZE_MISMATCH")
            receipts.append((name, sha.hexdigest()))
    return tuple(receipts)


def iter_bzip2(path: Path, *, max_expanded_bytes: int) -> Iterator[bytes]:
    """Yield bounded decoded blocks, without writing or executing archive members."""
    import bz2

    if not 1 <= max_expanded_bytes <= 512 * 1024**2:
        raise ValueError("ARCHIVE_EXPANSION_LIMIT")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024**2:
        raise ValueError("REGULAR_BOUNDED_ARCHIVE_REQUIRED")
    decoder = bz2.BZ2Decompressor()
    total = 0
    compressed = 0
    with path.open("rb") as stream:
        while not decoder.eof:
            data = stream.read(65536) if decoder.needs_input else b""
            compressed += len(data)
            if compressed > 256 * 1024**2:
                raise ValueError("ARCHIVE_COMPRESSED_LIMIT")
            if decoder.needs_input and not data:
                raise ValueError("BZIP2_TRUNCATED")
            block = decoder.decompress(
                data, max_length=min(65536, max_expanded_bytes - total + 1)
            )
            total += len(block)
            if total > max_expanded_bytes:
                raise ValueError("ARCHIVE_EXPANSION_LIMIT")
            if block:
                yield block
        if decoder.unused_data or stream.read(1):
            raise ValueError("BZIP2_TRAILING_OR_CONCATENATED_DATA")
