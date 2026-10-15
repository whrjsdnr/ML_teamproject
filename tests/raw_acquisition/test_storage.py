"""Only synthetic local bytes; no external download is performed by this suite."""

import bz2
import dataclasses
import hashlib
import io
import stat
import zipfile

import pytest

from ml.raw_acquisition.storage import (
    DownloadSpec,
    inspect_zip,
    iter_bzip2,
    save_response,
)

BODY = b"BZh-fixture-not-an-actual-corpus"
URL = "https://mcfp.felk.cvut.cz/publicDatasets/fixture.pcap.bz2"


def spec(**changes):
    return dataclasses.replace(
        DownloadSpec(URL, "fixture.pcap.bz2", len(BODY), 100, ("application/x-bzip2",)),
        **changes,
    )


def save(root, body=BODY, **changes):
    args = {
        "final_url": URL,
        "content_length": len(BODY),
        "content_type": "application/x-bzip2",
    } | changes
    return save_response(spec(), root, io.BytesIO(body), **args)


def test_bounded_bytes_local_sha_and_no_clobber(tmp_path):
    root = tmp_path / "private"
    r = save(root)
    assert r.sha256 == hashlib.sha256(BODY).hexdigest()
    assert not r.publisher_digest_verified and r.size_bytes == len(BODY)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / r.filename).stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        save(root)
    assert (root / r.filename).read_bytes() == BODY
    assert not list(root.glob(".download-*"))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"final_url": "https://example.org/fixture"},
        {"content_length": None},
        {"content_length": 1},
        {"content_type": "text/html"},
        {"content_type": None},
    ],
)
def test_transport_identity_and_headers(tmp_path, kwargs):
    with pytest.raises(ValueError):
        save(tmp_path / "private", **kwargs)


@pytest.mark.parametrize("body", [BODY[:-1], BODY + b"x", b"x" * len(BODY)])
def test_short_oversize_wrong_magic(tmp_path, body):
    root = tmp_path / "private"
    with pytest.raises(ValueError):
        save(root, body)
    assert not list(root.glob("*"))


def test_publisher_sha_mismatch_fails_closed(tmp_path):
    with pytest.raises(ValueError, match="DIGEST"):
        save_response(
            spec(publisher_sha256="0" * 64),
            tmp_path / "private",
            io.BytesIO(BODY),
            final_url=URL,
            content_length=len(BODY),
            content_type="application/x-bzip2",
        )


def test_missing_mime_requires_reviewed_flag_and_argus_signature(tmp_path):
    body = b"StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,Label\n"
    args = DownloadSpec(
        URL, "label.binetflow", len(body), 200, (), allow_missing_content_type=True
    )
    receipt = save_response(
        args,
        tmp_path / "private",
        io.BytesIO(body),
        final_url=URL,
        content_length=len(body),
        content_type=None,
    )
    assert receipt.content_type == "UNKNOWN"
    with pytest.raises(ValueError):
        save_response(
            dataclasses.replace(args, filename="wrong.binetflow"),
            tmp_path / "private",
            io.BytesIO(b"<html>" + b" " * 54),
            final_url=URL,
            content_length=len(body),
            content_type=None,
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://mcfp.felk.cvut.cz/x",
        "https://evil.test/x",
        "https://mcfp.felk.cvut.cz.evil.test/x",
        "https://user:secret@mcfp.felk.cvut.cz/x",
        "https://mcfp.felk.cvut.cz:444/x",
    ],
)
def test_no_external_url_or_credentials(url):
    with pytest.raises(ValueError):
        spec(url=url)


@pytest.mark.parametrize(
    "name", ["../a.pcap", "/a.pcap", "a\\b.pcap", "a.exe", "a..pcap"]
)
def test_download_paths(name):
    with pytest.raises(ValueError):
        spec(filename=name)


def test_private_storage_and_symlink(tmp_path):
    root = tmp_path / "public"
    root.mkdir(mode=0o755)
    with pytest.raises(ValueError):
        save(root)
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError):
        save(link)


def test_no_retry_after_transport_timeout(monkeypatch, tmp_path):
    from ml.raw_acquisition import storage

    calls = []

    class Opener:
        def open(self, *args, **kwargs):
            calls.append(1)
            raise TimeoutError("fixture timeout")

    monkeypatch.setattr(storage.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(TimeoutError):
        storage.fetch_reviewed_file(spec(), tmp_path / "private")
    assert calls == [1]


def archive(tmp_path, name="allowed/packet.pcap", data=b"fixture", mode=None):
    path = tmp_path / "test.zip"
    with zipfile.ZipFile(path, "w") as z:
        item = zipfile.ZipInfo(name)
        if mode is not None:
            item.external_attr = mode << 16
        z.writestr(item, data)
    return path


def test_zip_is_inspected_without_extraction(tmp_path):
    p = archive(tmp_path)
    result = inspect_zip(p, max_expanded_bytes=100)
    assert result == (("allowed/packet.pcap", hashlib.sha256(b"fixture").hexdigest()),)
    assert not (tmp_path / "allowed").exists()


@pytest.mark.parametrize(
    "name", ["../x.txt", "/abs.txt", "a\\x.txt", "C:/x.txt", "binary.exe"]
)
def test_zip_paths_and_executable(tmp_path, name):
    with pytest.raises(ValueError):
        inspect_zip(archive(tmp_path, name), max_expanded_bytes=100)


def test_zip_symlink_and_expansion_limit(tmp_path):
    with pytest.raises(ValueError):
        inspect_zip(
            archive(tmp_path, mode=stat.S_IFLNK | 0o777), max_expanded_bytes=100
        )
    with pytest.raises(ValueError):
        inspect_zip(archive(tmp_path, data=b"x" * 1000), max_expanded_bytes=100)


def test_bzip2_expansion_truncation_and_extra_member(tmp_path):
    p = tmp_path / "test.bz2"
    data = b"hello" * 100
    p.write_bytes(bz2.compress(data))
    assert b"".join(iter_bzip2(p, max_expanded_bytes=500)) == data
    with pytest.raises(ValueError):
        list(iter_bzip2(p, max_expanded_bytes=499))
    p.write_bytes(bz2.compress(data)[:-3])
    with pytest.raises(ValueError):
        list(iter_bzip2(p, max_expanded_bytes=500))
    p.write_bytes(bz2.compress(data) + bz2.compress(b"extra"))
    with pytest.raises(ValueError):
        list(iter_bzip2(p, max_expanded_bytes=500))


def test_download_deadline_and_cleanup(monkeypatch, tmp_path):
    from ml.raw_acquisition import storage

    ticks = iter([0, 301])
    monkeypatch.setattr(storage.time, "monotonic", lambda: next(ticks))
    root = tmp_path / "private"
    with pytest.raises(TimeoutError):
        save(root)
    assert not list(root.glob("*"))


def test_archive_directory_allocation_and_source_symlink_are_bounded(tmp_path):
    import struct

    p = archive(tmp_path)
    data = bytearray(p.read_bytes())
    offset = data.rfind(b"PK\x05\x06")
    struct.pack_into("<L", data, offset + 12, 65537)
    p.write_bytes(data)
    with pytest.raises(ValueError, match="DIRECTORY_LIMIT"):
        inspect_zip(p, max_expanded_bytes=100)
    link = tmp_path / "link.zip"
    link.symlink_to(p)
    with pytest.raises(ValueError):
        inspect_zip(link, max_expanded_bytes=100)
    with pytest.raises(ValueError):
        list(iter_bzip2(link, max_expanded_bytes=100))
