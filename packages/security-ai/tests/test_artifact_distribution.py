import gzip
import hashlib
import io
import json
import tarfile
from copy import deepcopy
from pathlib import Path
from urllib.error import URLError

import pytest

from security_ai import artifacts as a


def file_spec(raw):
    return {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    directory = tmp_path / "bundles"
    directory.mkdir()
    sources = {}
    content = {
        "dns/model/dnn_int8.tflite": b"synthetic model bytes",
        "dns/preprocessor/scaler.joblib": b"synthetic scaler bytes",
        "metadata/dns/feature_contract.json": b'{"version":"test"}',
    }
    spec = {
        "model_version": "test-model-v1",
        "feature_contract_version": "test-feature-v1",
        "files": {n: file_spec(b) for n, b in content.items()},
        "filename": f"{a.VERSION}-dns.tar.gz",
    }
    for i, (name, raw) in enumerate(content.items()):
        p = tmp_path / f"source-{i}"
        p.write_bytes(raw)
        sources[name] = p
    archive = directory / spec["filename"]
    a._build_archive(archive, a.VERSION, "dns", spec, sources)
    spec.update(file_spec(archive.read_bytes()))
    value = {
        "version": a.VERSION,
        "release_tag": a.VERSION,
        "bundles": {"dns": spec},
        "repository": a.REPOSITORY,
    }

    def catalog(version=a.VERSION):
        if version != a.VERSION:
            raise a.ArtifactVersionError("version")
        return deepcopy(value)

    monkeypatch.setattr(a, "catalog", catalog)
    return directory, tmp_path / "installed", content, value


def test_install_verify_and_idempotent_reuse(bundle):
    directory, root, content, _ = bundle
    result = a.install_local(directory, root, model="dns")
    assert result["installed_files"] == 3
    stats = {name: (root / name).stat().st_ino for name in content}
    assert a.verify_install(root, model="dns")["verified_files"] == 3
    result = a.install_local(directory, root, model="dns")
    assert result["installed_files"] == 0 and result["reused_files"] == 3
    for name, raw in content.items():
        assert (root / name).read_bytes() == raw
        assert (root / name).stat().st_ino == stats[name]


def test_existing_different_artifact_never_overwritten(bundle):
    directory, root, _, _ = bundle
    path = root / "dns/model/dnn_int8.tflite"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"user artifact")
    with pytest.raises(a.ArtifactInstallConflict):
        a.install_local(directory, root, model="dns")
    assert path.read_bytes() == b"user artifact"
    assert not (root / "dns/preprocessor/scaler.joblib").exists()


def test_missing_and_corrupt_archive_no_partial_install(bundle):
    directory, root, _, value = bundle
    archive = directory / value["bundles"]["dns"]["filename"]
    archive.unlink()
    with pytest.raises(a.ArtifactIntegrityError):
        a.install_local(directory, root, model="dns")
    archive.write_bytes(b"corrupt")
    with pytest.raises(a.ArtifactIntegrityError):
        a.install_local(directory, root, model="dns")
    assert not root.exists()
    assert not list(root.parent.glob(".security-ai-stage-*"))


def test_installed_missing_and_corrupt_file(bundle):
    directory, root, _, _ = bundle
    with pytest.raises(a.ArtifactIntegrityError):
        a.verify_install(root, model="dns")
    a.install_local(directory, root, model="dns")
    (root / "dns/model/dnn_int8.tflite").write_bytes(b"corrupt")
    with pytest.raises(a.ArtifactIntegrityError):
        a.verify_install(root, model="dns")


def test_wrong_version_rejected_before_io(bundle):
    directory, root, _, _ = bundle
    with pytest.raises(a.ArtifactVersionError):
        a.install_local(directory, root, model="dns", version="another-version")
    assert not root.exists()


def rewrite_archive(bundle, mutate):
    directory, _, content, value = bundle
    spec = value["bundles"]["dns"]
    members = [("bundle.json", a._manifest(a.VERSION, "dns", spec), None)]
    members += [(name, raw, None) for name, raw in content.items()]
    members = mutate(members)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw, linktype in members:
                info = tarfile.TarInfo(name)
                if linktype is not None:
                    info.type, info.linkname = linktype, "../../escape"
                    archive.addfile(info)
                else:
                    info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))
    raw = buffer.getvalue()
    (directory / spec["filename"]).write_bytes(raw)
    spec.update(file_spec(raw))  # Tests archive safety even if transport bytes are trusted.


@pytest.mark.parametrize(
    "attack",
    [
        "parent",
        "absolute",
        "backslash",
        "symlink",
        "hardlink",
        "duplicate",
        "extra",
        "missing",
        "bad-content",
        "bad-version",
    ],
)
def test_unsafe_archive_rejected_and_stage_cleaned(bundle, attack):
    directory, root, _, _ = bundle

    def mutate(members):
        if attack in ("parent", "absolute", "backslash"):
            name = {"parent": "../escape", "absolute": "/tmp/escape", "backslash": "..\\escape"}[
                attack
            ]
            return [*members, (name, b"x", None)]
        if attack in ("symlink", "hardlink"):
            kind = tarfile.SYMTYPE if attack == "symlink" else tarfile.LNKTYPE
            return [members[0], (members[1][0], b"", kind), *members[2:]]
        if attack == "duplicate":
            return [*members, members[1]]
        if attack == "extra":
            return [*members, ("extra", b"x", None)]
        if attack == "missing":
            return members[:-1]
        if attack == "bad-content":
            return [members[0], (members[1][0], b"x" * len(members[1][1]), None), *members[2:]]
        return [
            ("bundle.json", members[0][1].replace(a.VERSION.encode(), b"wrong-version"), None),
            *members[1:],
        ]

    rewrite_archive(bundle, mutate)
    with pytest.raises(a.ArtifactDistributionError):
        a.install_local(directory, root, model="dns")
    assert not root.exists()
    assert not (root.parent / "escape").exists()
    assert not list(root.parent.glob(".security-ai-stage-*"))


def test_existing_symlink_rejected(bundle):
    directory, root, _, _ = bundle
    outside = root.parent / "outside"
    outside.mkdir()
    root.mkdir()
    (root / "dns").symlink_to(outside, target_is_directory=True)
    with pytest.raises(a.ArtifactInstallConflict):
        a.install_local(directory, root, model="dns")
    assert not list(outside.iterdir())


def test_mid_install_failure_rolls_back_only_created_files(bundle, monkeypatch):
    directory, root, _, _ = bundle
    root.mkdir()
    user_file = root / "user-file"
    user_file.write_bytes(b"preserve")
    original = a.os.link
    count = 0

    def fail_second(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("disk failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(a.os, "link", fail_second)
    with pytest.raises(a.ArtifactInstallConflict):
        a.install_local(directory, root, model="dns")
    assert user_file.read_bytes() == b"preserve"
    assert list(root.iterdir()) == [user_file]


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/file",
        "https://evil.example/file",
        "https://github.com.evil.example/file",
        "https://user:pass@github.com/file",
        "https://github.com:444/file",
        "file:///tmp/file",
        "https://github.com/file#fragment",
        "https://127.0.0.1/file",
        "https://github.com/file\n",
    ],
)
def test_untrusted_https_and_redirect_rejected(url):
    with pytest.raises(a.ArtifactDownloadError):
        a._https(url, a.DOWNLOAD_HOSTS)
    with pytest.raises(a.ArtifactDownloadError):
        a._SafeRedirect(a.DOWNLOAD_HOSTS).redirect_request(None, None, 302, "", {}, url)


class Response(io.BytesIO):
    def __init__(self, raw, url):
        super().__init__(raw)
        self.url = url

    def geturl(self):
        return self.url


def release_metadata(value):
    spec = value["bundles"]["dns"]
    return {
        "tag_name": a.VERSION,
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": spec["filename"],
                "state": "uploaded",
                "size": spec["size_bytes"],
                "browser_download_url": f"https://github.com/{a.REPOSITORY}/releases/download/"
                f"{a.VERSION}/{spec['filename']}",
                "digest": "sha256:" + spec["sha256"],
            }
        ],
    }


def test_release_urls_resolved_from_actual_response(bundle, monkeypatch):
    _, _, _, value = bundle
    meta = release_metadata(value)
    monkeypatch.setattr(a, "_open", lambda url, hosts: Response(json.dumps(meta).encode(), url))
    assert a.resolve_release(value, ["dns"])["dns"] == meta["assets"][0]["browser_download_url"]


@pytest.mark.parametrize("bad", ["draft", "version", "missing", "digest", "url", "size"])
def test_wrong_release_assets_fail_closed(bundle, monkeypatch, bad):
    _, _, _, value = bundle
    meta = release_metadata(value)
    if bad == "draft":
        meta["draft"] = True
    elif bad == "version":
        meta["tag_name"] = "other"
    elif bad == "missing":
        meta["assets"] = []
    else:
        field, invalid = {
            "digest": ("digest", "sha256:" + "0" * 64),
            "url": ("browser_download_url", "https://evil.example/asset"),
            "size": ("size", 1),
        }[bad]
        meta["assets"][0][field] = invalid
    monkeypatch.setattr(a, "_open", lambda url, hosts: Response(json.dumps(meta).encode(), url))
    with pytest.raises(a.ArtifactDistributionError):
        a.resolve_release(value, ["dns"])


@pytest.mark.parametrize("failure", [None, "network", "checksum", "oversized", "truncated"])
def test_download_install_and_failure_cleanup(bundle, monkeypatch, failure):
    directory, root, _, value = bundle
    meta = release_metadata(value)
    raw = (directory / value["bundles"]["dns"]["filename"]).read_bytes()
    if failure == "checksum":
        raw = b"x" * len(raw)
    elif failure == "oversized":
        raw += b"x"
    elif failure == "truncated":
        raw = raw[:-1]
    downloaded_paths = []
    original_temp = a.tempfile.TemporaryDirectory

    def track_temp(*args, **kwargs):
        obj = original_temp(*args, **kwargs)
        downloaded_paths.append(Path(obj.name))
        return obj

    def open_response(url, hosts):
        if "api.github.com" in hosts:
            return Response(json.dumps(meta).encode(), url)
        if failure == "network":
            raise URLError("failure")
        return Response(raw, url)

    monkeypatch.setattr(a.tempfile, "TemporaryDirectory", track_temp)
    monkeypatch.setattr(a, "_open", open_response)
    if failure:
        with pytest.raises(a.ArtifactDistributionError):
            a.download_install(root, model="dns")
        assert not root.exists()
    else:
        assert a.download_install(root, model="dns")["installed_files"] == 3
    assert all(not p.exists() for p in downloaded_paths)


def test_selection_and_packaged_catalog():
    assert a.select("network") == ("network-quality", "network-edge")
    assert a.select("all") == a.GROUPS
    value = a.catalog()
    assert value["repository"] == a.REPOSITORY
    assert set(value["bundles"]) == set(a.GROUPS)
    with pytest.raises(a.ArtifactVersionError):
        a.catalog("wrong-version")


def test_builder_is_reproducible_and_does_not_overwrite(bundle, monkeypatch):
    directory, root, content, value = bundle
    dns_root = root.parent / "dns-source"
    resources = root.parent / "resources"
    resources.mkdir()
    for name, raw in content.items():
        path = (
            dns_root / name.removeprefix("dns/")
            if name.startswith("dns/")
            else resources / name.rsplit("/", 1)[1]
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    monkeypatch.setattr(a, "files", lambda _: resources)
    output = root.parent / "built-bundles"
    result = a.create_bundles(root.parent / "unused-network", dns_root, output, model="dns")
    filename = value["bundles"]["dns"]["filename"]
    assert result["bundles"] == [filename]
    assert (output / filename).read_bytes() == (directory / filename).read_bytes()
    before = (output / filename).stat().st_ino
    with pytest.raises(a.ArtifactInstallConflict):
        a.create_bundles(root.parent / "unused-network", dns_root, output, model="dns")
    assert (output / filename).stat().st_ino == before
