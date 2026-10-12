"""Versioned, bounded artifact transport. Never deserialize a model during installation.

The packaged catalog is the trust anchor. HTTPS URLs are resolved from an actual
published GitHub Release, never supplied by an inference request or guessed.
Administrator-controlled installation roots are required, as for the predictors.
"""

import gzip
import hashlib
import json
import os
import tarfile
import tempfile
from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

VERSION = "security-ai-artifacts-v1"
REPOSITORY = "whrjsdnr/ML_teamproject"
GROUPS = ("network-quality", "network-edge", "dns")
SELECTIONS = (*GROUPS, "network", "all")
BLOCK_SIZE = 1024 * 1024
MAX_METADATA = 1024 * 1024
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com"}


class ArtifactDistributionError(Exception):
    """Install/transport failure; does not produce a fallback model."""


class ArtifactVersionError(ArtifactDistributionError):
    """Unsupported bundle/model contract revision."""


class ArtifactIntegrityError(ArtifactDistributionError):
    """Missing, corrupt or unsafe bundle member."""


class ArtifactDownloadError(ArtifactDistributionError):
    """Published release missing or HTTPS transport failed."""


class ArtifactInstallConflict(ArtifactDistributionError):
    """Existing file differs; never overwrite it automatically."""


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(BLOCK_SIZE), b""):
            value.update(block)
    return value.hexdigest()


def _safe_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and 0 < len(name) <= 256
        and "\\" not in name
        and "\x00" not in name
        and not PurePosixPath(name).is_absolute()
        and not any(p in (".", "..", "") for p in name.split("/"))
    )


def catalog(version: str = VERSION) -> dict:
    if version != VERSION:
        raise ArtifactVersionError("Unsupported artifact release version")
    try:
        value = json.loads(files("security_ai").joinpath("artifact_catalog.json").read_bytes())
        if (
            value["schema_version"] != "security-ai-artifact-catalog-v1"
            or value["version"] != version
            or value["repository"] != REPOSITORY
            or value["release_tag"] != version
            or set(value["bundles"]) != set(GROUPS)
        ):
            raise ValueError("Invalid catalog identity")
        for group, asset in value["bundles"].items():
            if asset["filename"] != f"{version}-{group}.tar.gz":
                raise ValueError("Invalid archive name")
            for spec in [asset, *asset["files"].values()]:
                if (
                    type(spec["size_bytes"]) is not int
                    or not 0 < spec["size_bytes"] < 2 * 1024**3
                    or not isinstance(spec["sha256"], str)
                    or len(spec["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in spec["sha256"])
                ):
                    raise ValueError("Invalid pinned file metadata")
            if not 1 <= len(asset["files"]) <= 16 or not all(
                _safe_name(name) and name != "bundle.json" for name in asset["files"]
            ):
                raise ValueError("Invalid bundle members")
        return value
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise ArtifactIntegrityError("Invalid packaged artifact catalog") from error


def select(model: str) -> tuple[str, ...]:
    if model == "all":
        return GROUPS
    if model == "network":
        return GROUPS[:2]
    if model in GROUPS:
        return (model,)
    raise ArtifactVersionError("Unknown artifact selection")


def _manifest(version: str, group: str, spec: dict) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "security-ai-bundle-v1",
                "version": version,
                "group": group,
                "model_version": spec["model_version"],
                "feature_contract_version": spec["feature_contract_version"],
                "files": spec["files"],
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode()


def _regular_file(path: Path, root: Path) -> Path:
    # Reject links in every component below the administrator-selected root.
    relative = path.relative_to(root)
    current = root
    if root.is_symlink():
        raise ArtifactIntegrityError("Artifact root must not be a symlink")
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ArtifactIntegrityError("Artifact path contains a symlink")
    if not path.is_file():
        raise ArtifactIntegrityError("Required artifact file is missing")
    return path


def _verify_file(path: Path, spec: dict) -> None:
    if path.stat().st_size != spec["size_bytes"] or digest(path) != spec["sha256"]:
        raise ArtifactIntegrityError("Artifact size or SHA-256 mismatch")


def _expected(groups: Iterable[str], value: dict) -> dict:
    result = {}
    for group in groups:
        for name, spec in value["bundles"][group]["files"].items():
            if name in result and spec != result[name]:
                raise ArtifactIntegrityError("Conflicting required bundle metadata")
            result[name] = spec
    return result


def verify_install(root: Path, *, model: str = "all", version: str = VERSION) -> dict:
    value = catalog(version)
    root = Path(os.path.abspath(root))
    try:
        expected = _expected(select(model), value)
        for name, spec in expected.items():
            _verify_file(_regular_file(root / name, root), spec)
        return {
            "status": "PASS",
            "version": version,
            "model": model,
            "verified_files": len(expected),
        }
    except OSError as error:
        raise ArtifactIntegrityError("Cannot verify installed artifact files") from error


def _extract(archive: Path, stage: Path, group: str, value: dict) -> None:
    spec = value["bundles"][group]
    _verify_file(archive, spec)
    expected = spec["files"]
    seen = set()
    try:
        # No extractall, no links, no arbitrary path or unbounded member list.
        with tarfile.open(archive, mode="r|gz") as stream:
            for member in stream:
                if (
                    member.name in seen
                    or len(seen) >= len(expected) + 1
                    or not member.isfile()
                    or not _safe_name(member.name)
                    or member.pax_headers
                    or member.name not in {*expected, "bundle.json"}
                ):
                    raise ArtifactIntegrityError("Unsafe or unexpected archive member")
                seen.add(member.name)
                source = stream.extractfile(member)
                if source is None:
                    raise ArtifactIntegrityError("Archive member cannot be read")
                if member.name == "bundle.json":
                    manifest_bytes = _manifest(value["version"], group, spec)
                    if (
                        member.size != len(manifest_bytes)
                        or source.read(len(manifest_bytes) + 1) != manifest_bytes
                    ):
                        raise ArtifactVersionError("Archive bundle version/manifest mismatch")
                    continue
                entry = expected[member.name]
                if member.size != entry["size_bytes"]:
                    raise ArtifactIntegrityError("Archive member size mismatch")
                destination = stage / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                # Shared metadata across selected bundles must still be checked.
                temp = destination.with_name(destination.name + ".part")
                remaining = member.size
                with temp.open("xb") as target:
                    os.chmod(temp, 0o600)
                    while remaining:
                        block = source.read(min(BLOCK_SIZE, remaining))
                        if not block:
                            raise ArtifactIntegrityError("Truncated archive member")
                        target.write(block)
                        remaining -= len(block)
                    if source.read(1):
                        raise ArtifactIntegrityError("Oversized archive member")
                _verify_file(temp, entry)
                if destination.exists():
                    _verify_file(destination, entry)
                    temp.unlink()
                else:
                    temp.rename(destination)
        if seen != {*expected, "bundle.json"}:
            raise ArtifactIntegrityError("Required archive members are missing")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ArtifactIntegrityError("Cannot read verified archive") from error


def _target(root: Path, name: str) -> Path:
    current = root
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise ArtifactInstallConflict("Installation root is not a regular directory")
    for part in PurePosixPath(name).parts:
        current /= part
        if current.is_symlink():
            raise ArtifactInstallConflict("Installation path contains a symlink")
    if not current.resolve().is_relative_to(root.resolve()):
        raise ArtifactInstallConflict("Installation path escapes its root")
    return current


def install_local(
    bundle_dir: Path,
    root: Path,
    *,
    model: str = "all",
    version: str = VERSION,
) -> dict:
    """All selected archives/files verify before writing; identical files are reused.

    Atomic no-replace hardlinks publish files on the same filesystem. On failure,
    only files created by this invocation are removed. Trusted root ownership is
    required; this is not a multi-process snapshot transaction for model readers.
    """
    value = catalog(version)
    groups = select(model)
    expected = _expected(groups, value)
    root = Path(os.path.abspath(root))
    bundle_dir = Path(os.path.abspath(bundle_dir))
    if root.is_symlink():
        raise ArtifactInstallConflict("Installation root must not be a symlink")
    if not root.parent.is_dir():
        raise ArtifactInstallConflict("Installation parent directory must already exist")
    created_files = []
    created_dirs = []
    skipped = 0
    try:
        with tempfile.TemporaryDirectory(prefix=".security-ai-stage-", dir=root.parent) as temp:
            stage = Path(temp)
            for group in groups:
                archive = _regular_file(
                    bundle_dir / value["bundles"][group]["filename"], bundle_dir
                )
                _extract(archive, stage, group, value)
            for name, spec in expected.items():
                destination = _target(root, name)
                if destination.exists():
                    try:
                        _verify_file(destination, spec)
                    except (OSError, ArtifactIntegrityError) as error:
                        raise ArtifactInstallConflict(
                            "Existing artifact differs; refusing overwrite"
                        ) from error
            # Keep a ledger of new directories; never remove pre-existing ones.
            for name in expected:
                destination = _target(root, name)
                if destination.exists():
                    skipped += 1
                    continue
                missing = []
                parent = destination.parent
                while not parent.exists():
                    missing.append(parent)
                    parent = parent.parent
                for parent in reversed(missing):
                    try:
                        parent.mkdir(mode=0o700)
                        created_dirs.append(parent)
                    except FileExistsError:
                        if parent.is_symlink() or not parent.is_dir():
                            raise ArtifactInstallConflict(
                                "Installation directory changed"
                            ) from None
                _target(root, name)  # Recheck immediately before no-replace publish.
                inode = (stage / name).stat().st_ino
                os.link(stage / name, destination, follow_symlinks=False)
                created_files.append((destination, inode))
            verify_install(root, model=model, version=version)
        return {
            "status": "PASS",
            "version": version,
            "model": model,
            "installed_files": len(created_files),
            "reused_files": skipped,
        }
    except BaseException as error:
        for path, inode in reversed(created_files):
            if path.exists() and not path.is_symlink() and path.stat().st_ino == inode:
                path.unlink()
        for path in reversed(created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass  # Not empty: retain concurrent/user files.
        if isinstance(error, OSError):
            raise ArtifactInstallConflict(
                "Installation failed; created files rolled back"
            ) from error
        raise


def _https(url: str, hosts: set[str]) -> str:
    try:
        parsed = urlsplit(url)
        if (
            len(url) > 16384
            or parsed.scheme != "https"
            or parsed.hostname not in hosts
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.fragment
            or any(ord(c) < 32 or ord(c) == 127 for c in url)
        ):
            raise ValueError("Untrusted HTTPS URL")
    except ValueError as error:
        raise ArtifactDownloadError("URL is outside the trusted HTTPS hosts") from error
    return url


class _SafeRedirect(HTTPRedirectHandler):
    def __init__(self, hosts: set[str]) -> None:
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _https(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, hosts: set[str]):
    _https(url, hosts)
    opener = build_opener(_SafeRedirect(hosts))
    return opener.open(Request(url, headers={"User-Agent": "security-ai/0.1.0"}), timeout=30)


def resolve_release(value: dict, groups: Iterable[str]) -> dict[str, str]:
    """Obtain confirmed asset URLs from the fixed repository's actual public Release."""
    api = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{quote(value['release_tag'])}"
    try:
        with _open(api, {"api.github.com"}) as response:
            _https(response.geturl(), {"api.github.com"})
            raw = response.read(MAX_METADATA + 1)
        if len(raw) > MAX_METADATA:
            raise ArtifactDownloadError("Release metadata exceeds size limit")
        release = json.loads(raw)
        if release["tag_name"] != value["release_tag"] or release["draft"] or release["prerelease"]:
            raise ArtifactVersionError("Release is not the requested published stable version")
        assets = release["assets"]
        result = {}
        for group in groups:
            spec = value["bundles"][group]
            candidates = [a for a in assets if a["name"] == spec["filename"]]
            if len(candidates) != 1:
                raise ArtifactDownloadError("Required Release asset is missing or ambiguous")
            asset = candidates[0]
            if asset["state"] != "uploaded" or asset["size"] != spec["size_bytes"]:
                raise ArtifactIntegrityError(
                    "Published asset size/state differs from pinned catalog"
                )
            url = _https(asset["browser_download_url"], {"github.com"})
            parsed = urlsplit(url)
            expected = f"/{REPOSITORY}/releases/download/{value['release_tag']}/{spec['filename']}"
            if parsed.path != expected or parsed.query:
                raise ArtifactDownloadError(
                    "Release asset URL has an unexpected repository/version"
                )
            if asset.get("digest") not in (None, "sha256:" + spec["sha256"]):
                raise ArtifactIntegrityError("GitHub asset digest differs from pinned catalog")
            result[group] = url
        return result
    except ArtifactDistributionError:
        raise
    except HTTPError as error:
        raise ArtifactDownloadError(
            "Release unavailable or unauthorized; remote deployment BLOCKED"
        ) from error
    except (URLError, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        raise ArtifactDownloadError("Cannot resolve trusted Release assets") from error


def download_install(root: Path, *, model: str = "all", version: str = VERSION) -> dict:
    value = catalog(version)
    groups = select(model)
    urls = resolve_release(value, groups)
    try:
        # Downloads are disposable, not installed paths. Clean partial files on every failure.
        with tempfile.TemporaryDirectory(prefix="security-ai-download-") as temp:
            directory = Path(temp)
            for group in groups:
                spec = value["bundles"][group]
                target = directory / spec["filename"]
                total = 0
                with _open(urls[group], DOWNLOAD_HOSTS) as response, target.open("xb") as stream:
                    _https(response.geturl(), DOWNLOAD_HOSTS)
                    while block := response.read(BLOCK_SIZE):
                        total += len(block)
                        if total > spec["size_bytes"]:
                            raise ArtifactIntegrityError("Download exceeds pinned asset size")
                        stream.write(block)
                _verify_file(target, spec)
            return install_local(directory, root, model=model, version=version)
    except ArtifactDistributionError:
        raise
    except (URLError, OSError) as error:
        raise ArtifactDownloadError("Download failed; temporary files were removed") from error


def _build_archive(destination: Path, version: str, group: str, spec: dict, sources: dict) -> None:
    """Deterministic streaming tar/gzip; internal helper used to prepare reviewed assets."""
    from io import BytesIO

    with (
        destination.open("xb") as output,
        gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=output,
            mtime=0,
            compresslevel=9,
        ) as compressed,
        tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
    ):
        meta = _manifest(version, group, spec)
        info = tarfile.TarInfo("bundle.json")
        info.size, info.mode = len(meta), 0o600
        archive.addfile(info, BytesIO(meta))
        for name in sorted(spec["files"]):
            info = tarfile.TarInfo(name)
            info.size, info.mode = spec["files"][name]["size_bytes"], 0o600
            with sources[name].open("rb") as stream:
                archive.addfile(info, stream)


def create_bundles(
    network_root: Path,
    dns_root: Path,
    output: Path,
    *,
    model: str = "all",
    version: str = VERSION,
) -> dict:
    value = catalog(version)
    groups = select(model)
    roots = {"network": Path(os.path.abspath(network_root)), "dns": Path(os.path.abspath(dns_root))}
    sources = {}
    for name, spec in _expected(groups, value).items():
        if name.startswith("models/network/"):
            path = _regular_file(roots["network"] / name, roots["network"])
        elif name.startswith("dns/"):
            path = _regular_file(roots["dns"] / name.removeprefix("dns/"), roots["dns"])
        else:
            package, resource = (
                ("network_security_ai", "resources/" + name.rsplit("/", 1)[1])
                if name.startswith("metadata/network/")
                else ("dns_security_ai", name.rsplit("/", 1)[1])
            )
            if name == "metadata/network/artifact_manifest.json":
                resource = "artifact_manifest.json"
            path = Path(str(files(package).joinpath(resource)))
        _verify_file(path, spec)
        sources[name] = path
    output = Path(os.path.abspath(output))
    if output.is_symlink():
        raise ArtifactInstallConflict("Bundle output must not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    targets = [output / value["bundles"][g]["filename"] for g in groups]
    if any(p.exists() or p.is_symlink() for p in targets):
        raise ArtifactInstallConflict("Bundle output exists; refusing overwrite")
    published = []
    try:
        with tempfile.TemporaryDirectory(prefix=".bundle-stage-", dir=output) as temp:
            for group, target in zip(groups, targets, strict=True):
                spec = value["bundles"][group]
                staged = Path(temp) / target.name
                _build_archive(staged, version, group, spec, sources)
                _verify_file(staged, spec)
            for target in targets:
                staged = Path(temp) / target.name
                inode = staged.stat().st_ino
                os.link(staged, target)
                published.append((target, inode))
        return {"status": "PASS", "version": version, "bundles": [p.name for p, _ in published]}
    except BaseException:
        for path, inode in published:
            if path.exists() and not path.is_symlink() and path.stat().st_ino == inode:
                path.unlink()
        raise
