import io

import pytest

from ml.iot23.acquire import bounded_transfer
from ml.raw_acquisition.storage import DownloadSpec, save_response

URL = "https://mcfp.felk.cvut.cz/publicDatasets/example/conn.log.labeled"
HEADER = b"#separator \\x09\n#fields\tts\tuid\n#types\ttime\tstring\n"


def spec(size=None, **kwargs):
    size = len(HEADER) if size is None else size
    return DownloadSpec(URL, "conn.log.labeled", size, size, ("text/plain",), **kwargs)


def save(tmp_path, data=HEADER, **kwargs):
    return save_response(
        spec(),
        tmp_path / "private",
        io.BytesIO(data),
        final_url=URL,
        content_length=len(HEADER),
        content_type="text/plain",
        **kwargs,
    )


def test_zeek_prefix_sha_no_clobber(tmp_path):
    import hashlib

    receipt = save(tmp_path)
    assert receipt.sha256 == hashlib.sha256(HEADER).hexdigest()
    assert receipt.publisher_digest_verified is False
    with pytest.raises(FileExistsError):
        save(tmp_path)


@pytest.mark.parametrize("data", [b"x" * len(HEADER), HEADER[:-1], HEADER + b"x"])
def test_invalid_format_truncation_budget_cleanup(tmp_path, data):
    with pytest.raises(ValueError):
        save(tmp_path, data)
    assert list((tmp_path / "private").iterdir()) == []


def test_redirect_missing_mime_and_name(tmp_path):
    with pytest.raises(ValueError, match="REDIRECT"):
        save_response(
            spec(),
            tmp_path,
            io.BytesIO(HEADER),
            final_url=URL + "x",
            content_length=len(HEADER),
            content_type=None,
        )
    with pytest.raises(ValueError, match="CONTENT_TYPE"):
        save_response(
            spec(),
            tmp_path,
            io.BytesIO(HEADER),
            final_url=URL,
            content_length=len(HEADER),
            content_type=None,
        )
    with pytest.raises(ValueError, match="UNSUPPORTED"):
        DownloadSpec(URL, "other.log.labeled", 2, 2, ())


def test_existing_directory_does_not_start_child(tmp_path):
    target = tmp_path / "private"
    target.mkdir(mode=0o700)
    (target / "owned").write_text("keep")
    with pytest.raises(FileExistsError):
        bounded_transfer(spec(), target)
    assert (target / "owned").read_text() == "keep"


def test_hard_timeout_terminates_owned_child_no_retry(tmp_path, monkeypatch):
    import ml.iot23.acquire as module

    events = []

    class Pipe:
        def close(self):
            events.append("close")

    class Child:
        exitcode = None
        running = True

        def start(self):
            events.append("start")

        def join(self, timeout=None):
            events.append(("join", timeout))

        def is_alive(self):
            return self.running

        def terminate(self):
            events.append("terminate")
            self.running = False

    class Context:
        def Pipe(self, duplex=False):
            return Pipe(), Pipe()

        def Process(self, **kwargs):
            return Child()

    monkeypatch.setattr(module.multiprocessing, "get_context", lambda mode: Context())
    with pytest.raises(TimeoutError, match="WATCHDOG"):
        bounded_transfer(spec(), tmp_path / "private")
    assert events.count("start") == events.count("terminate") == 1
    assert any(
        isinstance(e, tuple) and e[0] == "join" and 0 < e[1] <= 300 for e in events
    )


def test_no_overwrite_and_symlink_storage(tmp_path):
    target = tmp_path / "real"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="SYMLINK"):
        save_response(
            spec(),
            link,
            io.BytesIO(HEADER),
            final_url=URL,
            content_length=len(HEADER),
            content_type="text/plain",
        )


def test_repeated_cli_does_not_retry_or_open_network(tmp_path, monkeypatch):
    import json
    import urllib.request
    from pathlib import Path

    from ml.iot23.acquire import acquire

    plan = json.loads(
        (
            Path(__file__).parents[2] / "docs/network-training-download-plan.json"
        ).read_text()
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/network-training-download-plan.json").write_text(json.dumps(plan))
    (tmp_path / plan["storage_directory"]).mkdir(parents=True)

    def denied(*args, **kwargs):
        pytest.fail("No duplicate network request permitted")

    monkeypatch.setattr(urllib.request, "build_opener", denied)
    with pytest.raises(FileExistsError, match="NO_AUTOMATIC_RETRY"):
        acquire(tmp_path)
