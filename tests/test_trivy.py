import subprocess

import pytest

from aegistrail.trivy import TrivyError, convert_trivy_json_to_sarif


def test_convert_trivy_json_to_sarif_uses_native_trivy_formatter(tmp_path, monkeypatch):
    source = tmp_path / "trivy-raw.json"
    source.write_text('{"SchemaVersion": 2, "Results": []}', encoding="utf-8")
    destination = tmp_path / "reports" / "results.sarif"
    calls = []

    monkeypatch.setattr("aegistrail.trivy.shutil.which", lambda _: "/usr/bin/trivy")

    def fake_run(command, check, capture_output, text, timeout):
        calls.append(command)
        output_path = command[command.index("--output") + 1]
        (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
        (tmp_path / output_path.split("/")[-2] / output_path.split("/")[-1]).write_text(
            '{"version":"2.1.0","runs":[]}', encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("aegistrail.trivy.subprocess.run", fake_run)

    result = convert_trivy_json_to_sarif(source, destination)

    assert result == destination
    assert result.is_file()
    assert calls[0][1:4] == ["convert", "--format", "sarif"]
    assert calls[0][-1] == str(source)


def test_convert_trivy_json_to_sarif_requires_input_file(tmp_path, monkeypatch):
    monkeypatch.setattr("aegistrail.trivy.shutil.which", lambda _: "/usr/bin/trivy")
    with pytest.raises(TrivyError, match="does not exist"):
        convert_trivy_json_to_sarif(tmp_path / "missing.json", tmp_path / "out.sarif")


def test_convert_trivy_json_to_sarif_reports_trivy_error(tmp_path, monkeypatch):
    source = tmp_path / "trivy-raw.json"
    source.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("aegistrail.trivy.shutil.which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(
        "aegistrail.trivy.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 2, stdout="", stderr="unsupported format"
        ),
    )
    with pytest.raises(TrivyError, match="unsupported format"):
        convert_trivy_json_to_sarif(source, tmp_path / "out.sarif")
