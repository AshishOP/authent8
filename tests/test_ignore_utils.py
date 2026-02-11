from pathlib import Path

from authent8.core.ignore_utils import load_ignore_patterns, should_ignore_path


def test_should_ignore_by_directory_segment(tmp_path: Path):
    project = tmp_path
    file_path = project / "node_modules" / "pkg" / "index.js"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("x", encoding="utf-8")

    assert should_ignore_path(file_path, project, ["node_modules"])


def test_should_ignore_by_glob(tmp_path: Path):
    project = tmp_path
    file_path = project / "assets" / "main.min.js"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("x", encoding="utf-8")

    assert should_ignore_path(file_path, project, ["*.min.js"])


def test_load_ignore_patterns_reads_a8ignore(tmp_path: Path):
    (tmp_path / ".a8ignore").write_text("custom_dir/\n# comment\nsecret.txt\n", encoding="utf-8")
    patterns = load_ignore_patterns(tmp_path)

    assert "custom_dir" in patterns
    assert "secret.txt" in patterns
