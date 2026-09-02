"""Skill collection helper tests."""

from pathlib import Path

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.ides._skill_utils import (
    MAX_SKILL_FILE_BYTES,
    MAX_SKILLS_PER_ROOT,
    walk_skill_dirs,
)

_BODY = '---\nname: dummy-skill\ndescription: Dummy.\n---\n\nDo the dummy thing.\n'


def test_walk_skill_dirs_missing_root_returns_empty() -> None:
    assert walk_skill_dirs(Path('/dummy/does-not-exist')) == []


def test_walk_skill_dirs_collects_path_and_content(fs: FakeFilesystem) -> None:
    root = Path('/dummy/skills')
    fs.create_file(root / 'dummy-skill' / 'SKILL.md', contents=_BODY)

    skills = walk_skill_dirs(root)

    assert skills == [{'path': str(root / 'dummy-skill' / 'SKILL.md'), 'content': _BODY}]


def test_walk_skill_dirs_sorted_by_path(fs: FakeFilesystem) -> None:
    """The session-context digest hashes the whole payload, so ordering has to be stable."""
    root = Path('/dummy/skills')
    for name in ('charlie', 'alpha', 'bravo'):
        fs.create_file(root / name / 'SKILL.md', contents=_BODY)

    paths = [skill['path'] for skill in walk_skill_dirs(root)]

    assert paths == sorted(paths)
    assert [Path(p).parent.name for p in paths] == ['alpha', 'bravo', 'charlie']


def test_walk_skill_dirs_ignores_dirs_without_skill_file(fs: FakeFilesystem) -> None:
    root = Path('/dummy/skills')
    fs.create_file(root / 'real-skill' / 'SKILL.md', contents=_BODY)
    fs.create_file(root / 'not-a-skill' / 'README.md', contents='nothing here')

    skills = walk_skill_dirs(root)

    assert [Path(s['path']).parent.name for s in skills] == ['real-skill']


def test_walk_skill_dirs_ignores_loose_files_in_root(fs: FakeFilesystem) -> None:
    """Only one directory level is scanned: a skill is always a directory holding a SKILL.md."""
    root = Path('/dummy/skills')
    fs.create_file(root / 'SKILL.md', contents=_BODY)

    assert walk_skill_dirs(root) == []


def test_walk_skill_dirs_does_not_recurse(fs: FakeFilesystem) -> None:
    """A skill directory may hold nested references; its SKILL.md sits at the top of it."""
    root = Path('/dummy/skills')
    fs.create_file(root / 'dummy-skill' / 'SKILL.md', contents=_BODY)
    fs.create_file(root / 'dummy-skill' / 'references' / 'SKILL.md', contents=_BODY)

    skills = walk_skill_dirs(root)

    assert len(skills) == 1
    assert skills[0]['path'] == str(root / 'dummy-skill' / 'SKILL.md')


def test_walk_skill_dirs_skips_empty_skill_file(fs: FakeFilesystem) -> None:
    root = Path('/dummy/skills')
    fs.create_file(root / 'blank-skill' / 'SKILL.md', contents='   \n\n')

    assert walk_skill_dirs(root) == []


def test_walk_skill_dirs_skips_oversized_skill_file(fs: FakeFilesystem) -> None:
    """An oversized body would cost the device its MCP inventory too - one request carries both."""
    root = Path('/dummy/skills')
    fs.create_file(root / 'huge-skill' / 'SKILL.md', contents='x' * (MAX_SKILL_FILE_BYTES + 1))
    fs.create_file(root / 'small-skill' / 'SKILL.md', contents=_BODY)

    skills = walk_skill_dirs(root)

    assert [Path(s['path']).parent.name for s in skills] == ['small-skill']


def test_walk_skill_dirs_truncates_at_count_cap(fs: FakeFilesystem) -> None:
    root = Path('/dummy/skills')
    for index in range(MAX_SKILLS_PER_ROOT + 5):
        fs.create_file(root / f'skill-{index:04d}' / 'SKILL.md', contents=_BODY)

    assert len(walk_skill_dirs(root)) == MAX_SKILLS_PER_ROOT


def test_walk_skill_dirs_follows_the_current_home(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the skills directory must resolve when called, not when the module is imported.

    It was a module-level constant, so Path.home() was captured at import and a redirected home could
    never be seen - which passed locally and failed on CI runners whose home differed.
    """
    from cycode.cli.apps.ai_guardrails.ides.claude_code import ClaudeCode, _claude_skills_dir

    relocated = Path('/relocated-home')
    fs.create_file(relocated / '.claude' / 'skills' / 'moved-skill' / 'SKILL.md', contents=_BODY)
    monkeypatch.setattr(Path, 'home', staticmethod(lambda: relocated))

    assert _claude_skills_dir() == relocated / '.claude' / 'skills'
    assert [Path(s['path']).parent.name for s in ClaudeCode().get_skills()] == ['moved-skill']
