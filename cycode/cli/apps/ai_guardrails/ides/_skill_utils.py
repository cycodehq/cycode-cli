"""Shared skill-collection helpers for IDE integrations.

A skill is a directory holding a ``SKILL.md``: ``<skills root>/<skill name>/SKILL.md``.
The same layout is used for user-scope skills (``~/.claude/skills/``) and for the skills a
plugin ships (``<plugin dir>/skills/``), so one walker serves both.

Unlike an MCP config - a small JSON file at a known path - a ``SKILL.md`` body is unbounded
prose, and the number of installed skills is unbounded too. Both are capped here rather than
downstream: the whole session-context report is one request, so an oversized skill would cost
the device its MCP inventory as well.
"""

from pathlib import Path
from typing import Optional

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Skills')

SKILL_FILE_NAME = 'SKILL.md'

# A skill is instructions, not data. Anything larger is not a skill we can usefully inventory,
# and sending it would push the one-request report toward the API's body limit.
MAX_SKILL_FILE_BYTES = 256 * 1024

# Per skills root, not per device: a developer with more installed skills than this in one place
# is an outlier we would rather truncate than let define the payload size.
MAX_SKILLS_PER_ROOT = 200


def _read_skill_file(skill_file: Path) -> Optional[dict]:
    """Read one ``SKILL.md`` into the session-context file shape, or None if unusable."""
    try:
        size = skill_file.stat().st_size
    except OSError as e:
        logger.debug('Failed to stat skill file, %s', {'path': str(skill_file)}, exc_info=e)
        return None

    if size > MAX_SKILL_FILE_BYTES:
        logger.debug(
            'Skill file exceeds the size cap; skipping, %s',
            {'path': str(skill_file), 'size': size, 'cap': MAX_SKILL_FILE_BYTES},
        )
        return None

    try:
        content = skill_file.read_text(encoding='utf-8')
    except Exception as e:
        logger.debug('Failed to read skill file, %s', {'path': str(skill_file)}, exc_info=e)
        return None

    if not content.strip():
        return None

    return {'path': str(skill_file), 'content': content}


def walk_skill_dirs(skills_root: Path) -> list[dict]:
    """Collect every ``<skills_root>/<name>/SKILL.md`` as ``{"path", "content"}``.

    Exactly one directory level is scanned. A skill directory may hold nested references and
    scripts, but its ``SKILL.md`` always sits at the top of it, so there is nothing to recurse
    into - which is also what keeps this bounded without a depth cap.

    Results are sorted by path: the session-context report is deduplicated by hashing the whole
    payload, so an unstable order would re-send an unchanged inventory.
    """
    if not skills_root.is_dir():
        return []

    try:
        skill_dirs = sorted(d for d in skills_root.iterdir() if d.is_dir())
    except OSError as e:
        logger.debug('Failed to list skills root, %s', {'path': str(skills_root)}, exc_info=e)
        return []

    skills: list[dict] = []
    for skill_dir in skill_dirs:
        if len(skills) >= MAX_SKILLS_PER_ROOT:
            logger.debug(
                'Skills root exceeds the count cap; truncating, %s',
                {'path': str(skills_root), 'cap': MAX_SKILLS_PER_ROOT},
            )
            break

        skill = _read_skill_file(skill_dir / SKILL_FILE_NAME)
        if skill:
            skills.append(skill)

    return skills
