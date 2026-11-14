"""Offline Markdown hygiene and local file/heading-link checks (stdlib only)."""
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'!?\[[^\]]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)')


def headings(text):
    seen = {}
    result = set()
    for line in text.splitlines():
        match = re.match(r'^#{1,6}\s+(.+?)(?:\s+#+)?$', line)
        if match:
            slug = re.sub(r'[^\w\- ]', '', match[1].lower()).replace(' ', '-')
            number = seen.get(slug, 0)
            seen[slug] = number + 1
            result.add(slug + (f'-{number}' if number else ''))
    return result


def check(path):
    errors = []
    text = path.read_text(encoding='utf-8')
    fence = None
    visible = []
    for number, line in enumerate(text.splitlines(), 1):
        marker = re.match(r'^\s*(`{3,}|~{3,})', line)
        if marker:
            char = marker[1][0]
            if fence is None:
                fence = char
            elif fence == char:
                fence = None
            continue
        if fence:
            continue
        visible.append(line)
        if line.rstrip(' ') != line and not line.endswith('  '):
            errors.append(f'{number}: trailing whitespace')
        if re.match(r'^#{1,6}[^ #]', line):
            errors.append(f'{number}: heading needs a space')
    if fence:
        errors.append('unclosed code fence')
    for target in LINK.findall('\n'.join(visible)):
        parts = urlsplit(target.strip('<>'))
        if parts.scheme or parts.netloc:
            continue  # Never fetch remote URLs.
        dest = (path.parent / unquote(parts.path)).resolve() if parts.path else path
        if not dest.is_relative_to(ROOT):
            errors.append(f'link escapes repository: {target}')
        elif not dest.exists():
            errors.append(f'missing local link: {target}')
        elif parts.fragment and dest.suffix.lower() == '.md':
            if unquote(parts.fragment) not in headings(dest.read_text(encoding='utf-8')):
                errors.append(f'missing heading: {target}')
    return errors


def main():
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others',
                                     '--exclude-standard', '*.md'], cwd=ROOT, text=True)
    failures = [(name, error) for name in sorted(set(names.splitlines()))
                for error in check(ROOT / name)]
    for name, error in failures:
        print(f'{name}: {error}')
    print(f'Checked {len(set(names.splitlines()))} Markdown files; {len(failures)} errors')
    return bool(failures)


if __name__ == '__main__':
    sys.exit(main())
