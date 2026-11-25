"""
Static shell completion scripts for `security-scan` — CLI_ROADMAP.md Phase 4.
"""

from __future__ import annotations

import argparse
import io
import textwrap
from typing import TextIO


def collect_option_strings(parser: argparse.ArgumentParser) -> list[str]:
    """All option strings (--foo, -q) from a built ArgumentParser."""
    seen: set[str] = set()
    for action in parser._actions:
        for s in getattr(action, "option_strings", ()) or ():
            if s:
                seen.add(s)
    return sorted(seen, key=lambda x: (len(x) - x.count("-"), x))


def write_completion_script(
    stream: TextIO,
    parser: argparse.ArgumentParser,
    shell: str,
    *,
    prog: str = "security-scan",
) -> None:
    """Emit a completion script for bash, zsh, or pwsh."""
    flags = collect_option_strings(parser)
    flags_bash = " ".join(_bash_word(f) for f in flags)

    if shell == "bash":
        stream.write(
            textwrap.dedent(
                f"""\
            # Generated: security-scan --print-completion bash
            # Usage: eval "$(security-scan --print-completion bash)"
            _security_scan_complete() {{
              local cur
              COMPREPLY=()
              cur="${{COMP_WORDS[COMP_CWORD]}}"
              if [[ ${{COMP_CWORD}} -eq 1 ]] && [[ "$cur" != -* ]]; then
                COMPREPLY=( $(compgen -W "run replay doctor" -- "$cur") )
                return 0
              fi
              local flags="{flags_bash}"
              COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
            }}
            complete -o default -o bashdefault -F _security_scan_complete {prog}
            """
            ).lstrip()
        )
    elif shell == "zsh":
        lines = [
            "# Generated: security-scan --print-completion zsh",
            "# Install: save as _security-scan on fpath, autoload -Uz compinit && compinit",
            f"#compdef {prog}",
            "_security_scan() {",
            "  local -a subcmds opts",
            "  subcmds=(run replay doctor)",
            "  opts=(",
        ]
        for f in flags:
            lines.append(f"    '{_escape_single(f)}'")
        lines.extend(
            [
                "  )",
                "  if (( CURRENT == 2 )) && [[ ${words[2]} != -* ]]; then",
                "    compadd -a subcmds",
                "    return",
                "  fi",
                "  compadd -a opts",
                "}",
                "_security_scan \"$@\"",
            ]
        )
        stream.write("\n".join(lines) + "\n")
    elif shell == "pwsh":
        all_words = ["run", "replay", "doctor", *flags]
        inner = ",".join(f"'{_escape_ps_single(s)}'" for s in all_words)
        stream.write(
            textwrap.dedent(
                f"""\
            # Generated: security-scan --print-completion pwsh
            # Dot-source or add to Microsoft.PowerShell_profile.ps1
            $SecurityScanCompleteAll = @({inner})
            Register-ArgumentCompleter -Native -CommandName {prog} -ScriptBlock {{
              param($wordToComplete, $commandAst, $cursorPosition)
              $SecurityScanCompleteAll | Where-Object {{ $_ -like "$wordToComplete*" }}
            }}
            """
            ).lstrip()
        )
    else:
        raise ValueError(f"unsupported shell: {shell!r}")


def _bash_word(s: str) -> str:
    if all(c.isalnum() or c in "._-:/" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _escape_single(s: str) -> str:
    return s.replace("'", "'\\''")


def _escape_ps_single(s: str) -> str:
    return s.replace("'", "''")


def completion_script_to_string(parser: argparse.ArgumentParser, shell: str, *, prog: str = "security-scan") -> str:
    buf = io.StringIO()
    write_completion_script(buf, parser, shell, prog=prog)
    return buf.getvalue()
