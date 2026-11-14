"""Password generator command: generate."""

from __future__ import annotations

import json

import typer

from envvault.cli._common import (
    _copy_to_clipboard,
    _fail,
    app,
    console,
)
from envvault.passwords import (
    DEFAULT_LENGTH,
    InvalidLength,
    PasswordOptions,
    entropy_bits,
    generate_password,
)


@app.command()
def generate(
    length: int = typer.Option(DEFAULT_LENGTH, "--length", "-l", min=8, max=256),
    upper: bool = typer.Option(True, "--upper/--no-upper"),
    lower: bool = typer.Option(True, "--lower/--no-lower"),
    digits: bool = typer.Option(True, "--digits/--no-digits"),
    symbols: bool = typer.Option(True, "--symbols/--no-symbols"),
    count: int = typer.Option(1, "--count", "-c", min=1, max=100),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
    copy: bool = typer.Option(False, "--copy", help="Copy the first one to the clipboard"),
) -> None:
    """Generate strong passwords locally (system CSPRNG)."""
    options = PasswordOptions(
        length=length, upper=upper, lower=lower, digits=digits, symbols=symbols
    )
    try:
        passwords = [generate_password(options) for _ in range(count)]
    except InvalidLength as exc:
        _fail(str(exc))
        return
    bits = round(entropy_bits(options), 1)
    if as_json:
        console.print_json(
            json.dumps(
                {
                    "passwords": passwords,
                    "length": length,
                    "entropy_bits": bits,
                    "alphabet_size": len(options.alphabet()),
                }
            )
        )
        return
    if copy and not _copy_to_clipboard(passwords[0]):
        _fail("no clipboard utility found (wl-copy/xclip/pbcopy)")
    for password in passwords:
        console.print(password)
    console.print(
        f"[dim]{length} characters · ~{bits} bits of entropy · "
        f"{len(options.alphabet())} possible symbols[/dim]",
        err=True,
    )
