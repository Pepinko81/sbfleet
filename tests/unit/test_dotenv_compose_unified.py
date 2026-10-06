"""Dotenv compose unified."""

from __future__ import annotations

import pytest

from sbfleet import upstream as up


@pytest.mark.parametrize(
    "text",
    [
        "X=pre$HOME\n",
        'X="$HOME"\n',
        'X="${HOME}"\n',
        'X="pre$HOME"\n',
        "X=pre${HOME}\n",
        "X=a${HOME:-x}\n",
    ],
)
def test_rejects_compose_expandable_interpolation(text: str) -> None:
    with pytest.raises(up.UpstreamError, match="unsupported interpolation"):
        up.parse_dotenv(text)


def test_accepts_single_quoted_dollar_literal() -> None:
    parsed = up.parse_dotenv("X='$HOME'\nY='${HOME}'\n")
    assert parsed["X"] == "$HOME"
    assert parsed["Y"] == "${HOME}"


def test_accepts_double_quoted_dollar_escape_and_writer_roundtrip() -> None:
    dumped = up.dump_dotenv({"K": "pre$post", "J": '{"a":1}'})
    parsed = up.parse_dotenv(dumped)
    assert parsed["K"] == "pre$post"
    assert parsed["J"] == '{"a":1}'
    assert up.parse_dotenv('X="a$$b"\n')["X"] == "a$b"


def test_rejects_del_and_controls() -> None:
    with pytest.raises(up.UpstreamError, match="control character"):
        up.parse_dotenv("X=a\x7fb\n")
    with pytest.raises(up.UpstreamError, match="control character"):
        up.parse_dotenv("X=a\x01b\n")
    with pytest.raises(up.UpstreamError, match="control character"):
        up.dump_dotenv({"X": "a\x7fb"})


def test_rejects_unquoted_dollar_dollar_and_whitespace() -> None:
    # : unquoted $$ / leading space diverge from Compose — refuse.
    with pytest.raises(up.UpstreamError, match=r"unquoted \$\$"):
        up.parse_dotenv("X=a$$b\n")
    with pytest.raises(up.UpstreamError, match="whitespace after"):
        up.parse_dotenv("X= abc\n")
