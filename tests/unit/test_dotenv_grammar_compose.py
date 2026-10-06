"""Dotenv grammar compose."""

from __future__ import annotations

import pytest

from sbfleet import upstream as up


def test_refuses_unquoted_dollar_dollar() -> None:
    with pytest.raises(up.UpstreamError, match=r"unquoted \$\$"):
        up.parse_dotenv("X=foo$$bar\n")
    with pytest.raises(up.UpstreamError, match=r"unquoted \$\$"):
        up.parse_dotenv("X=a$$b\n")


def test_refuses_unquoted_whitespace_after_equals() -> None:
    with pytest.raises(up.UpstreamError, match="whitespace after"):
        up.parse_dotenv("X= abc\n")
    # Tab after '=' is refused as a control character (also unsupported).
    with pytest.raises(up.UpstreamError):
        up.parse_dotenv("X=\tabc\n")
    assert up.parse_dotenv("X=abc\n")["X"] == "abc"


def test_double_quoted_dollar_dollar_still_unwraps() -> None:
    assert up.parse_dotenv('X="a$$b"\n')["X"] == "a$b"


def test_quoted_leading_space_preserved() -> None:
    assert up.parse_dotenv('X=" abc"\n')["X"] == " abc"


def test_dump_parse_roundtrip_preserves_dollar() -> None:
    dumped = up.dump_dotenv({"K": "pre$post", "J": '{"a":1}'})
    assert up.parse_dotenv(dumped) == {"K": "pre$post", "J": '{"a":1}'}


@pytest.mark.parametrize(
    "text",
    [
        "X=pre$HOME\n",
        'X="$HOME"\n',
        'X="${HOME}"\n',
        "X=a${HOME:-x}\n",
        "X=a\x7fb\n",
        "A=1\nA=2\n",
    ],
)
def test_still_refuses_expandables_controls_duplicates(text: str) -> None:
    with pytest.raises(up.UpstreamError):
        up.parse_dotenv(text)


def test_single_quoted_literal_unchanged() -> None:
    parsed = up.parse_dotenv("X='$HOME'\nY='${HOME}'\n")
    assert parsed["X"] == "$HOME"
    assert parsed["Y"] == "${HOME}"
