"""Structure-aware recursive chunker (headings -> paragraphs -> sentences -> hard split)."""

from __future__ import annotations

import re

from pydantic import BaseModel

_HEADING = re.compile(r"(?m)^(#{1,6})\s+(.+)$")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


class Chunk(BaseModel):
    index: int
    text: str
    heading: str | None = None


def _split_sections(text: str) -> list[tuple[str | None, str]]:
    matches = list(_HEADING.finditer(text))
    if not matches:
        return [(None, text)]
    sections: list[tuple[str | None, str]] = []
    if matches[0].start() > 0:
        sections.append((None, text[: matches[0].start()]))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections.append((m.group(2).strip(), text[m.start() : end]))
    return sections


def _pieces(text: str, size: int) -> list[str]:
    if len(text) <= size:
        return [text]
    out: list[str] = []
    for para in re.split(r"\n\s*\n", text):
        if len(para) <= size:
            out.append(para)
            continue
        for sent in _SENTENCE.split(para):
            if len(sent) <= size:
                out.append(sent)
            else:
                out.extend(sent[i : i + size] for i in range(0, len(sent), size))
    return out


def chunk_text(text: str, *, size: int = 1200, overlap: int = 150) -> list[Chunk]:
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("require size > overlap >= 0")
    chunks: list[Chunk] = []
    for heading, section in _split_sections(text.strip()):
        buf = ""
        for raw in _pieces(section.strip(), size):
            piece = raw.strip()
            if not piece:
                continue
            if buf and len(buf) + len(piece) + 2 > size:
                chunks.append(Chunk(index=len(chunks), text=buf, heading=heading))
                tail = buf[-overlap:] if overlap else ""
                buf = f"{tail}\n\n{piece}" if tail else piece
            else:
                buf = f"{buf}\n\n{piece}" if buf else piece
        if buf.strip():
            chunks.append(Chunk(index=len(chunks), text=buf, heading=heading))
    return chunks
