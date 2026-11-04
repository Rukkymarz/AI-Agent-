"""Document loaders: PDF, DOCX, TXT, CSV, JSON, Markdown, HTML, websites, GitHub repos.

Network loaders enforce SSRF protection (no private/loopback/link-local/metadata targets).
Binary format loaders depend on optional extras: `pip install aicompany-os[knowledge]`.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import socket
import subprocess
import tempfile
from collections.abc import Iterable
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from aicos.domain.common import new_id, sha256_hex
from aicos.domain.errors import SecurityViolation, ValidationFailed


class Document(BaseModel):
    id: str = Field(default_factory=lambda: new_id("doc"))
    source: str
    mime: str
    text: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        return sha256_hex(self.text)


class Loader(Protocol):
    @property
    def extensions(self) -> tuple[str, ...]: ...

    def load(self, data: bytes, source: str) -> list[Document]: ...


class TextLoader:
    extensions = (".txt", ".md", ".markdown", ".rst", ".log")

    def load(self, data: bytes, source: str) -> list[Document]:
        mime = "text/markdown" if source.lower().endswith((".md", ".markdown")) else "text/plain"
        return [Document(source=source, mime=mime, text=data.decode("utf-8", errors="replace"))]


class JsonLoader:
    extensions = (".json", ".jsonl")

    def load(self, data: bytes, source: str) -> list[Document]:
        text = data.decode("utf-8", errors="replace")
        if source.endswith(".jsonl"):
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            parsed = json.loads(text)
            items = parsed if isinstance(parsed, list) else [parsed]
        return [
            Document(
                source=f"{source}#{i}", mime="application/json", text=json.dumps(item, indent=2, ensure_ascii=False), metadata={"record": i}
            )
            for i, item in enumerate(items)
        ]


class CsvLoader:
    extensions = (".csv", ".tsv")

    def load(self, data: bytes, source: str) -> list[Document]:
        dialect = "excel-tab" if source.endswith(".tsv") else "excel"
        reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig", errors="replace")), dialect=dialect)
        rows = ["; ".join(f"{k}: {v}" for k, v in row.items() if k) for row in reader]
        return [Document(source=source, mime="text/csv", text="\n".join(rows), metadata={"rows": len(rows)})]


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "template", "svg", "iframe"}

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip_depth = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag in {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "tr", "section", "article"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif not self._skip_depth:
            self.parts.append(data)


class HtmlLoader:
    extensions = (".html", ".htm")

    def load(self, data: bytes, source: str) -> list[Document]:
        p = _TextExtractor()
        p.feed(data.decode("utf-8", errors="replace"))
        text = "\n".join(line.strip() for line in "".join(p.parts).splitlines() if line.strip())
        return [Document(source=source, mime="text/html", text=text, metadata={"title": p.title.strip()})]


class PdfLoader:
    extensions = (".pdf",)

    def load(self, data: bytes, source: str) -> list[Document]:  # pragma: no cover - optional dep
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise ValidationFailed("PDF support requires the 'knowledge' extra (pypdf)") from exc
        reader = PdfReader(io.BytesIO(data))
        return [
            Document(source=f"{source}#page={i + 1}", mime="application/pdf", text=page.extract_text() or "", metadata={"page": i + 1})
            for i, page in enumerate(reader.pages)
        ]


class DocxLoader:
    extensions = (".docx",)

    def load(self, data: bytes, source: str) -> list[Document]:  # pragma: no cover - optional dep
        try:
            import docx
        except ImportError as exc:
            raise ValidationFailed("DOCX support requires the 'knowledge' extra (python-docx)") from exc
        d = docx.Document(io.BytesIO(data))
        text = "\n".join(p.text for p in d.paragraphs)
        return [Document(source=source, mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", text=text)]


class LoaderRegistry:
    def __init__(self, loaders: Iterable[Loader] | None = None) -> None:
        self._by_ext: dict[str, Loader] = {}
        for loader in loaders or [TextLoader(), JsonLoader(), CsvLoader(), HtmlLoader(), PdfLoader(), DocxLoader()]:
            self.register(loader)

    def register(self, loader: Loader) -> None:
        for ext in loader.extensions:
            self._by_ext[ext.lower()] = loader

    def unregister(self, loader: Loader) -> None:
        for ext in loader.extensions:
            if self._by_ext.get(ext.lower()) is loader:
                del self._by_ext[ext.lower()]

    @property
    def extensions(self) -> set[str]:
        return set(self._by_ext)

    def for_source(self, source: str) -> Loader:
        suffix = PurePosixPath(urlparse(source).path or source).suffix.lower()
        loader = self._by_ext.get(suffix)
        if loader is None:
            raise ValidationFailed(f"unsupported document type: {suffix or 'unknown'}")
        return loader

    def load(self, data: bytes, source: str) -> list[Document]:
        return self.for_source(source).load(data, source)


# ----------------------------------------------------------------------------- SSRF guard
_BLOCKED_HOSTS = {"metadata.google.internal", "metadata", "localhost"}


def assert_public_url(url: str, *, allow_http: bool = False) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise SecurityViolation("only https URLs are allowed")
    host = (parsed.hostname or "").lower()
    if not host or host in _BLOCKED_HOSTS or host.endswith((".internal", ".local", ".localhost")):
        raise SecurityViolation("blocked host")
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationFailed("host does not resolve") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise SecurityViolation("URL resolves to a non-public address")


class WebsiteLoader:  # pragma: no cover - network
    """Fetch a single page via egress proxy. DNS-rebinding: pin via proxy in production."""

    def __init__(self, max_bytes: int = 5_000_000, timeout: float = 15.0) -> None:
        self.max_bytes, self.timeout = max_bytes, timeout

    def fetch(self, url: str) -> list[Document]:
        import httpx

        assert_public_url(url)
        with httpx.Client(timeout=self.timeout, follow_redirects=False, headers={"User-Agent": "aicompany-os-knowledge/0.1"}) as c:
            r = c.get(url)
            if r.is_redirect:
                raise ValidationFailed("redirects are not followed; ingest the final URL")
            r.raise_for_status()
            if len(r.content) > self.max_bytes:
                raise ValidationFailed("document too large")
        return HtmlLoader().load(r.content, url)


class GitHubRepoLoader:  # pragma: no cover - network/subprocess
    TEXT_EXT = {".md", ".txt", ".py", ".ts", ".js", ".go", ".rs", ".java", ".yaml", ".yml", ".toml", ".json", ".sql", ".sh"}

    def __init__(self, max_files: int = 2000, max_file_bytes: int = 200_000) -> None:
        self.max_files, self.max_file_bytes = max_files, max_file_bytes

    def load_repo(self, repo_url: str, ref: str | None = None) -> list[Document]:
        assert_public_url(repo_url)
        if urlparse(repo_url).hostname not in {"github.com", "gitlab.com", "gitea.com"}:
            raise SecurityViolation("repository host not allow-listed")
        docs: list[Document] = []
        with tempfile.TemporaryDirectory() as tmp:
            cmd = ["git", "clone", "--depth", "1", "--no-tags", "--single-branch"]
            if ref:
                cmd += ["--branch", ref]
            subprocess.run(
                [*cmd, "--", repo_url, tmp],
                check=True,
                timeout=180,
                capture_output=True,
                env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin"},
            )
            root = Path(tmp)
            for path in sorted(root.rglob("*")):
                if len(docs) >= self.max_files:
                    break
                if ".git" in path.parts or not path.is_file() or path.is_symlink():
                    continue
                if path.suffix.lower() not in self.TEXT_EXT or path.stat().st_size > self.max_file_bytes:
                    continue
                rel = path.relative_to(root).as_posix()
                docs.append(
                    Document(
                        source=f"{repo_url}/blob/{ref or 'HEAD'}/{rel}",
                        mime="text/plain",
                        text=path.read_text(encoding="utf-8", errors="replace"),
                        metadata={"path": rel},
                    )
                )
        return docs
