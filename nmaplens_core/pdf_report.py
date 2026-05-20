from __future__ import annotations

from textwrap import wrap

from .markdown_report import build_markdown_report


def build_pdf_report(scan_data: dict[str, object]) -> bytes:
    report_text = build_markdown_report(scan_data)
    lines = _normalize_lines(report_text)
    pages = _paginate(lines, max_lines_per_page=48)

    objects: list[bytes] = []

    def add_object(payload: str | bytes) -> int:
        data = payload.encode("latin-1", errors="replace") if isinstance(payload, str) else payload
        objects.append(data)
        return len(objects)

    font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    content_ids: list[int] = []
    page_ids: list[int] = []

    for page_lines in pages:
        stream = _build_page_stream(page_lines)
        content = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream
            + b"\nendstream"
        )
        content_ids.append(add_object(content))
        page_ids.append(0)

    pages_id = add_object("<< /Type /Pages /Kids [] /Count 0 >>")

    for index, content_id in enumerate(content_ids):
        page_payload = (
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        )
        page_ids[index] = add_object(page_payload)

    objects[pages_id - 1] = (
        f"<< /Type /Pages /Kids [{' '.join(f'{page_id} 0 R' for page_id in page_ids)}] "
        f"/Count {len(page_ids)} >>"
    ).encode("latin-1")

    catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")
    return _assemble_pdf(objects, catalog_id)


def _normalize_lines(report_text: str) -> list[str]:
    normalized: list[str] = []
    for raw_line in report_text.splitlines():
        line = raw_line.expandtabs(4).rstrip()
        if not line:
            normalized.append("")
            continue
        normalized.extend(wrap(line, width=92) or [""])
    return normalized


def _paginate(lines: list[str], max_lines_per_page: int) -> list[list[str]]:
    if not lines:
        return [["NmapLens Report"]]
    return [lines[index:index + max_lines_per_page] for index in range(0, len(lines), max_lines_per_page)]


def _build_page_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]
    first = True
    for line in lines:
        escaped = _escape_pdf_text(line)
        if first:
            commands.append(f"({escaped}) Tj")
            first = False
        else:
            commands.append(f"T* ({escaped}) Tj")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _assemble_pdf(objects: list[bytes], catalog_id: int) -> bytes:
    chunks = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
    offsets = [0]
    size = len(chunks[0])

    for object_id, payload in enumerate(objects, start=1):
        offsets.append(size)
        entry = f"{object_id} 0 obj\n".encode("latin-1") + payload + b"\nendobj\n"
        chunks.append(entry)
        size += len(entry)

    xref_offset = size
    xref = [f"xref\n0 {len(objects) + 1}\n".encode("latin-1"), b"0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(f"{offset:010d} 00000 n \n".encode("latin-1"))
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("latin-1")
    chunks.extend(xref)
    chunks.append(trailer)
    return b"".join(chunks)
