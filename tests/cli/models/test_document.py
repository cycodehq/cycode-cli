"""Binary (bytes) documents, as the guardrails scan sends attached images."""

from cycode.cli.models import Document
from cycode.cli.utils.scan_batch import split_documents_into_batches

_IMAGE = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100


def test_text_content_is_empty_for_bytes() -> None:
    assert Document('prompt-content.txt', 'some text').text_content == 'some text'
    assert Document('image-1-shot.png', _IMAGE).text_content == ''


def test_repr_does_not_dump_bytes() -> None:
    assert repr(Document('image-1-shot.png', _IMAGE)) == f'path:image-1-shot.png, content:<{len(_IMAGE)} bytes>'
    assert repr(Document('a.txt', 'abc')) == 'path:a.txt, content:abc'


def test_batches_count_bytes_as_they_are() -> None:
    documents = [Document('image-1-shot.png', _IMAGE), Document('prompt-content.txt', 'ü')]

    assert split_documents_into_batches('secret', documents) == [documents]
