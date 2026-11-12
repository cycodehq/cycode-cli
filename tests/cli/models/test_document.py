"""Binary (bytes) documents must be safe everywhere a document's content is read."""

from cycode.cli.models import Document
from cycode.cli.printers.utils.code_snippet_syntax import get_code_snippet_syntax
from cycode.cli.utils.scan_batch import split_documents_into_batches
from cycode.cli.utils.string_utils import is_binary_content
from cycode.cyclient.models import Detection

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


def test_bytes_content_is_binary() -> None:
    assert is_binary_content(_IMAGE) is True
    assert is_binary_content('plain text') is False


def test_code_snippet_of_a_bytes_document_is_empty() -> None:
    """Positions on an image point into text the server read out of it; there is nothing local to show."""
    detection = Detection(
        detection_type_id='type-id',
        type='GitHub Token',
        message='Hardcoded secret',
        detection_details={'line': 0, 'start_position': 3, 'length': 10},
        detection_rule_id='rule-id',
        severity='High',
    )

    snippet = get_code_snippet_syntax('secret', 'scan', detection, Document('image-1-shot.png', _IMAGE))

    assert snippet.code == ''
