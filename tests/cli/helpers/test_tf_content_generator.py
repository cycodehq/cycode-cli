import os

from cycode.cli.helpers import tf_content_generator
from tests.conftest import TEST_FILES_PATH

_PATH_TO_EXAMPLES = os.path.join(TEST_FILES_PATH, 'tf_content_generator_files')


def test_generate_tf_content_from_tfplan() -> None:
    print(_PATH_TO_EXAMPLES)
    examples_directories = [
        name for name in os.listdir(_PATH_TO_EXAMPLES) if os.path.isdir(os.path.join(_PATH_TO_EXAMPLES, name))
    ]

    for example in examples_directories:
        tfplan_path = os.path.join(_PATH_TO_EXAMPLES, example, 'tfplan.json')
        tf_expected_content_path = os.path.join(_PATH_TO_EXAMPLES, example, 'tf_content.txt')
        with open(tfplan_path, 'r', encoding='utf-8') as tfplan_file, open(
            tf_expected_content_path, 'r', encoding='utf-8'
        ) as tf_expected_content_file:
            tfplan_content: str = tfplan_file.read()
            tf_expected_content: str = tf_expected_content_file.read()
            tf_content = tf_content_generator.generate_tf_content_from_tfplan(tfplan_content)
            assert tf_content == tf_expected_content
