import os
import re

from cycode.cli.files_collector.iac import tf_content_generator
from cycode.cli.utils.path_utils import get_file_content, get_immediate_subdirectories
from tests.conftest import TEST_FILES_PATH

_PATH_TO_EXAMPLES = os.path.join(TEST_FILES_PATH, 'tf_content_generator_files')


def test_generate_tf_content_from_tfplan() -> None:
    examples_directories = get_immediate_subdirectories(_PATH_TO_EXAMPLES)
    for example in examples_directories:
        tfplan_content = get_file_content(os.path.join(_PATH_TO_EXAMPLES, example, 'tfplan.json'))
        tf_expected_content = get_file_content(os.path.join(_PATH_TO_EXAMPLES, example, 'tf_content.txt'))
        tf_content = tf_content_generator.generate_tf_content_from_tfplan(example, tfplan_content)

        cleaned_tf_content = re.sub(r'-[a-fA-F0-9\-]{36}', '', tf_content)
        assert cleaned_tf_content == tf_expected_content
