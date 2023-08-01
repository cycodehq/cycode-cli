import os

from cycode.cli.helpers import tf_content_generator

examples_main_dir = '../../test_files/tf_content_generator_files'


def test_generate_tf_content_from_tfplan() -> None:
    examples_directories = [
        name for name in os.listdir(examples_main_dir) if os.path.isdir(os.path.join(examples_main_dir, name))
    ]

    for example in examples_directories:
        tfplan_path = os.path.join(examples_main_dir, example, 'tfplan.json')
        tf_expected_content_path = os.path.join(examples_main_dir, example, 'tf_content.txt')
        with open(tfplan_path, 'r') as tfplan_file, open(tf_expected_content_path, 'r') as tf_expected_content_file:
            tfplan_content: str = tfplan_file.read()
            tf_expected_content: str = tf_expected_content_file.read()
            tf_content = tf_content_generator.generate_tf_content_from_tfplan(tfplan_content)
            assert tf_content == tf_expected_content
