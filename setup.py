from setuptools import find_packages, setup
from pathlib import Path
from cli import __version__


def get_long_description():
    this_directory = Path(__file__).parent
    return (this_directory / "README.md").read_text(encoding='utf-8')


setup(
    name='cycode',
    version=__version__,
    packages=find_packages(),
    url='https://github.com/cycodehq-public/cycode-cli',
    license='MIT',
    author='Cycode',
    data_files=[('cyclient', ['cyclient/config.yaml', 'VERSION.txt']), ('cli', ['cli/config.yaml', 'VERSION.txt'])],
    entry_points={
        'console_scripts': [
            'cycode=cli.cycode:main_cli',
        ]},
    include_package_data=True,
    author_email='support@cycode.com',
    description="Perform secrets/iac scans for your sources using Cycode's engine",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    install_requires=["click",
                      "requests",
                      "pyyaml",
                      "marshmallow",
                      "typing",
                      "pathspec",
                      "gitpython",
                      "arrow",
                      "colorama",
                      "binaryornot"
                      ],
    zip_safe=True,
    keywords="secret-scan cycode devops token secret security cycode code",
    classifiers=[
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
