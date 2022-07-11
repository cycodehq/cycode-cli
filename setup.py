from setuptools import find_packages, setup

from cli import __version__

setup(
    name='cycode',
    version=__version__,
    packages=find_packages(),
    url='https://github.com/cycodehq/cycode_cli',
    license='MIT',
    author='Cycode',
    data_files=[('cyclient', ['cyclient/config.yaml']), ('cli', ['cli/config.yaml'])],
    entry_points={
        'console_scripts': [
            'cycode=cli.cycode:main_cli',
        ]},
    include_package_data=True,
    author_email='maor@cycode.com',
    description='',
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
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
