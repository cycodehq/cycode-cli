import os
from os.path import normpath
from typing import TYPE_CHECKING

import pytest

from cycode.cli.files_collector.documents_walk_ignore import (
    _build_allowed_paths_set,
    _create_ignore_filter_manager,
    _filter_documents_by_allowed_paths,
    _get_cycodeignore_path,
    _get_document_check_path,
    filter_documents_with_cycodeignore,
)
from cycode.cli.models import Document

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem


# we are using normpath() in every test to provide multi-platform support


def _create_mocked_file_structure(fs: 'FakeFilesystem') -> None:
    """Create a mock file structure for testing."""
    fs.create_dir('/home/user/project')
    fs.create_dir('/home/user/.git')

    fs.create_dir('/home/user/project/.cycode')
    fs.create_file('/home/user/project/.cycode/config.yaml')
    fs.create_dir('/home/user/project/.git')
    fs.create_file('/home/user/project/.git/HEAD')

    # Create .cycodeignore with patterns
    fs.create_file('/home/user/project/.cycodeignore', contents='*.pyc\n*.log\nbuild/\n# comment line\n\n')
    
    # Create test files that should be filtered
    fs.create_file('/home/user/project/ignored.pyc')
    fs.create_file('/home/user/project/ignored.log')
    fs.create_file('/home/user/project/presented.txt')
    fs.create_file('/home/user/project/presented.py')
    
    # Create build directory with files (should be ignored)
    fs.create_dir('/home/user/project/build')
    fs.create_file('/home/user/project/build/output.js')
    fs.create_file('/home/user/project/build/bundle.css')

    # Create subdirectory
    fs.create_dir('/home/user/project/src')
    fs.create_file('/home/user/project/src/main.py')
    fs.create_file('/home/user/project/src/debug.log')  # should be ignored
    fs.create_file('/home/user/project/src/temp.pyc')  # should be ignored


def _create_test_documents(repo_path: str) -> list[Document]:
    """Create test Document objects for the mocked file structure."""
    documents = []
    
    # Files in root
    documents.append(Document(
        path='ignored.pyc',
        content='# compiled python',
        absolute_path=normpath(os.path.join(repo_path, 'ignored.pyc'))
    ))
    documents.append(Document(
        path='ignored.log',
        content='log content',
        absolute_path=normpath(os.path.join(repo_path, 'ignored.log'))
    ))
    documents.append(Document(
        path='presented.txt',
        content='text content',
        absolute_path=normpath(os.path.join(repo_path, 'presented.txt'))
    ))
    documents.append(Document(
        path='presented.py',
        content='print("hello")',
        absolute_path=normpath(os.path.join(repo_path, 'presented.py'))
    ))
    
    # Files in build directory (should be ignored)
    documents.append(Document(
        path='build/output.js',
        content='console.log("build");',
        absolute_path=normpath(os.path.join(repo_path, 'build/output.js'))
    ))
    documents.append(Document(
        path='build/bundle.css',
        content='body { color: red; }',
        absolute_path=normpath(os.path.join(repo_path, 'build/bundle.css'))
    ))
    
    # Files in src directory
    documents.append(Document(
        path='src/main.py',
        content='def main(): pass',
        absolute_path=normpath(os.path.join(repo_path, 'src/main.py'))
    ))
    documents.append(Document(
        path='src/debug.log',
        content='debug info',
        absolute_path=normpath(os.path.join(repo_path, 'src/debug.log'))
    ))
    documents.append(Document(
        path='src/temp.pyc',
        content='compiled',
        absolute_path=normpath(os.path.join(repo_path, 'src/temp.pyc'))
    ))
    
    return documents


def test_get_cycodeignore_path() -> None:
    """Test _get_cycodeignore_path helper function."""
    repo_path = normpath('/home/user/project')
    expected = normpath('/home/user/project/.cycodeignore')
    result = _get_cycodeignore_path(repo_path)
    assert result == expected


def test_create_ignore_filter_manager(fs: 'FakeFilesystem') -> None:
    """Test _create_ignore_filter_manager helper function."""
    _create_mocked_file_structure(fs)
    
    repo_path = normpath('/home/user/project')
    cycodeignore_path = normpath('/home/user/project/.cycodeignore')
    
    manager = _create_ignore_filter_manager(repo_path, cycodeignore_path)
    assert manager is not None
    
    # Test that it can walk the directory
    walked_dirs = list(manager.walk_with_ignored())
    assert len(walked_dirs) > 0


def test_get_document_check_path() -> None:
    """Test _get_document_check_path helper function."""
    repo_path = normpath('/home/user/project')
    
    # Test document with absolute_path
    doc_with_abs = Document(
        path='src/main.py',
        content='code',
        absolute_path=normpath('/home/user/project/src/main.py')
    )
    result = _get_document_check_path(doc_with_abs, repo_path)
    assert result == normpath('/home/user/project/src/main.py')
    
    # Test document without absolute_path but with absolute path
    doc_abs_path = Document(
        path=normpath('/home/user/project/src/main.py'),
        content='code'
    )
    result = _get_document_check_path(doc_abs_path, repo_path)
    assert result == normpath('/home/user/project/src/main.py')
    
    # Test document with relative path
    doc_rel_path = Document(
        path='src/main.py',
        content='code'
    )
    result = _get_document_check_path(doc_rel_path, repo_path)
    assert result == normpath('/home/user/project/src/main.py')


def test_build_allowed_paths_set(fs: 'FakeFilesystem') -> None:
    """Test _build_allowed_paths_set helper function."""
    _create_mocked_file_structure(fs)
    
    repo_path = normpath('/home/user/project')
    cycodeignore_path = normpath('/home/user/project/.cycodeignore')
    
    manager = _create_ignore_filter_manager(repo_path, cycodeignore_path)
    allowed_paths = _build_allowed_paths_set(manager, repo_path)
    
    # Check that allowed files are in the set
    assert normpath('/home/user/project/presented.txt') in allowed_paths
    assert normpath('/home/user/project/presented.py') in allowed_paths
    assert normpath('/home/user/project/src/main.py') in allowed_paths
    assert normpath('/home/user/project/.cycodeignore') in allowed_paths
    
    # Check that ignored files are NOT in the set
    assert normpath('/home/user/project/ignored.pyc') not in allowed_paths
    assert normpath('/home/user/project/ignored.log') not in allowed_paths
    assert normpath('/home/user/project/src/debug.log') not in allowed_paths
    assert normpath('/home/user/project/src/temp.pyc') not in allowed_paths
    assert normpath('/home/user/project/build/output.js') not in allowed_paths
    assert normpath('/home/user/project/build/bundle.css') not in allowed_paths


def test_filter_documents_by_allowed_paths() -> None:
    """Test _filter_documents_by_allowed_paths helper function."""
    repo_path = normpath('/home/user/project')
    
    # Create test documents
    documents = [
        Document(
            path='allowed.txt',
            content='content',
            absolute_path=normpath('/home/user/project/allowed.txt')
        ),
        Document(
            path='ignored.txt',
            content='content',
            absolute_path=normpath('/home/user/project/ignored.txt')
        ),
    ]
    
    # Create allowed paths set (only allow first document)
    allowed_paths = {normpath('/home/user/project/allowed.txt')}
    
    result = _filter_documents_by_allowed_paths(documents, allowed_paths, repo_path)
    
    assert len(result) == 1
    assert result[0].path == 'allowed.txt'


def test_filter_documents_with_cycodeignore_no_ignore_file(fs: 'FakeFilesystem') -> None:
    """Test filtering when no .cycodeignore file exists."""
    # Create structure without .cycodeignore
    fs.create_dir('/home/user/project')
    fs.create_file('/home/user/project/file1.py')
    fs.create_file('/home/user/project/file2.log')
    
    repo_path = normpath('/home/user/project')
    documents = [
        Document(path='file1.py', content='code'),
        Document(path='file2.log', content='log'),
    ]
    
    result = filter_documents_with_cycodeignore(documents, repo_path)
    
    # Should return all documents since no .cycodeignore exists
    assert len(result) == 2
    assert result == documents


def test_filter_documents_with_cycodeignore_basic_filtering(fs: 'FakeFilesystem') -> None:
    """Test basic document filtering with .cycodeignore."""
    _create_mocked_file_structure(fs)
    
    repo_path = normpath('/home/user/project')
    documents = _create_test_documents(repo_path)
    
    result = filter_documents_with_cycodeignore(documents, repo_path)
    
    # Count expected results: should exclude *.pyc, *.log, and build/* files
    expected_files = {
        'presented.txt',
        'presented.py', 
        'src/main.py',
    }
    
    result_files = {doc.path for doc in result}
    assert result_files == expected_files
    
    # Verify specific exclusions
    excluded_files = {doc.path for doc in documents if doc not in result}
    assert 'ignored.pyc' in excluded_files
    assert 'ignored.log' in excluded_files
    assert 'src/debug.log' in excluded_files
    assert 'src/temp.pyc' in excluded_files
    assert 'build/output.js' in excluded_files
    assert 'build/bundle.css' in excluded_files


def test_filter_documents_with_cycodeignore_relative_paths(fs: 'FakeFilesystem') -> None:
    """Test filtering documents with relative paths (no absolute_path set)."""
    _create_mocked_file_structure(fs)
    
    repo_path = normpath('/home/user/project')
    
    # Create documents without absolute_path
    documents = [
        Document(path='presented.py', content='code'),
        Document(path='ignored.pyc', content='compiled'),
        Document(path='src/main.py', content='code'),
        Document(path='src/debug.log', content='log'),
    ]
    
    result = filter_documents_with_cycodeignore(documents, repo_path)
    
    # Should filter out .pyc and .log files
    expected_files = {'presented.py', 'src/main.py'}
    result_files = {doc.path for doc in result}
    assert result_files == expected_files


def test_filter_documents_with_cycodeignore_absolute_paths(fs: 'FakeFilesystem') -> None:
    """Test filtering documents with absolute paths in path field."""
    _create_mocked_file_structure(fs)
    
    repo_path = normpath('/home/user/project')
    
    # Create documents with absolute paths in path field
    documents = [
        Document(path=normpath('/home/user/project/presented.py'), content='code'),
        Document(path=normpath('/home/user/project/ignored.pyc'), content='compiled'),
        Document(path=normpath('/home/user/project/src/main.py'), content='code'),
        Document(path=normpath('/home/user/project/src/debug.log'), content='log'),
    ]
    
    result = filter_documents_with_cycodeignore(documents, repo_path)
    
    # Should filter out .pyc and .log files
    expected_files = {
        normpath('/home/user/project/presented.py'),
        normpath('/home/user/project/src/main.py')
    }
    result_files = {doc.path for doc in result}
    assert result_files == expected_files


def test_filter_documents_with_cycodeignore_empty_file(fs: 'FakeFilesystem') -> None:
    """Test filtering with empty .cycodeignore file."""
    fs.create_dir('/home/user/project')
    fs.create_file('/home/user/project/.cycodeignore', contents='')  # empty file
    fs.create_file('/home/user/project/file1.py')
    fs.create_file('/home/user/project/file2.log')
    
    repo_path = normpath('/home/user/project')
    documents = [
        Document(path='file1.py', content='code'),
        Document(path='file2.log', content='log'),
    ]
    
    result = filter_documents_with_cycodeignore(documents, repo_path)
    
    # Should return all documents since .cycodeignore is empty
    assert len(result) == 2


def test_filter_documents_with_cycodeignore_comments_only(fs: 'FakeFilesystem') -> None:
    """Test filtering with .cycodeignore file containing only comments and empty lines."""
    fs.create_dir('/home/user/project')
    fs.create_file('/home/user/project/.cycodeignore', contents='# Just comments\n\n# More comments\n')
    fs.create_file('/home/user/project/file1.py')
    fs.create_file('/home/user/project/file2.log')
    
    repo_path = normpath('/home/user/project')
    documents = [
        Document(path='file1.py', content='code'),
        Document(path='file2.log', content='log'),
    ]
    
    result = filter_documents_with_cycodeignore(documents, repo_path)
    
    # Should return all documents since no real ignore patterns
    assert len(result) == 2


def test_filter_documents_with_cycodeignore_error_handling() -> None:
    """Test error handling when document processing fails."""
    # Use non-existent repo path
    repo_path = normpath('/non/existent/path')
    
    documents = [
        Document(path='file1.py', content='code'),
        Document(path='file2.txt', content='content'),
    ]
    
    # Should return all documents since .cycodeignore doesn't exist
    result = filter_documents_with_cycodeignore(documents, repo_path)
    assert len(result) == 2


def test_filter_documents_with_cycodeignore_complex_patterns(fs: 'FakeFilesystem') -> None:
    """Test filtering with complex ignore patterns."""
    fs.create_dir('/home/user/project')
    
    # Create .cycodeignore with various pattern types
    cycodeignore_content = '''
# Ignore specific files
config.json
secrets.key

# Ignore file patterns  
*.tmp
*.cache

# Ignore directories
logs/
temp/

# Ignore files in specific directories
tests/*.pyc
'''
    fs.create_file('/home/user/project/.cycodeignore', contents=cycodeignore_content)
    
    # Create test files
    test_files = [
        'config.json',      # ignored
        'secrets.key',      # ignored
        'app.py',          # allowed
        'file.tmp',        # ignored
        'data.cache',      # ignored
        'logs/app.log',    # ignored (directory)
        'temp/file.txt',   # ignored (directory)
        'tests/test.pyc',  # ignored (pattern in directory)
        'tests/test.py',   # allowed
        'src/main.py',     # allowed
    ]
    
    for file_path in test_files:
        full_path = normpath(os.path.join('/home/user/project', file_path))
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        fs.create_file(full_path)
    
    repo_path = normpath('/home/user/project')
    documents = [Document(path=f, content='content') for f in test_files]
    
    result = filter_documents_with_cycodeignore(documents, repo_path)
    
    # Should only allow: app.py, tests/test.py, src/main.py
    expected_files = {'app.py', 'tests/test.py', 'src/main.py'}
    result_files = {doc.path for doc in result}
    assert result_files == expected_files
