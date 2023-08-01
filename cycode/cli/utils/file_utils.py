import os


def change_filename_extension(filename: str, extension: str) -> str:
    base_name, old_ext = os.path.splitext(filename)
    return base_name + '.' + extension
