import os


def split_list(input_list, batch_size):
    for i in range(0, len(input_list), batch_size):
        yield input_list[i:i + batch_size]


def cpu_count():
    return os.cpu_count() or 1
