import json
import os

from ethstaker_deposit.key_handling.keystore import Keystore


def get_uuid(key_file: str) -> str:
    keystore = Keystore.from_file(key_file)
    return keystore.uuid


def get_permissions(path: str, file_name: str) -> str:
    return oct(os.stat(os.path.join(path, file_name)).st_mode & 0o777)


def verify_file_permission(os_ref, folder_path, files):
    if os_ref.name == 'posix':
        for file_name in files:
            assert get_permissions(folder_path, file_name) == '0o440'


def read_json_file(path: str, file_name: str):
    with open(os.path.join(path, file_name), 'r', encoding='utf-8') as f:
        return json.load(f)
