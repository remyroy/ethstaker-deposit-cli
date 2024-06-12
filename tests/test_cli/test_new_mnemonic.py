import asyncio
import json
import os

from tempfile import TemporaryDirectory

import pytest
from click.testing import CliRunner

from eth_utils import decode_hex

from ethstaker_deposit.cli import new_mnemonic
from ethstaker_deposit.deposit import cli
from ethstaker_deposit.key_handling.key_derivation.mnemonic import abbreviate_words
from ethstaker_deposit.utils.constants import (
    BLS_WITHDRAWAL_PREFIX,
    DEFAULT_VALIDATOR_KEYS_FOLDER_NAME,
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
)
from ethstaker_deposit.utils.intl import load_text
from .helpers import get_permissions, get_uuid


def test_new_mnemonic_bls_withdrawal(monkeypatch) -> None:
    # monkeypatch get_mnemonic
    def mock_get_mnemonic(language, words_path, entropy=None) -> str:
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    monkeypatch.setattr(new_mnemonic, "get_mnemonic", mock_get_mnemonic)

    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        runner = CliRunner()
        inputs = ['english', 'english', '1', 'mainnet', 'MyPassword', 'MyPassword',
                  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']
        data = '\n'.join(inputs)
        arguments = [
            '--ignore_connectivity',
            'new-mnemonic',
            '--eth1_withdrawal_address', '',
            '--folder', my_folder_path,
        ]
        result = runner.invoke(cli, arguments, input=data)
        assert result.exit_code == 0

        # Check files
        validator_keys_folder_path = os.path.join(my_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        all_uuid = [
            get_uuid(validator_keys_folder_path + '/' + key_file)
            for key_file in key_files
            if key_file.startswith('keystore')
        ]
        assert len(set(all_uuid)) == 1

        # Verify file permissions
        if os.name == 'posix':
            for file_name in key_files:
                assert get_permissions(validator_keys_folder_path, file_name) == '0o440'


def test_new_mnemonic_eth1_address_withdrawal(monkeypatch) -> None:
    # monkeypatch get_mnemonic
    def mock_get_mnemonic(language, words_path, entropy=None) -> str:
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    monkeypatch.setattr(new_mnemonic, "get_mnemonic", mock_get_mnemonic)

    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        runner = CliRunner()
        eth1_withdrawal_address = '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        inputs = ['english', '1', 'mainnet', 'MyPassword', 'MyPassword', eth1_withdrawal_address,
                  eth1_withdrawal_address,
                  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            '--ignore_connectivity',
            'new-mnemonic',
            '--folder', my_folder_path,
        ]
        result = runner.invoke(cli, arguments, input=data)
        assert result.exit_code == 0

        # Check files
        validator_keys_folder_path = os.path.join(my_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        deposit_file = [key_file for key_file in key_files if key_file.startswith('deposit_data')][0]
        with open(validator_keys_folder_path + '/' + deposit_file, 'r', encoding='utf-8') as f:
            deposits_dict = json.load(f)
        for deposit in deposits_dict:
            withdrawal_credentials = bytes.fromhex(deposit['withdrawal_credentials'])
            assert withdrawal_credentials == (
                ETH1_ADDRESS_WITHDRAWAL_PREFIX + b'\x00' * 11 + decode_hex(eth1_withdrawal_address)
            )

        all_uuid = [
            get_uuid(validator_keys_folder_path + '/' + key_file)
            for key_file in key_files
            if key_file.startswith('keystore')
        ]
        assert len(set(all_uuid)) == 1

        # Verify file permissions
        if os.name == 'posix':
            for file_name in key_files:
                assert get_permissions(validator_keys_folder_path, file_name) == '0o440'


def test_new_mnemonic_eth1_address_withdrawal_bad_checksum(monkeypatch) -> None:
    # monkeypatch get_mnemonic
    def mock_get_mnemonic(language, words_path, entropy=None) -> str:
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    monkeypatch.setattr(new_mnemonic, "get_mnemonic", mock_get_mnemonic)

    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        runner = CliRunner()

        # NOTE: final 'A' needed to be an 'a'
        wrong_eth1_withdrawal_address = '0x00000000219ab540356cBB839Cbe05303d7705FA'
        correct_eth1_withdrawal_address = '0x00000000219ab540356cBB839Cbe05303d7705Fa'

        inputs = ['english', '1', 'mainnet', 'MyPassword', 'MyPassword',
                  wrong_eth1_withdrawal_address, correct_eth1_withdrawal_address, correct_eth1_withdrawal_address,
                  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            '--ignore_connectivity',
            'new-mnemonic',
            '--folder', my_folder_path,
        ]
        result = runner.invoke(cli, arguments, input=data)
        assert result.exit_code == 0

        # Check files
        validator_keys_folder_path = os.path.join(my_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        deposit_file = [key_file for key_file in key_files if key_file.startswith('deposit_data')][0]
        with open(validator_keys_folder_path + '/' + deposit_file, 'r', encoding='utf-8') as f:
            deposits_dict = json.load(f)
        for deposit in deposits_dict:
            withdrawal_credentials = bytes.fromhex(deposit['withdrawal_credentials'])
            assert withdrawal_credentials == (
                ETH1_ADDRESS_WITHDRAWAL_PREFIX + b'\x00' * 11 + decode_hex(correct_eth1_withdrawal_address)
            )

        all_uuid = [
            get_uuid(validator_keys_folder_path + '/' + key_file)
            for key_file in key_files
            if key_file.startswith('keystore')
        ]
        assert len(set(all_uuid)) == 1

        # Verify file permissions
        if os.name == 'posix':
            for file_name in key_files:
                assert get_permissions(validator_keys_folder_path, file_name) == '0o440'


def test_new_mnemonic_eth1_address_withdrawal_alias(monkeypatch) -> None:
    # monkeypatch get_mnemonic
    def mock_get_mnemonic(language, words_path, entropy=None) -> str:
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    monkeypatch.setattr(new_mnemonic, "get_mnemonic", mock_get_mnemonic)

    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        runner = CliRunner()
        execution_address = '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        inputs = [execution_address, 'english', '1', 'mainnet', 'MyPassword', 'MyPassword',
                  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            '--ignore_connectivity',
            'new-mnemonic',
            '--folder', my_folder_path,
            '--execution_address', execution_address,  # execution_address and eth1_withdrawal_address are aliases
        ]
        result = runner.invoke(cli, arguments, input=data)
        assert result.exit_code == 0

        # Check files
        validator_keys_folder_path = os.path.join(my_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        deposit_file = [key_file for key_file in key_files if key_file.startswith('deposit_data')][0]
        with open(validator_keys_folder_path + '/' + deposit_file, 'r', encoding='utf-8') as f:
            deposits_dict = json.load(f)
        for deposit in deposits_dict:
            withdrawal_credentials = bytes.fromhex(deposit['withdrawal_credentials'])
            assert withdrawal_credentials == (
                ETH1_ADDRESS_WITHDRAWAL_PREFIX + b'\x00' * 11 + decode_hex(execution_address)
            )

        all_uuid = [
            get_uuid(validator_keys_folder_path + '/' + key_file)
            for key_file in key_files
            if key_file.startswith('keystore')
        ]
        assert len(set(all_uuid)) == 1

        # Verify file permissions
        if os.name == 'posix':
            for file_name in key_files:
                assert get_permissions(validator_keys_folder_path, file_name) == '0o440'


def test_new_mnemonic_eth1_address_withdrawal_double_params(monkeypatch) -> None:
    # monkeypatch get_mnemonic
    def mock_get_mnemonic(language, words_path, entropy=None) -> str:
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    monkeypatch.setattr(new_mnemonic, "get_mnemonic", mock_get_mnemonic)

    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        runner = CliRunner()
        execution_address = '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        inputs = [execution_address, 'english', '1', 'mainnet', 'MyPassword', 'MyPassword',
                  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            '--ignore_connectivity',
            'new-mnemonic',
            '--folder', my_folder_path,
            '--execution_address', execution_address,
            '--eth1_withdrawal_address', execution_address,  # double param
        ]
        result = runner.invoke(cli, arguments, input=data)

        # FIXME: Should not allow it
        assert result.exit_code == 0


def test_pbkdf2_new_mnemonic(monkeypatch) -> None:
    # monkeypatch get_mnemonic
    def mock_get_mnemonic(language, words_path, entropy=None) -> str:
        return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    monkeypatch.setattr(new_mnemonic, "get_mnemonic", mock_get_mnemonic)

    # Prepare pbkdf2 folder and scrypt folder
    with TemporaryDirectory() as pbkdf2_folder_path, TemporaryDirectory() as scrypt_folder_path:

        runner = CliRunner()

        inputs = ['english', '1', 'mainnet', 'MyPassword', 'MyPassword',
                  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            'new-mnemonic',
            '--eth1_withdrawal_address', '',
            '--folder', pbkdf2_folder_path,
            '--pbkdf2',
        ]
        result = runner.invoke(cli, arguments, input=data)
        assert result.exit_code == 0

        arguments = [
            '--language', 'english',
            'new-mnemonic',
            '--eth1_withdrawal_address', '',
            '--folder', scrypt_folder_path,
        ]
        result = runner.invoke(cli, arguments, input=data)
        assert result.exit_code == 0

        # Load store generated files
        validator_keys_folder_path = os.path.join(pbkdf2_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        deposit_file = [key_file for key_file in key_files if key_file.startswith('deposit_data')][0]
        with open(validator_keys_folder_path + '/' + deposit_file, 'r', encoding='utf-8') as f:
            pbkdf2_deposit_dict = json.load(f)[0]

        keystore_file = [key_file for key_file in key_files if key_file.startswith('keystore-m_')][0]
        with open(validator_keys_folder_path + '/' + keystore_file, 'r', encoding='utf-8') as f:
            pbkdf2_keystore_dict = json.load(f)

        validator_keys_folder_path = os.path.join(scrypt_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        deposit_file = [key_file for key_file in key_files if key_file.startswith('deposit_data')][0]
        with open(validator_keys_folder_path + '/' + deposit_file, 'r', encoding='utf-8') as f:
            scrypt_deposit_dict = json.load(f)[0]

        keystore_file = [key_file for key_file in key_files if key_file.startswith('keystore-m_')][0]
        with open(validator_keys_folder_path + '/' + keystore_file, 'r', encoding='utf-8') as f:
            scrypt_keystore_dict = json.load(f)

        # Verify deposit files
        assert pbkdf2_deposit_dict['withdrawal_credentials'] == scrypt_deposit_dict['withdrawal_credentials']
        assert pbkdf2_deposit_dict['pubkey'] == scrypt_deposit_dict['pubkey']
        assert pbkdf2_deposit_dict['signature'] == scrypt_deposit_dict['signature']
        assert pbkdf2_deposit_dict['deposit_message_root'] == scrypt_deposit_dict['deposit_message_root']
        assert pbkdf2_deposit_dict['deposit_data_root'] == scrypt_deposit_dict['deposit_data_root']

        # Verify keystore files
        assert pbkdf2_keystore_dict['crypto']['kdf']['function'] == 'pbkdf2'
        assert scrypt_keystore_dict['crypto']['kdf']['function'] == 'scrypt'
        assert pbkdf2_keystore_dict['pubkey'] == scrypt_keystore_dict['pubkey']


@pytest.mark.asyncio
async def test_script_bls_withdrawal() -> None:
    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        if os.name == 'nt':  # Windows
            run_script_cmd = 'sh deposit.sh'
        else:  # Mac or Linux
            run_script_cmd = './deposit.sh'

        install_cmd = run_script_cmd + ' install'
        proc = await asyncio.create_subprocess_shell(
            install_cmd,
        )
        await proc.wait()

        cmd_args = [
            run_script_cmd,
            '--language', 'english',
            '--non_interactive',
            'new-mnemonic',
            '--num_validators', '5',
            '--mnemonic_language', 'english',
            '--chain', 'mainnet',
            '--keystore_password', 'MyPassword',
            '--eth1_withdrawal_address', '""',
            '--folder', my_folder_path,
        ]
        proc = await asyncio.create_subprocess_shell(
            ' '.join(cmd_args),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )

        seed_phrase = ''
        parsing = False
        mnemonic_json_file = os.path.join(os.getcwd(), 'ethstaker_deposit/../ethstaker_deposit/cli/',
                                          'new_mnemonic.json')
        async for out in proc.stdout:
            output = out.decode('utf-8').rstrip()
            if output.startswith(load_text(['msg_mnemonic_presentation'], mnemonic_json_file, 'new_mnemonic')):
                parsing = True
            elif output.startswith(load_text(['msg_mnemonic_retype_prompt'], mnemonic_json_file, 'new_mnemonic')):
                parsing = False
            elif parsing:
                seed_phrase += output
                if len(seed_phrase) > 0:
                    encoded_phrase = seed_phrase.encode()
                    proc.stdin.write(encoded_phrase)
                    proc.stdin.write(b'\n')

        assert len(seed_phrase) > 0

        await proc.wait()

        # Check files
        validator_keys_folder_path = os.path.join(my_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        deposit_file = [key_file for key_file in key_files if key_file.startswith('deposit_data')][0]
        with open(validator_keys_folder_path + '/' + deposit_file, 'r', encoding='utf-8') as f:
            deposits_dict = json.load(f)
        for deposit in deposits_dict:
            withdrawal_credentials = bytes.fromhex(deposit['withdrawal_credentials'])
            print('withdrawal_credentials', withdrawal_credentials)
            assert withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX

        _, _, key_files = next(os.walk(validator_keys_folder_path))

        all_uuid = [
            get_uuid(validator_keys_folder_path + '/' + key_file)
            for key_file in key_files
            if key_file.startswith('keystore')
        ]
        assert len(set(all_uuid)) == 5

        # Verify file permissions
        if os.name == 'posix':
            for file_name in key_files:
                assert get_permissions(validator_keys_folder_path, file_name) == '0o440'


@pytest.mark.asyncio
async def test_script_abbreviated_mnemonic() -> None:
    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        if os.name == 'nt':  # Windows
            run_script_cmd = 'sh deposit.sh'
        else:  # Mac or Linux
            run_script_cmd = './deposit.sh'

        install_cmd = run_script_cmd + ' install'
        proc = await asyncio.create_subprocess_shell(
            install_cmd,
        )
        await proc.wait()

        cmd_args = [
            run_script_cmd,
            '--language', 'english',
            '--non_interactive',
            'new-mnemonic',
            '--num_validators', '5',
            '--mnemonic_language', 'english',
            '--chain', 'mainnet',
            '--keystore_password', 'MyPassword',
            '--eth1_withdrawal_address', '""',
            '--folder', my_folder_path,
        ]
        proc = await asyncio.create_subprocess_shell(
            ' '.join(cmd_args),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )

        seed_phrase = ''
        parsing = False
        mnemonic_json_file = os.path.join(os.getcwd(), 'ethstaker_deposit/../ethstaker_deposit/cli/',
                                          'new_mnemonic.json')
        async for out in proc.stdout:
            output = out.decode('utf-8').rstrip()
            if output.startswith(load_text(['msg_mnemonic_presentation'], mnemonic_json_file, 'new_mnemonic')):
                parsing = True
            elif output.startswith(load_text(['msg_mnemonic_retype_prompt'], mnemonic_json_file, 'new_mnemonic')):
                parsing = False
            elif parsing:
                seed_phrase += output
                if len(seed_phrase) > 0:
                    abbreviated_mnemonic = ' '.join(abbreviate_words(seed_phrase.split(' ')))
                    encoded_phrase = abbreviated_mnemonic.encode()
                    proc.stdin.write(encoded_phrase)
                    proc.stdin.write(b'\n')

        assert len(seed_phrase) > 0

        await proc.wait()

        # Check files
        validator_keys_folder_path = os.path.join(my_folder_path, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
        _, _, key_files = next(os.walk(validator_keys_folder_path))

        all_uuid = [
            get_uuid(validator_keys_folder_path + '/' + key_file)
            for key_file in key_files
            if key_file.startswith('keystore')
        ]
        assert len(set(all_uuid)) == 5

        # Verify file permissions
        if os.name == 'posix':
            for file_name in key_files:
                assert get_permissions(validator_keys_folder_path, file_name) == '0o440'
