import os

from tempfile import TemporaryDirectory

from click.testing import CliRunner

from ethstaker_deposit.credentials import Credential
from ethstaker_deposit.deposit import cli
from ethstaker_deposit.settings import get_chain_setting
from ethstaker_deposit.utils.constants import DEFAULT_EXIT_TRANSACTION_FOLDER_NAME
from ethstaker_deposit.utils.intl import (
    load_text,
)
from tests.test_cli.helpers import (
    read_json_file,
    verify_file_permission,
)


def test_exit_transaction_keystore() -> None:
    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        exit_transaction_folder_path = os.path.join(my_folder_path, DEFAULT_EXIT_TRANSACTION_FOLDER_NAME)
        os.mkdir(exit_transaction_folder_path)

        # Shared parameters
        chain = 'mainnet'
        keystore_password = 'solo-stakers'

        # Prepare credential
        credential = Credential(
            mnemonic='aban aban aban aban aban aban aban aban aban aban aban abou',
            mnemonic_password='',
            index=0,
            amount=0,
            chain_setting=get_chain_setting(chain),
            hex_eth1_withdrawal_address=None
        )

        # Save keystore file
        keystore_filepath = credential.save_signing_keystore(keystore_password, exit_transaction_folder_path)

        runner = CliRunner()
        arguments = [
            '--language', 'english',
            '--non_interactive',
            'exit-transaction-keystore',
            '--output_folder', my_folder_path,
            '--chain', chain,
            '--keystore', keystore_filepath,
            '--keystore_password', keystore_password,
            '--validator_index', '1',
            '--epoch', '1234',
        ]
        result = runner.invoke(cli, arguments)

        assert result.exit_code == 0

        # Check files
        _, _, exit_transaction_files = next(os.walk(exit_transaction_folder_path))

        # Filter files to signed_exit as keystore file will exist as well
        exit_transaction_file = [f for f in exit_transaction_files if 'signed_exit' in f]

        assert len(set(exit_transaction_file)) == 1

        json_data = read_json_file(exit_transaction_folder_path, exit_transaction_file[0])

        # Verify file content
        assert json_data['message']['epoch'] == '1234'
        assert json_data['message']['validator_index'] == '1'
        assert json_data['signature']

        # Verify file permissions
        verify_file_permission(os, folder_path=exit_transaction_folder_path, files=exit_transaction_file)


def test_exit_transaction_with_pbkdf2() -> None:
    # Prepare folder
    with TemporaryDirectory() as pbkdf2_folder_path, TemporaryDirectory() as scrypt_folder_path:

        pbkdf2_exit_transaction_folder_path = os.path.join(pbkdf2_folder_path, DEFAULT_EXIT_TRANSACTION_FOLDER_NAME)
        scrypt_exit_transaction_folder_path = os.path.join(scrypt_folder_path, DEFAULT_EXIT_TRANSACTION_FOLDER_NAME)
        os.mkdir(pbkdf2_exit_transaction_folder_path)
        os.mkdir(scrypt_exit_transaction_folder_path)

        # Shared parameters
        chain = 'mainnet'
        keystore_password = 'solo-stakers'

        # Prepare credential
        pbkdf2_credential = Credential(
            mnemonic='aban aban aban aban aban aban aban aban aban aban aban abou',
            mnemonic_password='',
            index=0,
            amount=0,
            chain_setting=get_chain_setting(chain),
            hex_eth1_withdrawal_address=None,
            use_pbkdf2=True,
        )
        scrypt_credential = Credential(
            mnemonic='aban aban aban aban aban aban aban aban aban aban aban abou',
            mnemonic_password='',
            index=0,
            amount=0,
            chain_setting=get_chain_setting(chain),
            hex_eth1_withdrawal_address=None,
            use_pbkdf2=False,
        )

        # Save keystore file
        pbkdf2_keystore_filepath = pbkdf2_credential.save_signing_keystore(
            keystore_password,
            pbkdf2_exit_transaction_folder_path,
        )
        scrypt_keystore_filepath = scrypt_credential.save_signing_keystore(
            keystore_password,
            scrypt_exit_transaction_folder_path,
        )

        runner = CliRunner()
        arguments = [
            '--language', 'english',
            '--non_interactive',
            'exit-transaction-keystore',
            '--output_folder', pbkdf2_folder_path,
            '--chain', chain,
            '--keystore', pbkdf2_keystore_filepath,
            '--keystore_password', keystore_password,
            '--validator_index', '1',
            '--epoch', '1234',
        ]
        result = runner.invoke(cli, arguments)
        assert result.exit_code == 0

        arguments = [
            '--language', 'english',
            '--non_interactive',
            'exit-transaction-keystore',
            '--output_folder', scrypt_folder_path,
            '--chain', chain,
            '--keystore', scrypt_keystore_filepath,
            '--keystore_password', keystore_password,
            '--validator_index', '1',
            '--epoch', '1234',
        ]
        result = runner.invoke(cli, arguments)
        assert result.exit_code == 0

        # Check files
        _, _, exit_transaction_files = next(os.walk(pbkdf2_exit_transaction_folder_path))
        pbkdf2_exit_transaction_file = [f for f in exit_transaction_files if 'signed_exit' in f]
        assert len(set(pbkdf2_exit_transaction_file)) == 1
        pbkdf2_json_data = read_json_file(pbkdf2_exit_transaction_folder_path, pbkdf2_exit_transaction_file[0])

        _, _, exit_transaction_files = next(os.walk(scrypt_exit_transaction_folder_path))
        scrypt_exit_transaction_file = [f for f in exit_transaction_files if 'signed_exit' in f]
        assert len(set(scrypt_exit_transaction_file)) == 1
        scrypt_json_data = read_json_file(scrypt_exit_transaction_folder_path, scrypt_exit_transaction_file[0])

        assert pbkdf2_json_data['message']['epoch'] == scrypt_json_data['message']['epoch']
        assert pbkdf2_json_data['message']['validator_index'] == scrypt_json_data['message']['validator_index']
        assert pbkdf2_json_data['signature'] == scrypt_json_data['signature']

        verify_file_permission(os, folder_path=pbkdf2_exit_transaction_folder_path, files=pbkdf2_exit_transaction_file)
        verify_file_permission(os, folder_path=scrypt_exit_transaction_folder_path, files=scrypt_exit_transaction_file)


def test_invalid_keystore_path() -> None:
    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        invalid_keystore_file = os.path.join(os.getcwd(), 'README.md')

        runner = CliRunner()
        inputs = []
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            '--non_interactive',
            'exit-transaction-keystore',
            '--output_folder', my_folder_path,
            '--chain', "mainnet",
            '--keystore', invalid_keystore_file,
            '--keystore_password', "password",
            '--validator_index', '1',
            '--epoch', '1234',
        ]
        result = runner.invoke(cli, arguments, input=data)

        assert result.exit_code != 0


def test_invalid_keystore_file() -> None:
    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        runner = CliRunner()
        inputs = []
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            '--non_interactive',
            'exit-transaction-keystore',
            '--output_folder', my_folder_path,
            '--chain', "mainnet",
            '--keystore', "invalid_keystore_path",
            '--keystore_password', "password",
            '--validator_index', '1',
            '--epoch', '1234',
        ]
        result = runner.invoke(cli, arguments, input=data)

        assert result.exit_code != 0


def test_invalid_keystore_password() -> None:
    # Prepare folder
    with TemporaryDirectory() as my_folder_path:

        exit_transaction_folder_path = os.path.join(my_folder_path, DEFAULT_EXIT_TRANSACTION_FOLDER_NAME)
        os.mkdir(exit_transaction_folder_path)

        # Shared parameters
        chain = 'mainnet'
        keystore_password = 'solo-stakers'

        # Prepare credential
        credential = Credential(
            mnemonic='aban aban aban aban aban aban aban aban aban aban aban abou',
            mnemonic_password='',
            index=0,
            amount=0,
            chain_setting=get_chain_setting(chain),
            hex_eth1_withdrawal_address=None
        )

        # Save keystore file
        keystore_filepath = credential.save_signing_keystore(keystore_password, exit_transaction_folder_path)
        runner = CliRunner()
        inputs = []
        data = '\n'.join(inputs)
        arguments = [
            '--language', 'english',
            '--non_interactive',
            'exit-transaction-keystore',
            '--output_folder', my_folder_path,
            '--chain', chain,
            '--keystore', keystore_filepath,
            '--keystore_password', "incorrect_password",
            '--validator_index', '1',
            '--epoch', '1234',
        ]
        result = runner.invoke(cli, arguments, input=data)

        assert result.exit_code != 0

        mnemonic_json_file = os.path.join(os.getcwd(), 'ethstaker_deposit/cli/', 'exit_transaction_keystore.json')
        assert load_text(
            ['arg_exit_transaction_keystore_keystore_password', 'mismatch'],
            mnemonic_json_file,
            'exit_transaction_keystore'
        ) in result.output
