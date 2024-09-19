import subprocess
import os
import sys
import shutil
import click


def clear_terminal() -> None:
    # We bundle libtinfo via pyinstaller, which messes with the system tput.
    # Remove LD_LIBRARY_PATH just for subprocess.run()
    if sys.platform == 'linux':
        clean_env = os.environ.copy()
        clean_env.pop('LD_LIBRARY_PATH', None)
    if sys.platform == 'win32':
        # Special-case for asyncio pytest on Windows
        if os.getenv("IS_ASYNC_TEST") == "1":
            click.clear()
        elif shutil.which('clear'):
            subprocess.run(['clear'])
        else:
            subprocess.run('cls', shell=True)
    elif sys.platform == 'linux' or sys.platform == 'darwin':
        if shutil.which('tput'):
            subprocess.run(['tput', 'reset'], env=clean_env)
        elif shutil.which('reset'):
            subprocess.run(['reset'], env=clean_env)
        elif shutil.which('clear'):
            subprocess.run(['clear'], env=clean_env)
        else:
            click.clear()
    else:
        click.clear()
