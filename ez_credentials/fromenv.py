#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'Christophe Druet'
__copyright__ = "Copyright (c) 2024- Stoachup SRL - All rights reserved."
__credits__ = ['Christophe Druet']
__license__ = 'MIT'
__version__ = '1.2.1'
__maintainer__ = 'Christophe Druet'
__email__ = 'christophe@stoachup.com'
__status__ = 'Prod'

"""
This Python script is designed to securely manage and store encrypted tokens containing key-value pairs in a `.env` file. 

Below is a brief breakdown of the main functions and what they do:

1. **Environment and Dependencies**:
   - The script imports several modules: `os`, `re`, `jwt`, `secrets`, and `python-dotenv`.
   - It uses `python-dotenv` to manage environment variables and `jwt` for encoding and decoding JSON Web Tokens (JWTs).
   - It uses `loguru` for logging messages during execution.

2. **Functions**:
   - **`_load_dotenv(salt: str = secrets.token_hex())`**:
     - This function loads environment variables from a `.env` file, either in the user's home directory or the current working directory.
     - If a specific environment variable (`PERSAULT`) is not found, it generates a new salt using the `secrets` module and updates the `.env` file with this new salt.

   - **`_update_dotenv(file_path: str, regexp: str, subs: str | None = None, count=0, flags=0)`**:
     - This function updates the `.env` file by replacing or removing specific lines based on a regular expression. It ensures that the file is updated only if necessary and that its permissions are securely set (readable and writable only by the owner).

   - **`set_password(service_name: str, key: str, value)`**:
     - This function sets or updates a key-value pair for a specific service in the `.env` file.
     - It first loads the existing token, if any, decrypts it using the salt from the environment variable (`PERSAULT`), updates the token with the new key-value pair, re-encrypts it, and then updates the `.env` file.

   - **`get_password(service_name: str, key: str) -> Optional[str]`**:
     - This function retrieves the value of a specified key from the decrypted token associated with a service.
     - If the token is expired or invalid, or if the key is not found, appropriate warnings are logged.

   - **`delete_password(service_name: str, key: str)`**:
     - This function deletes a key-value pair from the token associated with a service.
     - After deleting the key, it re-encrypts the remaining data and updates the `.env` file. If the token becomes empty after deletion, it removes the token from the `.env` file.

3. **Security Measures**:
   - The script includes several security measures:
     - Environment variables are managed securely using `.env` files.
     - JWTs are used to encrypt sensitive data, ensuring that key-value pairs are stored securely.
     - File permissions for the `.env` file are set to restrict access.

4. **Usage**:
   - This script can be used for managing service credentials or any other sensitive key-value pairs securely within a project, particularly when working with multiple services that require secure storage of API keys, passwords, or other secrets.
"""

import os
import re
import jwt
import secrets
import dotenv
from typing import Optional
from loguru import logger

def _load_dotenv(salt: str = secrets.token_hex()):
    """
    Load environment variables from `.env` files. If no salt is found in the environment, 
    a new one is generated and saved to the `.env` file.

    :param salt: A hex string used as the salt for encryption, defaults to a new random value.
    :type salt: str, optional
    """
    dotenv_path = os.path.join((os.getenv('HOME') or os.getenv('HOMEPATH')), '.env')
    if os.path.exists(dotenv_path):
        dotenv.load_dotenv(dotenv_path)

    if not os.getenv('PERSAULT'):
        logger.warning('No salt defined in ~/.env. Defining one...')
        _update_dotenv(dotenv_path, 
            r'^PERSAULT\\s*=\\s\'?.+\'?$',
            f"PERSAULT={salt}",
            count=1)
        dotenv.load_dotenv(dotenv_path, override=True)

    dotenv_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(dotenv_path):
        dotenv.load_dotenv(dotenv_path, override=True)


def _update_dotenv(file_path: str, regexp: str, subs: Optional[str] = None, count=0, flags=0):
    """
    Update or create a `.env` file by replacing lines that match a regular expression.

    :param file_path: Path to the `.env` file.
    :type file_path: str
    :param regexp: Regular expression pattern to search for in the file.
    :type regexp: str
    :param subs: Replacement string. If None, matching lines will be removed.
    :type subs: str, optional
    :param count: Maximum number of pattern occurrences to replace, defaults to 0 (replace all).
    :type count: int, optional
    :param flags: Regex flags to modify the behavior of the pattern matching.
    :type flags: int, optional
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    if os.path.exists(file_path):
        with open(file_path, "r+") as file:
            new_contents = None
            if subs is None:
                file_contents = file.readlines()
                new_contents = [line for line in file_contents if not re.search(regexp, line, flags=flags)]
            else:
                file_contents = file.read()
                new_contents = re.sub(regexp, subs, file_contents, count=count, flags=flags)
            
            if file_contents != new_contents:
                file.seek(0)
                file.truncate()
                file.write(new_contents)
                logger.debug(f'{file_path} has been updated')
            else:
                logger.debug(f'No changes made to {file_path}')
    else:
        with open(file_path, "w") as file:
            file.write(subs)
        logger.debug(f'{file_path} has been created')
    
    os.chmod(file_path, 0o0600)


def set_password(service_name: str, key: str, value):
    """
    Set or update a key-value pair for a given service in the `.env` file, securely stored as a JWT.

    :param service_name: Name of the service for which the credentials are being set.
    :type service_name: str
    :param key: The key for the credential (e.g., 'username', 'password').
    :type key: str
    :param value: The value associated with the key.
    :type value: Any
    """
    _load_dotenv()

    old_token = {}
    try:
        token = os.getenv(service_name.upper(), None)
        old_token = jwt.decode(token, os.getenv('PERSAULT'), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        pass
    except jwt.exceptions.InvalidTokenError:
        pass

    enc_token = jwt.encode(old_token | {key: value}, os.getenv('PERSAULT'), algorithm='HS256')

    _update_dotenv(os.path.join(os.getcwd(), '.env'), 
        fr'{service_name.upper()}={os.getenv(service_name.upper())}', 
        f'{service_name.upper()}={enc_token}', 
        count=1)


def get_password(service_name: str, key: str) -> Optional[str]:
    """
    Retrieve the value of a specified key from the decrypted token associated with a service.

    :param service_name: Name of the service for which the credentials are being retrieved.
    :type service_name: str
    :param key: The key for which the value is to be retrieved.
    :type key: str
    :return: The value associated with the key, or None if not found or token is invalid/expired.
    :rtype: Optional[str]
    """
    _load_dotenv()
    try:
        token = os.getenv(service_name.upper(), None)
        decrypted_token = jwt.decode(token, os.getenv('PERSAULT'), algorithms=['HS256'])
        if not decrypted_token.get(key, None):
            logger.warning(f'No value found for "{key}"')
            return None
        return decrypted_token[key]

    except jwt.ExpiredSignatureError:
        logger.warning('Expired token.')
        return None
    except jwt.exceptions.InvalidTokenError:
        logger.warning('Invalid token.')
        return None


def delete_password(service_name: str, key: str):
    """
    Delete a key-value pair from the token associated with a service and update the `.env` file.

    :param service_name: Name of the service from which the credentials are being deleted.
    :type service_name: str
    :param key: The key for the credential to be deleted.
    :type key: str
    """
    _load_dotenv()
    try:
        token = os.getenv(service_name.upper(), None)
        decrypted_token = jwt.decode(token, os.getenv('PERSAULT'), algorithms=['HS256'])
        decrypted_token.pop(key, None)
        enc_token = jwt.encode(decrypted_token, os.getenv('PERSAULT'), algorithm='HS256')
        _update_dotenv(os.path.join(os.getcwd(), '.env'), 
            fr'{service_name.upper()}={token}', 
            subs=f'{service_name.upper()}={enc_token}' if decrypted_token else None, 
            count=1)

    except jwt.ExpiredSignatureError:
        logger.warning('Expired token.')
        return None
    except jwt.exceptions.InvalidTokenError:
        logger.warning('Invalid token.')
        return None