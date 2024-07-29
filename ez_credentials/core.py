#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'Christophe Druet'
__copyright__ = 'Copyright (c) 2024 Stoachup SRL - All rights reserved.'
__credits__ = ['Christophe Druet']
__license__ = 'MIT'
__version__ = '1.0.1'
__maintainer__ = 'Christophe Druet'
__email__ = 'christophe@stoachup.com'
__status__ = 'Dev'

import secrets
import keyring
import jwt
import getpass
import requests
import validators
from datetime import datetime, timedelta
from typing import Tuple, Dict, Optional
from yarl import URL
from loguru import logger

from .utils import URL


class Manager:
    """
    Base class to handle encoding and decoding of passwords/tokens with an expiration mechanism.

    :param service_name: The name of the service for which the manager is used.
    :type service_name: str
    """

    def __init__(self, service_name, **kwargs):
        self.service_name = service_name
        self.salt_key = f"{service_name}_salt"

        self.salt = keyring.get_password(self.service_name, self.salt_key)
        if self.salt is None:
            salt = secrets.token_hex()
            logger.debug("Salt generated.")
            try:
                keyring.set_password(self.service_name, self.salt_key, salt)
                logger.debug("New salt stored in keyring.")
            except Exception as e:
                logger.error(f"Failed to store salt in keyring: {e}")
            self.salt = salt
        else:
            logger.debug("Salt retrieved from keyring.")

        logger.debug(f"Access manager initialized for service: {self.service_name}")

    def reset_salt(self):
        """
        Reset the keyring for the service.
        """
        try:
            keyring.delete_password(self.service_name, self.salt_key)
        except keyring.errors.PasswordDeleteError:
            pass

    def _encode(self, value, expires_in):
        """
        Encode the value with an expiration date.

        :param value: The value to encode.
        :type value: str
        :param expires_in: Time in seconds for the value to expire.
        :type expires_in: int
        :return: The encoded JWT.
        :rtype: str
        """
        logger.debug(f"Encoding value with expiration in {expires_in} seconds.")
        try:
            payload = {
                'key': value,
                'exp': datetime.utcnow() + timedelta(seconds=expires_in)
            }
            encoded_jwt = jwt.encode(payload, self.salt, algorithm='HS256')
            logger.debug(f"Value encoded with expiration in {expires_in} seconds.")
            return encoded_jwt
        except jwt.InvalidKeyError as e:
            logger.error(f"Failed to encode JWT: {e}")
            return None
        except Exception as e:
            logger.exception(f"Failed to encode JWT: {e}")
            return None

    def _decode(self, encoded_key):
        """
        Decode the JWT to retrieve the value.

        :param encoded_key: The encoded JWT.
        :type encoded_key: str
        :return: The decoded value.
        :rtype: str
        """
        logger.debug("Decoding JWT.")
        try:
            payload = jwt.decode(encoded_key, self.salt, algorithms=['HS256'])
            logger.debug("JWT decoded successfully.")
            return payload['key']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.DecodeError as e:
            logger.error(f"Failed to decode JWT: {e}")
            return None


class CredentialManager(Manager):
    """
    Class to handle user credentials (username and password).

    :param service_name: The name of the service for which the manager is used.
    :type service_name: str
    """

    def __init__(self, service_name: str, **kwargs):
        Manager.__init__(self, service_name, **kwargs)
        self.credential_expires_in = kwargs.get('credential_expires_in', kwargs.get('expires_in', 30 * 24 * 60 * 60))
        self.username_key = f"{service_name}_username"
        self.password_key = f"{service_name}_password"
        logger.debug(f"CredentialManager initialized ({self.credential_expires_in}s).")

    def reset_password(self):
        """
        Reset the keyring for the password.
        """
        try:
            keyring.delete_password(self.service_name, self.password_key)
        except keyring.errors.PasswordDeleteError:
            pass

    def reset_username(self):
        """
        Reset the keyring for the username, which implies resetting the password.
        """
        self.reset_password()
        try:
            keyring.delete_password(self.service_name, self.username_key)
        except keyring.errors.PasswordDeleteError:
            pass

    reset = reset_username

    def prompt_for_username(self) -> str:
        """
        Prompt the user for a username if not already set.
        """
        return input("Userid: ")

    @property
    def username(self) -> Optional[str]:
        """
        Retrieve the stored username.

        :return: The stored username.
        :rtype: Optional[str]
        """
        logger.debug("Retrieving username from keyring.")
        username = keyring.get_password(self.service_name, self.username_key)
        if username is None:
            logger.warning("No username found. Prompting for defining one...")
            username = self.prompt_for_username()
            self.username = username

        logger.debug(f"Username retrieved: {username}.")
        return username

    @username.setter
    def username(self, value):
        """
        Set the username and delete the existing password if the username changes.

        :param value: The new username.
        :type value: str
        """
        logger.debug(f"Setting username to {value}.")
        if value != keyring.get_password(self.service_name, self.username_key):
            self.reset_password()
            logger.debug("Existing password deleted as username changed.")
        try:
            keyring.set_password(self.service_name, self.username_key, value)
            logger.debug("Username stored in keyring.")
        except Exception as e:
            logger.error(f"Failed to store username in keyring: {e}")

    def prompt_for_password(self) -> None:
        """
        Prompt the user for a password if not already set.
        """
        password = getpass.getpass("Password: ")
        logger.info("Password prompted.")
        return password

    @property
    def password(self) -> Optional[str]:
        """
        Retrieve the stored password. Prompts for a password if expired or not set.

        :return: The stored password.
        :rtype: Optional[str]
        """
        password = None
        if encoded_password := keyring.get_password(self.service_name, self.password_key):
            logger.debug("Password found in keyring.")
            password = self._decode(encoded_password)

        if password is None:
            logger.info("Password is expired or not set, prompting for new password.")
            password = self.prompt_for_password()
            self.password = password
        
        return password

    @password.setter
    def password(self, value):
        """
        Set the password, encoding it with an expiration date.

        :param value: The new password.
        :type value: str
        """
        try:
            encoded_password = self._encode(value, self.credential_expires_in)
            keyring.set_password(self.service_name, self.password_key, encoded_password)
            logger.debug("Password stored in keyring.")
        except Exception as e:
            logger.error(f"Failed to store password in keyring: {e}")

    def is_password_expired(self) -> bool:
        """
        Check if the stored password has expired.

        :return: True if the password is expired, False otherwise.
        :rtype: bool
        """
        if encoded_password := keyring.get_password(self.service_name, self.password_key):
            if self._decode(encoded_password) is None:
                logger.warning("Password is expired.")
                return True
            else:
                return False
        else:
            logger.warning("No password found in keyring.")
            return True

    is_expired = is_password_expired

    def as_dict(self) -> Dict[str, str]:
        """
        Return the credentials as a dictionary.

        :return: The credentials as dictionary.
        :rtype: Dict[str, str]
        """
        logger.debug("Returning credentials as dictionary.")
        return {'username': self.username, 'password': self.password}

    def as_tuple(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Return the credentials as a tuple.

        :return: The credentials as a tuple (username, password).
        :rtype: Tuple[Optional[str], Optional[str]]
        """
        logger.debug("Returning credentials as tuple.")
        return self.username, self.password

    def __call__(self, **kwargs) -> Tuple[Optional[str], Optional[str]] or Dict[str, str]:
        """
        Return the credentials as a tuple or dictionary.

        :param kwargs: Additional arguments to control the return format.
        :return: The credentials as a tuple (username, password) or dictionary.
        :rtype: Tuple[Optional[str], Optional[str]] or Dict[str, str]
        """
        return self.as_dict() if kwargs.get('as_dict', False) else self.as_tuple()


class TokenManager(Manager):
    """
    Class to handle tokens.

    :param service_name: The name of the service for which the manager is used.
    :type service_name: str
    """

    def __init__(self, service_name: str, **kwargs):
        Manager.__init__(self, service_name, **kwargs)
        self.token_expires_in = kwargs.get('token_expires_in', 7 * 24 * 60 * 60)
        self.token_key = f"{service_name}_token"
        logger.debug("TokenManager initialized.")

    def reset(self):
        """
        Reset the keyring for the service.
        """
        try:
            keyring.delete_password(self.service_name, self.token_key)
        except keyring.errors.PasswordDeleteError:
            pass

    def renew_token(self) -> None:
        """
        Renew the stored token.
        """
        self.token = self.seek_token()

    def seek_token(self) -> str:
        """
        Prompt the user for a token.

        :return: The token entered by the user.
        :rtype: str
        """
        token = getpass.getpass("Token: ")
        logger.info("Token prompted.")
        return token

    @property
    def token(self) -> Optional[str]:
        """
        Retrieve the stored token. Fetches a new token if expired or not set.

        :return: The stored token.
        :rtype: Optional[str]
        """
        token = None
        if encoded_token := keyring.get_password(self.service_name, self.token_key):
            token = self._decode(encoded_token)
        
        if token is None:
            logger.info("Token is expired or not set, seeking new token.")
            token = self.seek_token()
            self.token = token
        
        return token

    @token.setter
    def token(self, token):
        """
        Set the token, encoding it with an expiration date.

        :param token: The new token.
        :type token: str
        """
        try:
            keyring.set_password(self.service_name, self.token_key, self._encode(token, self.token_expires_in))
            logger.debug("Token stored in keyring.")
        except Exception as e:
            logger.error(f"Failed to store token in keyring: {e}")

    def is_token_expired(self) -> bool:
        """
        Check if the stored token has expired.

        :return: True if the token is expired, False otherwise.
        :rtype: bool
        """
        if encoded_token := keyring.get_password(self.service_name, self.token_key):
            if self._decode(encoded_token) is None:
                logger.warning("Token is expired.")
                return True
            else:
                return False
        else:
            logger.warning("No token found in keyring.")
            return True

    is_expired = is_token_expired

    def __call__(self, **kwargs) -> str or Dict[str, str]:
        """
        Return the token as a string or dictionary.

        :param kwargs: Additional arguments to control the return format.
        :return: The token as a string or dictionary.
        :rtype: str or Dict[str, str]
        """
        if kwargs.get('as_dict', False):
            logger.debug("Returning token as dictionary.")
            return {kwargs.get('with_key', 'token'): self.token}
        else:
            logger.debug("Returning token as string.")
            return self.token


PromptedTokenManager = TokenManager


class TokenCredentialManager(CredentialManager, TokenManager):
    """
    Class to handle both credentials and tokens prompted from the user.

    :param service_name: The name of the service for which the manager is used.
    :type service_name: str
    """

    def __init__(self, service_name: str, **kwargs):
        CredentialManager.__init__(self, service_name, **kwargs)
        PromptedTokenManager.__init__(self, service_name, **kwargs)
        logger.debug("PromptedTokenCredentialManager initialized.")

    def reset(self):
        """
        Reset the keyring for the service.
        """
        CredentialManager.reset(self)
        PromptedTokenManager.reset(self)

    def __call__(self, **kwargs) -> Tuple[Optional[str], Optional[str]] or str or Dict[str, str]:
        """
        Return credentials or token based on expiration and input parameters.

        :param kwargs: Additional arguments to control the return format.
        :return: The credentials or token.
        :rtype: Tuple[Optional[str], Optional[str]] or str or Dict[str, str]
        """
        if self.is_password_expired() or kwargs.get('credentials', False):
            logger.debug("Password is expired or credentials requested, returning credentials.")
            return CredentialManager.__call__(self, **kwargs)
        else:
            logger.debug("Returning token.")
            return PromptedTokenManager.__call__(self, **kwargs)


PromptedTokenCredentialManager = TokenCredentialManager


class WebServiceTokenManager(TokenManager):
    """
    Class to handle tokens fetched from a web service.

    :param service_name: The name of the service for which the manager is used.
    :type service_name: str
    :param login_url: The URL for the web service login.
    :type login_url: str
    """

    def __init__(self, service_name: str, **kwargs):
        super().__init__(service_name, **kwargs)

        self.url = URL(kwargs.get('url'))
        self.path = kwargs.get('path', 'login')
        self.params = kwargs.get('params', {'format': 'json'})
        self.headers = kwargs.get('headers', {'Content-Type': 'application/json', 'Accept': 'application/json'})

        self.session = requests.Session()

        logger.debug(f"WebServiceTokenManager initialized with login URL: {self.url}")

    def prompt_for_credentials(self) -> Tuple[str, str]:
        """
        Retrieve credentials using the parent class methods.

        :return: The username and password.
        :rtype: Tuple[str, str]
        """
        username = input('Userid: ')
        password = getpass.getpass('Password: ')
        return username, password


    def fetch_token(self) -> str:
        """
        Fetch a token from the web service using the provided credentials.

        :return: The fetched token.
        :rtype: str
        :raises ValueError: If fetching the token fails.
        """
        username, password = self.prompt_for_credentials()

        if not username or not password:
            logger.error("Username or password is not set.")
            raise ValueError("Username or password is not set.")

        try:
            logger.debug('Fetching token from web service...')
            response = self.session.post(
                self.url / self.path,
                json={'username': username, 'password': password},
                params=self.params,
                headers=self.headers
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 400:
                logger.debug(e)
                logger.error("Invalid username or password.")
                raise
            elif response.status_code == 403:
                logger.debug(e)
                logger.error("Account may have been blocked.")
                raise
            else:
                logger.exception(f"HTTP error occurred: {e}")
                raise

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch token from web service: {e}")
            raise ValueError("Failed to fetch token from web service.") from e

        logger.debug("Token fetched from web service.")
        token = self.process_response_to_get_token(response.json())
        return token

    def process_response_to_get_token(self, data) -> str:
        return data.get('token')

    def seek_token(self) -> str:
        token = self.fetch_token()
        logger.info("Token fetched using seek_token.")
        return token


class WebServiceTokenCredentialManager(CredentialManager, WebServiceTokenManager):
    """
    Class to handle credentials and tokens with web service fetching.

    :param service_name: The name of the service for which the manager is used.
    :type service_name: str
    """

    def __init__(self, service_name: str, **kwargs):
        CredentialManager.__init__(self, service_name, **kwargs)
        WebServiceTokenManager.__init__(self, service_name, **kwargs)
        logger.debug("WebServiceTokenCredentialManager initialized.")

    def reset(self):
        """
        Reset the keyring for the service.
        """
        CredentialManager.reset(self)
        WebServiceTokenManager.reset(self)

    def prompt_for_credentials(self) -> Tuple[str, str]:
        """
        Retrieve credentials using the parent class methods.

        :return: The username and password.
        :rtype: Tuple[str, str]
        """
        return self.username, self.password

    def is_expired(self) -> bool:
        """
        Check if either the password or token is expired.

        :return: True if either the password or token is expired, False otherwise.
        :rtype: bool
        """
        expired = WebServiceTokenManager.is_token_expired(self) or CredentialManager.is_password_expired(self)
        logger.debug(f"Checked expiration status: {expired}")
        return expired

    def __call__(self, **kwargs) -> str or Dict[str, str]:
        """
        Return token and get a new one if needed.

        :param kwargs: Additional arguments to control the return format.
        :return: The credentials or token.
        :rtype: str or Dict[str, str]
        """
        logger.debug("Returning token.")
        return WebServiceTokenManager.__call__(self, **kwargs)


# Usage example
if __name__ == "__main__":
    service_name = "my_service"
    token_url = "https://example.com/api"
    manager = WebServiceTokenCredentialManager(service_name, token_expires_in=60*60, url=token_url, path='token')

    # Set the username and password initially
    manager.username = "my_username"
    manager.password = "test"

    # Get the credentials, will prompt if expired
    credentials = manager(credentials=True, as_dict=True)
    logger.info(f"Current credentials: {credentials}")

    # Get the token, will fetch from web service if expired
    token = manager(as_dict=True, with_key='accessKey')
    logger.info(f"Current token: {token}")
