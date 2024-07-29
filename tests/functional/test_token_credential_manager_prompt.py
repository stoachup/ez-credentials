#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'Christophe Druet'
__copyright__ = "Copyright (c) 2024 Stoachup SRL - All rights reserved."
__credits__ = ['Christophe Druet']
__license__ = 'MIT'
__version__ = '0.0.1'
__maintainer__ = 'Christophe Druet'
__email__ = 'christophe@stoachup.com'
__status__ = 'Dev'

import pytest
from unittest.mock import patch
from time import sleep


def test_prompt_for_new_token_when_token_expired(prompted_token_credential_manager):
    # Set a known password and expire it
    prompted_token_credential_manager.username = "test_user"
    prompted_token_credential_manager.password = "initial_pass"
    prompted_token_credential_manager.token_expires_in = 1
    prompted_token_credential_manager.token = "initial_token" 

    sleep(1)
    
    # Mock input and getpass.getpass to simulate user entering new credentials
    with patch('getpass.getpass', return_value="new_token") as mock_getpass:

        # Call the Manager to prompt for credentials
        username, password = prompted_token_credential_manager(credentials=True)
        token = prompted_token_credential_manager()

        # Verify that it prompted for the new password
        mock_getpass.assert_called_once_with("Token: ")

        # Verify that the new credentials were set correctly
        assert username == "test_user"
        assert password == "initial_pass"
        assert token == "new_token"
        assert prompted_token_credential_manager.username == "test_user"
        assert prompted_token_credential_manager.password == "initial_pass"
        assert prompted_token_credential_manager.token == "new_token"


def test_prompt_for_new_password_when_password_expired(prompted_token_credential_manager):
    # Set a known password and expire it
    prompted_token_credential_manager.username = "test_user"
    prompted_token_credential_manager.credential_expires_in = 1
    prompted_token_credential_manager.password = "initial_pass"
    prompted_token_credential_manager.token = "initial_token"

    sleep(1)
    
    # Mock input and getpass.getpass to simulate user entering new credentials
    with patch('getpass.getpass', return_value="new_pass") as mock_getpass:

        # Call the Manager to prompt for credentials
        username, password = prompted_token_credential_manager()
        token = prompted_token_credential_manager()

        # Verify that it prompted for the new password
        mock_getpass.assert_called_once_with("Password: ")

        # Verify that the new credentials were set correctly
        assert username == "test_user"
        assert password == "new_pass"
        assert token == "initial_token"
        assert prompted_token_credential_manager.username == "test_user"
        assert prompted_token_credential_manager.password == "new_pass"
        assert prompted_token_credential_manager.token == "initial_token"
