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


def test_prompt_for_new_password_when_expired(credential_manager):
    # Set a known password and expire it
    credential_manager.username = "test_user"
    credential_manager.credential_expires_in = 1
    credential_manager.password = "initial_pass"

    sleep(1)
    
    # Mock input and getpass.getpass to simulate user entering new credentials
    with patch('getpass.getpass', return_value="new_pass") as mock_getpass:

        # Call the CredentialManager to get the credentials
        username, password = credential_manager()

        # Verify that it prompted for the new password
        mock_getpass.assert_called_once_with("Password: ")

        # Verify that the new credentials were set correctly
        assert username == "test_user"
        assert password == "new_pass"
        assert credential_manager.username == "test_user"
        assert credential_manager.password == "new_pass"
