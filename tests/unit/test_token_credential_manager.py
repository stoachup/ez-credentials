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
from time import sleep


def test_is_expiration_chain(prompted_token_credential_manager):
    # Set a known password
    prompted_token_credential_manager.credential_expires_in = 2
    prompted_token_credential_manager.password = "test_pass"
    prompted_token_credential_manager.token_expires_in = 1
    prompted_token_credential_manager.token ="test_token"
    
    # Initially, the password should not be expired
    assert not prompted_token_credential_manager.is_token_expired()
    sleep(1)
    assert not prompted_token_credential_manager.is_password_expired()
    assert prompted_token_credential_manager.is_token_expired()
    sleep(1)
    assert prompted_token_credential_manager.is_password_expired()

