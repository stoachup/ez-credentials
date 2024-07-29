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


def test_set_get_username(credential_manager):
    credential_manager.username = "test_user"
    assert credential_manager.username == "test_user"

def test_set_get_password(credential_manager):
    credential_manager.password = "test_pass"
    assert credential_manager.password == "test_pass"

def test_is_password_expired(credential_manager):
    # Set a known password
    credential_manager.credential_expires_in = 1
    credential_manager.password = "test_pass"
    
    # Initially, the password should not be expired
    assert not credential_manager.is_password_expired()
    sleep(1)
    assert credential_manager.is_password_expired()
