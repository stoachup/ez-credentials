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


def test_set_get_token(token_manager):
    token_manager.token = "test_token"
    assert token_manager.token == "test_token"

def test_is_token_expired(token_manager):
    # Set a known password
    token_manager.token_expires_in = 1
    token_manager.token = "test_token"
    
    # Initially, the password should not be expired
    assert not token_manager.is_token_expired()
    sleep(1)
    assert token_manager.is_token_expired()
