#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'Christophe Druet'
__copyright__ = "Copyright (c) 2024 Stoachup SRL - All rights reserved."
__credits__ = ['Christophe Druet']
__license__ = 'MIT'
__version__ = '1.2.0'
__maintainer__ = 'Christophe Druet'
__email__ = 'christophe@stoachup.com'
__status__ = 'Dev'

import pytest
import requests
import keyring

@pytest.fixture
def service_name():
    return "test_service"

@pytest.fixture
def credential_manager(service_name):
    from ez_credentials import CredentialManager
    return CredentialManager(service_name)

@pytest.fixture
def token_manager(service_name):
    from ez_credentials import TokenManager
    return TokenManager(service_name)

@pytest.fixture
def prompted_token_manager(service_name):
    from ez_credentials import PromptedTokenManager
    return PromptedTokenManager(service_name)

@pytest.fixture
def prompted_token_credential_manager(service_name):
    from ez_credentials import PromptedTokenCredentialManager
    return PromptedTokenCredentialManager(service_name)

@pytest.fixture
def web_service_token_manager(service_name):
    from ez_credentials import WebServiceTokenManager
    return WebServiceTokenManager(service_name, url="https://example.com/api/token")

@pytest.fixture
def web_service_token_credential_manager(service_name):
    from ez_credentials import WebServiceTokenCredentialManager
    return WebServiceTokenCredentialManager(service_name, url="https://example.com/api/token")
