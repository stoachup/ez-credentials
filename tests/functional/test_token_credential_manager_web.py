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
from unittest.mock import patch, MagicMock
import requests


@patch('requests.Session.post')
def test_fetch_token_success(mock_post, web_service_token_credential_manager):
    """
    Test fetching a token successfully from the web service.
    """
    # Mock the response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'token': 'test_web_token'}
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    with patch.object(web_service_token_credential_manager, 'prompt_for_credentials', return_value=('user', 'pass')):
        # Perform token fetch
        token = web_service_token_credential_manager.fetch_token()

    assert token == 'test_web_token'

@patch('requests.Session.post')
def test_fetch_token_failure(mock_post, web_service_token_credential_manager):
    """
    Test handling of token fetching failure from the web service.
    """
    # Mock the response
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Bad Request")
    mock_post.return_value = mock_response

    with patch.object(web_service_token_credential_manager, 'prompt_for_credentials', return_value=('user', 'wrong_pass')):
        with pytest.raises(requests.exceptions.HTTPError, match="Bad Request"):
            web_service_token_credential_manager.fetch_token()
