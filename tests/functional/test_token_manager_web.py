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
def test_fetch_token_success(mock_post, web_service_token_manager):
    """
    Test fetching a token successfully from the web service.
    """
    # Mock the response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'token': 'test_web_token'}
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    # Mock prompt_for_credentials to avoid user input
    with patch.object(web_service_token_manager, 'prompt_for_credentials', return_value=('user', 'pass')):
        token = web_service_token_manager.fetch_token()

    assert token == 'test_web_token'

@patch('requests.Session.post')
def test_fetch_token_invalid_credentials(mock_post, web_service_token_manager):
    """
    Test handling of token fetching failure from the web service with invalid credentials.
    """
    # Mock the response
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Bad Request")
    mock_post.return_value = mock_response

    # Mock prompt_for_credentials to avoid user input
    with patch.object(web_service_token_manager, 'prompt_for_credentials', return_value=('user', 'wrong_pass')):
        with pytest.raises(requests.exceptions.HTTPError, match="Bad Request"):
            web_service_token_manager.fetch_token()

@patch('requests.Session.post')
def test_fetch_token_failure(mock_post, web_service_token_manager):
    """
    Test handling of token fetching failure from the web service.
    """
    # Mock the response
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Forbidden")
    mock_post.return_value = mock_response

    # Mock prompt_for_credentials to avoid user input
    with patch.object(web_service_token_manager, 'prompt_for_credentials', return_value=('user', 'pass')):
        with pytest.raises(requests.exceptions.HTTPError, match="Forbidden"):
            web_service_token_manager.fetch_token()

@patch('requests.Session.post')
def test_fetch_token_server_error(mock_post, web_service_token_manager):
    """
    Test handling of token fetching failure because of another issue
    """
    # Mock the response
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Internal Server Error")
    mock_post.return_value = mock_response

    # Mock prompt_for_credentials to avoid user input
    with patch.object(web_service_token_manager, 'prompt_for_credentials', return_value=('user', 'wrong_pass')):
        with pytest.raises(requests.exceptions.HTTPError, match="Internal Server Error"):
            web_service_token_manager.fetch_token()


def test_process_response_to_get_token(web_service_token_manager):
    # Test the response processing method
    response_data = {'token': 'processed_token'}
    token = web_service_token_manager.process_response_to_get_token(response_data)

    assert token == 'processed_token'

@patch('builtins.input', return_value='test_user')
@patch('getpass.getpass', return_value='test_password')
def test_prompt_for_credentials(mock_getpass, mock_input, web_service_token_manager):
    username, password = web_service_token_manager.prompt_for_credentials()

    assert username == 'test_user'
    assert password == 'test_password'