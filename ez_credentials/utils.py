#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'Christophe Druet'
__copyright__ = "Copyright (c) 2023 ENTSO-E AISBL - All rights reserved."
__credits__ = ['Christophe Druet']
__license__ = 'MIT'
__version__ = '1.0.0'
__maintainer__ = 'Christophe Druet'
__email__ = 'christophe.druet@entsoe.com'
__status__ = 'Dev'

import validators
import yarl

from loguru import logger


def URL(url: str):
    if not validators.url(url):
        logger.exception(f'Base URL "{url}" is not valid')
        raise ValueError(f'Base URL "{url}" is not valid')
    else:
        logger.debug(f'URL: {url} OK')
    
    return yarl.URL(url)
