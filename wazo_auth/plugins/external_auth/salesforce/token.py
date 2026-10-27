# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

EXPIRATION_MARGIN = 30


def is_expired(token_expiration, now):
    if token_expiration is None:
        return True
    return now + EXPIRATION_MARGIN > token_expiration


def new_link(token_data, lifetime, now):
    return {
        'access_token': token_data['access_token'],
        'refresh_token': token_data.get('refresh_token'),
        'token_expiration': _expiration(token_data, lifetime, now),
        'scope': _scope_text(token_data.get('scope')),
        'instance_url': token_data.get('instance_url'),
    }


def refreshed_link(link, token_data, lifetime, now):
    return {
        **link,
        'access_token': token_data['access_token'],
        'refresh_token': token_data.get('refresh_token') or link.get('refresh_token'),
        'token_expiration': _expiration(token_data, lifetime, now),
        'scope': _scope_text(token_data.get('scope')) or link.get('scope'),
        'instance_url': token_data.get('instance_url') or link.get('instance_url'),
    }


def _expiration(token_data, lifetime, now):
    # Salesforce sends no expires_in: the lifetime comes from the config
    return int(now + token_data.get('expires_in', lifetime))


def _scope_text(scope):
    if isinstance(scope, list):
        return ' '.join(scope)
    return scope
