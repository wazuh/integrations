#!/usr/bin/env python3

import tools

UNKNOWN_ERROR_ERRCODE = 999

class WazuhIntegrationException(Exception):
    """Class that represents an exception for the Wazuh external integrations.

    Parameters
    ----------
    error : int
        Error key.
    kwargs : str
        Values of the error message that should be substituted.
    """
    def __init__(self, errcode: int, **kwargs):
        self._errcode = errcode
        info = self.__class__.ERRORS[errcode]
        self._message = info['message'].format(**kwargs) if kwargs else \
            info['message']
        self._key = info['key']
        super().__init__(f'{self.key}: {self.message}')

    @property
    def errcode(self):
        return self._errcode

    @property
    def key(self):
        return self._key

    @property
    def message(self):
        return self._message


class WazuhIntegrationInternalError(WazuhIntegrationException):
    """Class that represents a critical exception for the Wazuh external integrations."""
    ERRORS = {
        # 1-99 -> Internal errors
        1: {
            'key': 'GCloudWazuhNotRunning',
            'message': 'Wazuh must be running'
        },
        2: {
            'key': 'GCloudSocketError',
            'message': 'Error initializing {socket_path} socket'
        },
        3: {
            'key': 'GCloudSocketSendError',
            'message': 'Error sending event to Wazuh'
        },
    }
