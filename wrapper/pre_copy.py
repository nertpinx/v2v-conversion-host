"All helpers needed to handle copying data prom VMWare"

from six.moves.urllib.parse import urlparse, unquote

from .state import StateObject


class _PreCopyInternal(object):
    __slots__ = [
        'server',
        'user',
        'port',
    ]

    def __init__(self, data):
        uri = urlparse(data['vmware_uri'])

        self.server = uri.hostname
        self.port = uri.port
        self.user = 'administrator@vsphere.local'
        if uri.username:
            self.user = unquote(uri.username)


class PreCopy(StateObject):
    __slots__ = [
        'internal',
    ]

    _hidden = [
        'data',
    ]

    @staticmethod
    def __new__(cls, data):
        if not data.get('two_phase', False):
            return None
        return super(PreCopy, cls).__new__(cls)

    def __init__(self, data):
        self.internal = _PreCopyInternal(data)
        self.data = data
