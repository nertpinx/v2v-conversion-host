import unittest
from wrapper.pre_copy import PreCopy


class TestPreCopy(unittest.TestCase):
    """ Tests state object, make sure it behaves like a proper singleton """

    def test_uri_parsing_one_phase(self):
        """ Nothing should happen unless two phase conversion is requested. """
        pc = PreCopy({'vmware_uri': 'esx://example.com'})
        self.assertTrue(pc is None)

    def test_uri_parsing_minimal(self):
        """ Make sure the VMWare URI is parsed correctly. """
        pc = PreCopy({
            'two_phase': True,
            'vmware_uri': 'vpx://example.com'
        })
        self.assertTrue(pc is not None)
        self.assertEqual(pc.internal.user,
                         'administrator@vsphere.local')
        self.assertEqual(pc.internal.server, 'example.com')
        self.assertEqual(pc.internal.port, None)

    def test_uri_parsing(self):
        """ Make sure the VMWare URI is parsed correctly. """
        pc = PreCopy({
            'two_phase': True,
            'vmware_uri': 'vpx://some.server:12345'
        })
        self.assertTrue(pc is not None)
        self.assertEqual(pc.internal.user,
                         'administrator@vsphere.local')
        self.assertEqual(pc.internal.server, 'some.server')
        self.assertEqual(pc.internal.port, 12345)

    def test_uri_parsing_full(self):
        """ Make sure the VMWare URI is parsed correctly. """
        pc = PreCopy({
            'two_phase': True,
            'vmware_uri': 'esx://user%40domain@some.remote.server:443'
        })
        self.assertTrue(pc is not None)
        self.assertEqual(pc.internal.user, 'user@domain')
        self.assertEqual(pc.internal.server, 'some.remote.server')
        self.assertEqual(pc.internal.port, 443)
