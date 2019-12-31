import unittest
from wrapper.pre_copy import PreCopy


class TestPreCopy(unittest.TestCase):
    """ Tests state object, make sure it behaves like a proper singleton """

    basic_data = {
        'output_format': 'raw',
        'vmware_uri': 'vpx://example.com',
        'vmware_password': '',
        'vmware_password_file': '',
        'vm_name': 'some-name',
    }

    def get_precopy(self, uri, two_phase=True):
        data = self.basic_data.copy()
        data['vmware_uri'] = uri
        data['two_phase'] = two_phase
        return PreCopy(data)

    def test_uri_parsing_one_phase(self):
        """ Nothing should happen unless two phase conversion is requested. """

        pc = self.get_precopy('esx://example.com', two_phase=False)

        self.assertTrue(pc is None)

    def test_uri_parsing_minimal(self):
        """ Make sure the VMWare URI is parsed correctly. """

        pc = self.get_precopy('vpx://example.com')

        self.assertTrue(pc is not None)
        self.assertEqual(pc.vmware.user,
                         'administrator@vsphere.local')
        self.assertEqual(pc.vmware.server, 'example.com')
        self.assertEqual(pc.vmware.port, None)

        del pc

    def test_uri_parsing(self):
        """ Make sure the VMWare URI is parsed correctly. """

        pc = self.get_precopy('vpx://some.server:12345')

        self.assertTrue(pc is not None)
        self.assertEqual(pc.vmware.user,
                         'administrator@vsphere.local')
        self.assertEqual(pc.vmware.server, 'some.server')
        self.assertEqual(pc.vmware.port, 12345)

        del pc

    def test_uri_parsing_full(self):
        """ Make sure the VMWare URI is parsed correctly. """

        pc = self.get_precopy('esx://user%40domain@some.remote.server:443')

        self.assertTrue(pc is not None)
        self.assertEqual(pc.vmware.user, 'user@domain')
        self.assertEqual(pc.vmware.server, 'some.remote.server')
        self.assertEqual(pc.vmware.port, 443)

        del pc
