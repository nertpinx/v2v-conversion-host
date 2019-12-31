"All helpers needed to handle copying data prom VMWare"

import os
import libvirt
import logging
import six
import stat
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ETree

from collections import OrderedDict
from six.moves.urllib.parse import urlparse, unquote
from pyVim.connect import SmartConnect, SmartConnectNoSSL, Disconnect
from pyVmomi import vim  # pylint: disable=no-name-in-module; dynamic module

from .state import STATE, StateObject
from .common import VDDK_LIBDIR, VDDK_LIBRARY_PATH, error
from .common import add_perms_to_file, nbd_uri_from_unix_socket


_TIMEOUT = 10
# TODO: [py2] Remove the line and use DEVNULL from subprocess directly
_DEVNULL = getattr(subprocess, 'DEVNULL', open(os.devnull, 'r+'))


class _VMWare(object):
    __slots__ = [
        'server',
        'user',
        '_password',
        'password_file',
        'port',
        '_conn',
        'insecure',
        'thumbprint',
        '_uri',
        '_vm',
        '_vm_name',
    ]

    def __init__(self, data):
        self._uri = data['vmware_uri']
        uri = urlparse(self._uri)

        self.server = uri.hostname
        self.port = uri.port
        self.user = 'administrator@vsphere.local'
        self._password = data['vmware_password']
        self.thumbprint = data.get('vmware_thumbprint')
        if uri.username:
            self.user = unquote(uri.username)

        self.insecure = data.get('insecure_connection', False)

        self._conn = None
        self._vm = None
        self._vm_name = data['vm_name']

    def _connect(self):
        "Connect to the remote VMWare server"

        if self._conn:
            return

        connect_args = {
            'host': self.server,
            'user': self.user,
            'pwd': self._password,
        }
        if self.port is not None:
            connect_args['port'] = self.port
        if self.thumbprint is not None:
            connect_args['thumbprint'] = self.thumbprint

        if self.insecure:
            self._conn = SmartConnectNoSSL(**connect_args)
        self._conn = SmartConnect(**connect_args)

    def _disconnect(self):
        if self._conn is None:
            return
        Disconnect(self._conn)
        self._conn = None

    def get_vm(self):
        self._connect()
        if self._vm:
            return self._vm

        view_mgr = self._conn.content.viewManager
        view = view_mgr.CreateContainerView(self._conn.content.rootFolder,
                                            [vim.VirtualMachine],
                                            recursive=True)
        vms = [vm for vm in view.view if vm.name == self._vm_name]
        if len(vms) > 1:
            raise ValueError('VM name "%s" is not unique' % self._vm_name)
        if len(vms) != 1:
            raise ValueError('No VM with name "%s"' % self._vm_name)

        self._vm = vms[0]
        return self._vm

    def get_domxml(self):
        def auth_cb(cred, _):
            for c in cred:
                if c[0] == libvirt.VIR_CRED_AUTHNAME:
                    c[4] = self.user
                elif c[0] == libvirt.VIR_CRED_PASSPHRASE:
                    c[4] = self._password
                else:
                    return -1
            return 0

        cred_info = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE],
                     auth_cb, None]
        conn = libvirt.openAuth(self._uri, cred_info)

        return conn.lookupByName(self._vm_name).XMLDesc()

    def get_disks_from_config(self, config):
        return [x for x in config.hardware.device
                if isinstance(x, vim.vm.device.VirtualDisk)]

    def __del__(self):
        self._disconnect()


class _PreCopyDisk(StateObject):
    __slots__ = [
        'change_ids',  # List of ChangeIDs from VMWare
        'key',  # Key on the VMWare server
        'label',  # Label for nicer user reporting
        'local_path',  # Path on local filesystem
        'overlay',  # Path to the local overlay
        'path',  # The VMWare-reported path (on the host)
        'pidfile',  # nbdkit's pidfile path
        'proc_nbdkit',  # nbdkit process
        'proc_qemu',  # nbdkit process
        'size',  # in Bytes
        'sock',  # nbdkit's unix socket path
        'status',  # Any string for user-reporting
        'vmware_object',  # Disk object returned by pyvmomi
    ]

    _hidden = [
        'change_ids',
        'key',
        'local_path',
        'overlay',
        'path',
        'pidfile',
        'proc',
        'sock',
        'vmware_object',
    ]

    def __init__(self, disk, tmp_dir):
        self.change_ids = []
        self.label = disk.deviceInfo.label
        self.local_path = None
        self.path = disk.backing.fileName
        self.size = int(disk.capacityInBytes)
        self.status = 'prepared'
        self.key = disk.key
        self.vmware_object = disk

        self.sock = os.path.join(tmp_dir, 'nbdkit-%s.sock' % self.key)
        self.pidfile = os.path.join(tmp_dir, 'nbdkit-%s.pid' % self.key)
        self.proc = None


class PreCopy(StateObject):
    __slots__ = [
        'data',
        'output_format',
        '_tmp_dir',
        '_tmp_dir_path',
        'vmware',

        'disks',
    ]

    _hidden = [
        'data',
        'output_format',
        '_tmp_dir',
        '_tmp_dir_path',
        'vmware',
    ]

    @staticmethod
    def __new__(cls, data):
        if not data.get('two_phase', False):
            return None
        return super(PreCopy, cls).__new__(cls)

    def __init__(self, data):
        self.vmware = _VMWare(data)
        self.output_format = data['output_format']
        # TODO: [py2] Just use the py3 version
        if six.PY3:
            self._tmp_dir = tempfile.TemporaryDirectory(prefix='v2v-')
            self._tmp_dir_path = self._tmp_dir.name
        else:
            self._tmp_dir_path = tempfile.mkdtemp(prefix='v2v-')

        # Let others browse it
        add_perms_to_file(self._tmp_dir_path, stat.S_IXOTH, -1, -1)

    def __del__(self):
        # TODO: [py2] Just use the py3 version
        if six.PY3:
            # This is mostly for tests, but neither the object nor the
            # TemporaryDirectory object should be used multiple times.
            if self._tmp_dir is not None:
                self._tmp_dir.cleanup()
        else:
            if self._tmp_dir_path is not None:
                import shutil
                shutil.rmtree(self._tmp_dir_path)

    def init_disk_data(self):
        "Updates data about disks in the remote VM"

        vm = self.vmware.get_vm()
        if vm.snapshot:
            logging.warning("VM should not have any previous snapshots")
        disks = self.vmware.get_disks_from_config(vm.config)

        disks = [(str(d.key), _PreCopyDisk(d, self._tmp_dir)) for d in disks]
        self.disks = OrderedDict(disks)

        STATE.write()

    def _fix_disks(self, domxml):
        class DiskToFix(object):
            __slots__ = ['path', 'fixed']

            def __init__(self, path):
                self.path = path
                self.fixed = False

        disk_map = {disk.path: DiskToFix(disk.local_path)
                    for disk in self.disks.items()}
        tree = ETree.fromstring(domxml)
        for disk in tree.find('devices').findall('disk'):
            src = disk.find('source')
            if src is None:
                continue
            path = src.get('file')
            if path is None:
                continue
            disk_data = disk_map.get(path)
            if disk_data is None:
                continue
            # disk.set('type', 'block')
            # del src.attrib['file']
            # src.set('dev', dm['path'])
            src.set('file', disk_data.path)
            disk_data.fixed = True

        # Check that all paths were changed
        for k, v in six.iteritems(disk_map):
            if not v.fixed:
                raise RuntimeError('Disk path "%s" was '
                                   'not fixed in the domxml' % k)

        return ETree.tostring(tree)

    def get_xml(self):
        xmlfile = os.path.join(self._tmp_dir_path, 'vm.xml')
        with open(xmlfile, 'wb') as f:
            f.write(self._fix_disks(self.vmware.get_domxml()))

    def _get_nbdkit_cmd(self, disk, vmware_password_file):
        env = 'LD_LIBRARY_PATH=%s' % VDDK_LIBRARY_PATH
        if 'LD_LIBRARY_PATH' in os.environ:
            env += ':' + os.environ['LD_LIBRARY_PATH']

        nbdkit_cmd = [
            'env',
            env,
            'nbdkit',
            '-v',
            '-U', disk.sock,
            '-P', disk.pidfile,
            '--exit-with-parent',
            '--readonly',
            '--foreground',
            '--exportname=/',
            '--filter=log',
            '--filter=cacheextents',
            '--filter=retry',
            'vddk',
            # need to use _moId, but it's protected
            'vm=moref=%s' % self.vmware.get_vm().moId,
            'server=%s' % self.vmware.server,
            # TODO: asdf
            'thumbprint=%s' % self.vmware.thumbprint,
            'password=+%s' % self.vmware.password_file,
            'libdir=%s' % VDDK_LIBDIR,
            'file=%s' % disk.path,
            'logfile=/dev/stdout',
        ]
        if hasattr(self.vmware, 'user'):
            nbdkit_cmd.append('user=%s' % self.vmware.user)

        return nbdkit_cmd

    def _start_nbdkits(self, vmware_password_file):
        paths = []
        for disk in self.disks:
            cmd = self._get_nbdkit_cmd(disk, vmware_password_file)
            logfd = open(STATE.wrapper_log, 'a')
            logging.debug('Starting nbdkit: %s', cmd)
            disk.proc_nbdkit = subprocess.Popen(cmd,
                                                stdout=logfd,
                                                stderr=subprocess.STDOUT,
                                                stdin=_DEVNULL)
            paths.append((disk.pidfile, disk.sock))

        logging.debug('Waiting for all nbdkit processes to initialize')
        endt = time.time() + _TIMEOUT
        while paths:
            for path in paths[:]:
                if os.path.exists(path[0]) and os.path.exists(path[1]):
                    paths.remove(path)
            if endt < time.time() or not paths:
                break
            time.sleep(.1)

        if paths:
            raise RuntimeError('Timed out waiting for nbdkits to initialize')

    def _stop_nbdkits(self):
        for disk in self.disks:
            if disk.proc_nbdkit is None:
                continue
            logging.debug('Stopping nbdkit with pid=%d', disk.proc_nbdkit.pid)
            disk.proc_nbdkit.terminate()
            try:
                disk.proc_nbdkit.communicate(timeout=_TIMEOUT)
            except subprocess.TimeoutExpired:
                disk.proc_nbdkit.kill()
                disk.proc_nbdkit.communicate()
            disk.proc_nbdkit = None

    def _wait_for_qemus(self, cb=None):
        while (True for disk in self.disks if disk.proc_qemu is not None):
            for disk in self.disks:
                if disk.proc_qemu is None:
                    continue
                if disk.proc_qemu.poll() is None:
                    continue
                if disk.proc_qemu.returncode != 0:
                    error('qemu-img failed with returncode %d' %
                          disk.proc_qemu.returncode)
                    STATE.failed = True
                disk.proc_qemu = None
                if cb is not None:
                    cb(disk)

    def copy_disks(self, vmware_password_file):
        "Copy all disk data from the VMWare server to locally mounted disks."

        self._start_nbdkits(vmware_password_file)

        ndisks = len(self.disks)
        cmd_templ = ['qemu-img', 'convert', '-f', 'raw',
                     '-O', self.output_format]
        for i, disk in enumerate(self.disks):
            logging.debug('Copying disk %d/%d', i, ndisks)
            # TODO: ditch qemu-img
            logfd = open(STATE.wrapper_log, 'a')
            socket_uri = nbd_uri_from_unix_socket(disk.sock)
            cmd = cmd_templ + [socket_uri, disk.local_path]
            try:
                disk.proc_qemu = subprocess.Popen(cmd,
                                                  stdout=logfd,
                                                  stderr=subprocess.STDOUT,
                                                  stdin=_DEVNULL,
                                                  universal_newlines=True)
            except subprocess.CalledProcessError as e:
                error('qemu-img failed with: %s' % e.output, exception=True)
                raise
            disk.status = 'Copying'
            STATE.write()

        def callback(disk):
            disk.status = 'Copied'
            STATE.write()

        self._wait_for_qemus(callback)

        self._stop_nbdkits()

    def commit_overlays(self):
        "Commit all overlays to local disks."

        for disk in self.disks:
            if disk.overlay is None:
                raise RuntimeError('Did not get any overlay data from v2v')

        ndisks = len(self.disks)
        cmd_templ = ['qemu-img', 'commit']
        for i, disk in enumerate(self.disks):
            logging.debug('Committing disk %d/%d', i, ndisks)
            logfd = open(STATE.wrapper_log, 'a')
            cmd = cmd_templ + [disk.overlay]
            try:
                disk.proc_qemu = subprocess.Popen(cmd,
                                                  stdout=logfd,
                                                  stderr=subprocess.STDOUT,
                                                  stdin=_DEVNULL,
                                                  universal_newlines=True)
            except subprocess.CalledProcessError as e:
                error('qemu-img failed with: %s' % e.output, exception=True)
                raise
            disk.status = 'Committing'
            STATE.write()

        def callback(disk):
            disk.status = 'Commited'
            STATE.write()
            try:
                os.remove(disk.overlay)
            except FileNotFoundError:
                pass
            disk.overlay = None

        self._wait_for_qemus(callback)

    def cleanup(self):
        "Clean up everything upon any error"

        # Stopping nbdkits first because it might help us stop the qemu
        # processes
        self._stop_nbdkits()

        for disk in self.disks:
            if disk.proc_qemu is None:
                continue
            logging.debug('Stopping qemu-img with pid=%d', disk.proc_qemu.pid)
            disk.proc_qemu.terminate()
            try:
                disk.proc_qemu.communicate(timeout=_TIMEOUT)
            except subprocess.TimeoutExpired:
                disk.proc_qemu.kill()
                disk.proc_qemu.communicate()
            disk.proc_qemu = None
            if disk.overlay is not None:
                try:
                    os.remove(disk.overlay)
                except FileNotFoundError:
                    pass
            disk.overlay = None

    def finish(self):
        "Finish anything that is needed after successful conversion"
        pass
