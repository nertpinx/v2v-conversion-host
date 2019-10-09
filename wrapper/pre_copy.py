#!/usr/bin/env python

import os
import libvirt
import logging
import nbd
import six
import subprocess
import time

import xml.etree.ElementTree as ETree

from collections import OrderedDict
from packaging import version
from pyVmomi import vim
from pyVim.connect import SmartConnect  # , Disconnect
# from pyVim.task import WaitForTask
from six.moves.urllib.parse import urlparse, unquote

from .singleton import State
from .common import error

MAX_BLOCK_STATUS_LEN = 2 << 30  # 2GB (4GB requests fail over the 32b protocol)
MAX_PREAD_LEN = 23 << 20  # 23MB (24M requests fail in vddk)

NBD_MIN_VERSION = version.parse("0.9.8")

TIMEOUT = 10  # Seconds

# TODO: Make it into a class and:
# - use members instead of state['internal']
# - __init__() instead of prepare, etc.

if six.PY2:
    DEVNULL = open(os.devnull, 'r+')
else:
    xrange = range
    DEVNULL = subprocess.DEVNULL

_nbd_version = version.parse(nbd.NBD().get_version())
if _nbd_version < NBD_MIN_VERSION:
    raise RuntimeError("version on libnbd is too old.  Version found = %s.  Min version required = %s" %
                       (_nbd_version, NBD_MIN_VERSION))


def prepare(data):
    state = State().instance

    logging.debug('Parsing URI: %s', data['vmware_uri'])
    uri = urlparse(data['vmware_uri'])
    logging.debug('Parsed URI as %s', uri)

    state['internal']['pre_copy'].update({
        'server': uri.hostname,
        'user': 'administrator@vsphere.local',
        'port': uri.port,
    })
    if uri.username:
        state['internal']['pre_copy']['user'] = unquote(uri.username)
    if data['two_phase']:
        state['pre_copy'] = {'disks': {}}


def _connect(data):
    state = State().instance

    context = None
    if data['insecure_connection']:
        logging.debug('Insecure connection requested')
        import ssl
        if hasattr(ssl, '_create_unverified_context'):
            context = ssl._create_unverified_context()
        else:
            raise RuntimeError('Cannot connect insecurely with ' +
                               'current ssl module')

    args = {
        'host': state['internal']['pre_copy']['server'],
        'user': state['internal']['pre_copy']['user'],
        'pwd': data['vmware_password'],
        'sslContext': context,
        'thumbprint': data['vmware_fingerprint']
    }
    # We can't even put `port: None` there, so we need to check if it was part
    # of the uri
    if state['internal']['pre_copy']['port'] is not None:
        args['port'] = state['internal']['pre_copy']['port']

    logging.debug('Connecting to server %s as user %s',
                  args['host'], args['user'])
    state['internal']['pre_copy']['conn'] = SmartConnect(**args)
    logging.debug('Connected to server')


def get_vm(data):
    state = State().instance
    logging.debug('Looking for VM %s', data['vm_name'])
    content = state['internal']['pre_copy']['conn'].content

    view = content.viewManager.CreateContainerView(content.rootFolder,
                                                   [vim.VirtualMachine],
                                                   recursive=True)
    logging.debug('Finding the VM in list of %d records', len(view.view))
    vms = [vm for vm in view.view if vm.name == data['vm_name']]
    if len(vms) > 1:
        raise RuntimeError('Multiple VMs with the name %s' % data['vm_name'])
    if len(vms) != 1:
        raise RuntimeError('Could not find VM with name %s' % data['vm_name'])

    logging.debug('Found VM %s: %s', data['vm_name'], vms[0])
    state['internal']['pre_copy']['vm'] = vms[0]


def get_disks_from_config(config):
    def diskname(disk):
        return '%s (key=%s)' % (disk.deviceInfo.label, disk.key)
    disks = [x for x in config.hardware.device
             if isinstance(x, vim.vm.device.VirtualDisk)]
    logging.debug('Disks found: %d: %s',
                  len(disks), ', '.join([diskname(d) for d in disks]))
    return disks


def get_disks():
    state = State().instance
    vm = state['internal']['pre_copy']['vm']
    disks = get_disks_from_config(vm.config)
    state['pre_copy']['disks'] = OrderedDict()
    state['internal']['pre_copy']['disks'] = OrderedDict()
    for disk in disks:
        state['pre_copy']['disks'][str(disk.key)] = {
            'label': disk.deviceInfo.label,
            'path': disk.backing.fileName,
            'change_ids': ['*'],
            'status': 'prepared',
            'size': int(disk.capacityInBytes),
        }
        state['internal']['pre_copy']['disks'][str(disk.key)] = {
            'vmw_obj': disk,
        }
    state.write()


def validate():
    if State().instance['internal']['pre_copy']['vm'].snapshot:
        raise RuntimeError('VM must not have any previous snapshots.')


def get_nbdkit_cmd(data, sock_path, pidfile_path, disk):
    state = State().instance

    env = 'LD_LIBRARY_PATH=/opt/vmware-vix-disklib-distrib/lib64'
    if 'LD_LIBRARY_PATH' in os.environ:
        env += ':' + os.environ['LD_LIBRARY_PATH']

    nbdkit_cmd = [
        'env',
        env,
        'nbdkit',
        '-v',
        '-U', sock_path,
        '-P', pidfile_path,
        '--exit-with-parent',
        '--readonly',
        '--foreground',
        '--exportname=/',
        '--filter=log',
        '--filter=cacheextents',
        'vddk',
        'vm=moref=' + state['internal']['pre_copy']['vm']._moId,
        'server=%s' % state['internal']['pre_copy']['server'],
        'thumbprint=%s' % data['vmware_fingerprint'],
        'password=+%s' % data['vmware_password_file'],
        'libdir=%s' % '/opt/vmware-vix-disklib-distrib',
        'file=%s' % disk['path'],
        'logfile=/dev/stdout',
    ]
    if 'user' in state['internal']['pre_copy']:
        nbdkit_cmd.append('user=%s' % state['internal']['pre_copy']['user'])

    return nbdkit_cmd


def start_nbdkits(data):
    state = State().instance
    tempdir = state['internal']['pre_copy']['tempdir']
    logdir = state['internal']['pre_copy']['logdir']
    wait_for_paths = []
    for disk_key, disk in six.iteritems(state['pre_copy']['disks']):
        sock_path = os.path.join(tempdir, 'nbdkit-%s.sock' % disk_key)
        log_path = os.path.join(logdir, 'nbdkit-%s.log' % disk_key)
        pidfile_path = os.path.join(logdir, 'nbdkit-%s.pid' % disk_key)
        disk_internal = state['internal']['pre_copy']['disks'][disk_key]
        disk_internal['nbdkit_sock'] = sock_path
        disk_internal['nbdkit_log'] = log_path
        disk_internal['nbdkit_pidfile'] = pidfile_path
        wait_for_paths.append(sock_path)
        cmd = get_nbdkit_cmd(data, sock_path, pidfile_path, disk)
        logging.debug('Starting nbdkit: %s', cmd)
        proc = subprocess.Popen(cmd,
                                stdout=open(log_path, 'w'),
                                stderr=subprocess.STDOUT,
                                stdin=DEVNULL)
        disk_internal['nbdkit_process'] = proc

    logging.debug('Waiting for all nbdkit processes to initialize')
    endt = time.time() + TIMEOUT
    while wait_for_paths:
        for path in wait_for_paths[:]:
            if os.path.exists(path):
                wait_for_paths.remove(path)
        if endt < time.time() or not wait_for_paths:
            break
        time.sleep(.1)

    if wait_for_paths:
        raise RuntimeError('Timed out waiting for nbdkits to initialize')


def get_domxml(data):
    state = State().instance
    auth_creds = {
        libvirt.VIR_CRED_AUTHNAME: state['internal']['pre_copy']['user'],
        libvirt.VIR_CRED_PASSPHRASE: data['vmware_password'],
    }

    def auth_cb(cred, _):
        for c in cred:
            val = auth_creds.get(c[0], None)
            if val is None:
                return -1
            c[4] = val
        return 0
    conn = libvirt.openAuth(data['vmware_uri'],
                            [list(auth_creds.keys()), auth_cb, None])
    return conn.lookupByName(data['vm_name']).XMLDesc()


def fix_disks(domxml, disk_map):
    logging.debug('Trying to fix the domain XML to point to local devices')
    logging.debug('Using disk map %s', disk_map)
    tree = ETree.fromstring(domxml)
    for disk in tree.find('devices').findall('disk'):
        logging.debug('Trying to fixup "%s"', ETree.tostring(disk))
        src = disk.find('source')
        if src is None:
            continue
        path = src.get('file')
        if path is None:
            continue
        if path not in disk_map:
            continue
        dm = disk_map[path]
        # disk.set('type', 'block')
        logging.debug('Changing path "%s" to device "%s" in domain XML',
                      path, dm['path'])
        # del src.attrib['file']
        # src.set('dev', dm['path'])
        src.set('file', dm['path'])
        dm['fixed'] = True

    # Check that all paths were changed
    for k, v in six.iteritems(disk_map):
        if not v['fixed']:
            raise RuntimeError('Disk path "%s" was not fixed in the domxml' % k)
    return ETree.tostring(tree)


def prepare_libvirtxml(data, host):
    state = State().instance
    source_disks = state['pre_copy']['disks']
    source_disk_paths = list([x['path'] for x in source_disks.values()])
    target_disk_paths = host.get_disk_paths()
    if len(target_disk_paths) != len(source_disk_paths):
        raise RuntimeError("Invalid disk data")
    target_objects = ({'fixed': False, 'path': p} for p in target_disk_paths)
    disk_map = dict(zip(source_disk_paths, target_objects))
    domxml = get_domxml(data)
    domxml = fix_disks(domxml, disk_map)
    with open(state['internal']['pre_copy']['libvirtxml'], 'wb') as xmlfile:
        xmlfile.write(domxml)


def connect(data):
    _connect(data)
    get_vm(data)
    get_disks()
    validate()


def cleanup():
    state = State().instance
    logging.debug('Cleaning up')
    # TODO: Figure out what we need to do (detach, remove, etc.)
    for disk in state['internal']['pre_copy']['disks'].values():
        if 'nbdkit_process' not in disk:
            continue
        proc = disk['nbdkit_process']
        proc.terminate()
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        del disk['nbdkit_process']


def nbd_uri_from_socket(socket):
    return 'nbd+unix:///?socket=%s' % socket

################################################################
################################################################

# def update_change_ids(vm):
#     state = State().instance
#     disks = get_all_disks(vm.snapshot.currentSnapshot.config)
#     for disk in disks:
#         disk_state = state['disks'][str(disk.key)]
#         if 'change_ids' not in disk_state.keys():
#             disk_state['change_ids'] = []
#         logging.debug('Adding change ID "%s" to the list for disk %s' %
#                       (disk.backing.changeId, disk.deviceInfo.label))
#         disk_state['change_ids'].append(disk.backing.changeId)
#     state.write()


# def create_snapshot(vm):
#     state = State().instance
#     if state['sync_type'] == 'initial':
#         logging.info('Enabling CBT for the VM')
#         config_spec = vim.vm.ConfigSpec(changeTrackingEnabled=True)
#         WaitForTask(vm.Reconfigure(config_spec))
#         logging.debug('CBT for the VM enabled')

#     logging.debug('Creating VM snapshot for CBT')
#     WaitForTask(vm.CreateSnapshot(name='v2v_cbt',
#                                   description='Snapshot to start CBT',
#                                   memory=False,
#                                   quiesce=False))
#     logging.debug('VM snapshot for CBT created')

#     update_change_ids(vm)


# def validate_state(sync_type):
#     state = State().instance

#     if sync_type == 'initial':
#         for key in state.keys():
#             if key not in ('last_message', 'internal', 'statefile'):
#                 error('Non-empty state on initial run, extra key: %s' % key)
#         state['disks'] = {}
#     else:
#         if state.get('status') != 'Completed':
#             if 'error' in state.keys():
#                 error('Cannot continue, last run ended with error: %s' %
#                       state['error'])
#             error('Cannot continue, last run did not complete successfully')

#         if 'sync_type' not in state.keys():
#             error('Missing "sync_type" from last state')
#         if state['sync_type'] == 'final':
#             error('Nothing to do after the final sync')

#         for key, disk in state['disks'].items():
#             disk['status'] = 'Gathering data'
#             if 'progress' in disk:
#                 del disk['progress']

#         del state['status']

#     state['status'] = 'Running'
#     state['sync_type'] = sync_type
#     state.write()


# def validate_state_vm(vm):
#     state = State().instance

#     if vm.snapshot:
#         error('VM must not have any previous snapshots.  Pass --remove-all-existing-snapshots to clean them beforehand')

#     disks = get_all_disks(vm.config)

#     if state['sync_type'] == 'initial':
#         for disk in disks:
#             pass
#     else:
#         if list(state['disks'].keys()) != [str(x.key) for x in disks]:
#             error('Unsupported scenario: disks changed between runs!')

#     if state['sync_type'] == 'final' and vm.runtime.powerState != 'poweredOff':
#         error('Cannot run final sync with running machine')

#     state['status'] = 'Running'
#     if 'vm_uuid' not in state.keys():
#         state['vm_uuid'] = vm.config.instanceUuid
#     if 'vm_moid' not in state.keys():
#         state['vm_moid'] = vm._moId

#     state.write()


# def get_extents(vm):
#     state = State().instance

#     state['internal']['disk_extents'] = {}

#     snapshot = state['internal']['last_snapshot']
#     for key, disk in state['disks'].items():
#         total_len = 0
#         extents = []

#         if state['sync_type'] == 'final':
#             change_id = disk['change_ids'][-1]
#         else:
#             # '*' is initially in the list
#             change_id = disk['change_ids'][-2]

#         while total_len < disk['size']:
#             tmp = vm.QueryChangedDiskAreas(snapshot,
#                                            int(key),
#                                            total_len,
#                                            change_id)
#             extents += tmp.changedArea
#             total_len += tmp.startOffset + tmp.length
#         logging.debug('Gathered %d extents to transfer, total size is %d B' %
#                       (len(extents), sum(x.length for x in extents)))
#         state['internal']['disk_extents'][str(key)] = extents


# def _old_get_nbdkit_cmd(disk, key):
#     state = State().instance
#     logging.debug('Generating nbdkit command')

#     env = 'LD_LIBRARY_PATH=%s/lib64' % VDDK_LIBDIR
#     if 'LD_LIBRARY_PATH' in os.environ:
#         env += ':' + os.environ['LD_LIBRARY_PATH']

#     logfile = state.get('logfile', 'disk-sync.log')
#     logfile = logfile.replace('.log', '-nbdkit-' + key + '.log')
#     nbdkit_cmd = [
#         'env',
#         env,
#         'nbdkit',
#         '-s',
#         '--exit-with-parent',
#         '--readonly',
#         '--exportname=/',
#         '--filter=log',
#         '--filter=cacheextents',
#         'vddk',
#         'libdir=%s' % VDDK_LIBDIR,
#         'vm=moref=' + state['vm_moid'],
#         'server=%s' % state['server'],
#         'thumbprint=%s' % state['vmware_fingerprint'],
#         'user=%s' % state['user'],
#         'password=+%s' % state['pwdfile'],
#         'libdir=%s' % VDDK_LIBDIR,
#         'file=%s' % disk['path'],
#         'logfile=%s' % logfile,
#     ]

#     return nbdkit_cmd


# def get_block_status(nbd_handle, extent):
#     logging.debug('Gathering block status for extent of size %d B at offset %d B' %
#                   (extent.length, extent.start))

#     blocks = []
#     last_offset = extent.start

#     def update_blocks(metacontext, offset, extents, err):
#         if metacontext != 'base:allocation':
#             return
#         for length, flags in zip(extents[::2], extents[1::2]):
#             blocks.append({
#                 'offset': offset,
#                 'length': length,
#                 'flags': flags,
#             })
#             offset += length

#     while last_offset < extent.start + extent.length:
#         nblocks = len(blocks)
#         length = min(extent.length, MAX_BLOCK_STATUS_LEN)
#         logging.debug('Calling block_status with length=%d offset=%d' %
#                       (length, last_offset))
#         nbd_handle.block_status(length, last_offset, update_blocks)
#         if len(blocks) == nblocks:
#             error('Missing block status data from NBD')
#         last_offset = blocks[-1]['offset'] + blocks[-1]['length']

#     return blocks


# # This is called back when nbd_aio_pread completes.
# def read_completed(fd, buf, offset, err):
#     logging.debug('Writing %d B to offset %d B' % (buf.size(), offset))
#     os.pwrite(fd, buf.to_bytearray(), offset)
#     # By returning 1 here we auto-retire the aio_pread command.
#     return 1


# # Process any AIO requests without blocking.
# def process_aio_requests(nbd_handle):
#     while nbd_handle.poll(0) == 1:
#         pass


# # Block until all AIO commands on the handle have finished.
# def wait_for_aio_commands_to_finish(nbd_handle):
#     while nbd_handle.aio_in_flight() > 0:
#         nbd_handle.poll(-1)


# def sync_data():
#     state = State().instance
#     for key, disk in state['disks'].items():
#         logging.debug('Opening local file %s' % 'disk-%s.img' % key)
#         fd = os.open('disk-%s.img' % key, os.O_WRONLY | os.O_CREAT)

#         if len(state['internal']['disk_extents'][key]) == 0:
#             logging.debug('No changed extents for disk: %s(key=%s)' %
#                           (disk['label'], key))
#             if state['sync_type'] == 'initial':
#                 logging.debug('Truncating file %s to %d B' %
#                               ('disk-%s.img' % key, disk['size']))
#                 os.ftruncate(fd, disk['size'])
#             disk['status'] = 'Completed'
#             state.write()
#             os.close(fd)
#             continue

#         disk['status'] = 'Starting nbdkit for data access'
#         state.write()

#         cmd = get_nbdkit_cmd(disk, key)

#         nbd_handle = nbd.NBD()
#         nbd_handle.add_meta_context("base:allocation")

#         logging.debug('Connecting to the nbdkit command')
#         nbd_handle.connect_command(cmd)

#         logging.debug('Getting block info for disk: %s(key=%s)' %
#                       (disk['label'], key))
#         disk['status'] = 'Getting block info'
#         state.write()

#         copied = 0
#         data_blocks = []
#         for extent in state['internal']['disk_extents'][key]:
#             # Skip over extents smaller than 1MB
#             if extent.length < 1 << 20:
#                 logging.debug('Skipping block status for extent of size %d B at offset %d B' %
#                               (extent.length, extent.start))
#                 data_blocks.append({
#                     'offset': extent.start,
#                     'length': extent.length,
#                     'flags': 0,
#                 })
#                 continue

#             logging.debug('Gathering block status for extent of size %d B at offset %d B' %
#                           (extent.length, extent.start))

#             blocks = get_block_status(nbd_handle, extent)
#             logging.debug('Gathered block status of %d: %s' % (len(blocks), blocks))
#             data_blocks += [x for x in blocks if not x['flags'] & nbd.STATE_HOLE]

#         logging.debug('Block status filtered down to %d data blocks' %
#                       len(data_blocks))
#         if len(data_blocks) == 0:
#             logging.debug('No extents have allocated data for disk: %s(key=%s)' %
#                           (disk['label'], key))
#             if state['sync_type'] == 'initial':
#                 logging.debug('Truncating file %s to %d B' %
#                               ('disk-%s.img' % key, disk['size']))
#                 os.ftruncate(fd, disk['size'])
#             os.close(fd)
#             disk['status'] = 'Completed'
#             state.write()
#             continue

#         to_copy = sum([x['length'] for x in data_blocks])
#         logging.debug('Copying %d B of data' % to_copy)

#         disk['status'] = 'Copying'
#         disk['progress'] = {'to_copy': to_copy, 'copied': copied}
#         state.write()
#         for block in data_blocks:
#             if block['flags'] & nbd.STATE_ZERO:
#                 logging.debug('Writing %d B of zeros to offset %d B' %
#                               (block['length'], block['offset']))
#                 # Optimize for memory usage, maybe?
#                 os.pwrite(fd, [0] * block['length'], block['offset'])
#             else:
#                 count = 0
#                 while count < block['length']:
#                     length = min(block['length'] - count, MAX_PREAD_LEN)
#                     offset = block['offset'] + count

#                     logging.debug('Reading %d B from offset %d B' %
#                                   (length, offset))
#                     buf = nbd.Buffer(length)
#                     nbd_handle.aio_pread(
#                         buf, offset,
#                         lambda err, fd=fd, buf=buf, offset=offset:
#                         read_completed(fd, buf, offset, err))
#                     count += length

#                     process_aio_requests(nbd_handle)

#             copied += block['length']
#             disk['progress']['copied'] = copied
#             state.write()

#         wait_for_aio_commands_to_finish(nbd_handle)

#         if copied == 0:
#             logging.debug('Nothing to copy for disk: %s(key=%s)' %
#                           (disk['label'], key))
#         else:
#             logging.debug('Copied %d B for disk: %s(key=%s)' %
#                           (copied, disk['label'], key))

#         os.ftruncate(fd, disk['size'])
#         os.close(fd)
#         nbd_handle.shutdown()
#         disk['status'] = 'Completed'


# def parse_args():
#     parser = argparse.ArgumentParser()

#     parser.add_argument('-f', '--inputfile',
#                         help="File conatining all input data")

#     parser.add_argument('-s', '--statefile',
#                         help="File used for keeping state around")

#     parser.add_argument('-t', '--sync-type',
#                         dest='sync_type',
#                         choices=['initial', 'intermediate', 'final'],
#                         default='intermediate',
#                         help="Type of sync [initial, intermediate (default), final]")

#     parser.add_argument('--remove-all-existing-snapshots',
#                         dest='clear_snaps',
#                         action='store_true')

#     return parser.parse_args()


# def parse_input(args):
#     state = State().instance

#     with open(args.inputfile, 'r') as f:
#         data = json.load(f)

#     if 'vm_uuid' not in data and 'vm_name' not in data:
#         raise KeyError('Either "vm_name" or "vm_uuid" must be supplied in input data')

#     for key in ('vm_uuid', 'vm_name'):
#         if key in data:
#             if key not in state.keys():
#                 state[key] = data[key]
#             elif state[key] != data[key]:
#                 raise ValueError('Mismatch in values for ' +
#                                  ' key "%s": "%s" != "%s"' %
#                                  (key, state[key], data[key]))

#     for key in ('vmware_uri', 'vmware_fingerprint', 'pwdfile', 'statefile'):
#         if key not in data:
#             raise KeyError('Missing "%s" in input data' % key)
#         if state['sync_type'] == 'initial':
#             state[key] = data[key]
#         elif state[key] != data[key]:
#             raise ValueError('Mismatch in values for key "%s": "%s" != "%s"' %
#                              (key, state[key], data[key]))

#     if 'loglevel' in data:
#         if data['loglevel'] not in ('ERROR', 'WARNING', 'INFO', 'DEBUG'):
#             raise ValueError('Unknown loglevel: %s' % data['loglevel'])
#         state['loglevel'] = data['loglevel']
#     else:
#         state['loglevel'] = 'ERROR'

#     state['insecure_connection'] = data.get('insecure_connection', False)


# def main():
#     '''TODO: Add some description here '''

#     args = parse_args()

#     state = State(args).instance
#     validate_state(args.sync_type)
#     parse_input(args)
#     log_config(filename=state.get('logfile'),
#                level=getattr(logging, state['loglevel']))

#     if args.sync_type == 'initial' and args.clear_snaps:
#         while vm.snapshot:
#             snapshot = vm.snapshot.rootSnapshotList[0].snapshot
#             logging.debug('Removing snapshot %s with children' % snapshot)
#             # It ought to be faster to remove whole snapshot chains at a time
#             WaitForTask(snapshot.Remove(removeChildren=True))

#     # TODO: Check all the limitations from
#     # https://pubs.vmware.com/vsphere-50/topic/com.vmware.ICbase/PDF/vddk_prog_guide.pdf
#     validate_state_vm(vm)

#     last_snapshot = None
#     if args.sync_type != 'final':
#         logging.info('Creating snapshot')
#         create_snapshot(vm)
#         last_snapshot = vm.snapshot.currentSnapshot

#     state['internal']['last_snapshot'] = last_snapshot

#     logging.info('Gathering extents data')
#     get_extents(vm)

#     logging.info('Copying data')
#     sync_data()

#     if last_snapshot:
#         logging.debug('Cleaning up created snapshot')
#         WaitForTask(last_snapshot.Remove(removeChildren=True))

#     logging.debug('Looks like everything went fine')
#     state['status'] = 'Completed'
#     state.write()


def actually_sync_disks_but_first_please_rename_and_implement_me():
    raise NotImplementedError("Disk Syncing")


def qemu_img_convert(data):
    state = State().instance
    try:
        for i, (key, disk) in enumerate(state['internal']['pre_copy']['disks'].items()):
            logging.debug('Copying disk #%d', i)
            state['pre_copy']['disks'][key]['status'] = 'Copying'
            state.write()
            proc = subprocess.check_output(['qemu-img', 'convert',
                                            '-f', 'raw',
                                            nbd_uri_from_socket(disk['nbdkit_sock']),
                                            '-O', data['output_format'],
                                            disk['local_path']],
                                           stderr=subprocess.STDOUT,
                                           universal_newlines=True)
            state['pre_copy']['disks'][key]['status'] = 'Copied'
            state.write()
    except subprocess.CalledProcessError as e:
        error('qemu-img failed with: %s' % e.output, exception=True)
        raise


def commit_overlays():
    state = State().instance
    if not state['internal'].get('v2v_data'):
        raise RuntimeError('No internal data from v2v')
    if not state['internal']['v2v_data'].get('saved_overlays'):
        raise RuntimeError('No data from v2v about saved overlays')
    try:
        for i, ov in enumerate(state['internal']['v2v_data']['saved_overlays']):
            logging.debug('Committing disk #%d', i)
            key = list(state['pre_copy']['disks'])[i]
            state['pre_copy']['disks'][key]['status'] = 'Committing'
            state.write()
            proc = subprocess.check_output(['qemu-img', 'commit', ov],
                                           stderr=subprocess.STDOUT,
                                           universal_newlines=True)
            state['pre_copy']['disks'][key]['status'] = 'Commited'
            state.write()
            # At this point the file is successfully commited, so remove it
            os.remove(ov)
    except subprocess.CalledProcessError as e:
        error('qemu-img failed with: %s' % e.output, exception=True)
        raise
