#!/usr/bin/env python

from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
from pyVim.task import WaitForTask

import nbd

from six.moves.urllib.parse import urlparse, unquote

import argparse
import os
import logging
import ssl
import sys
import json

LOG_FORMAT_TIME = '[%(asctime)s] '
LOG_FORMAT_MSG = ': %(message)s'

LOG_FORMAT_LVL = '[%(levelname)s]'
LOG_FORMAT_LVL_COLOR = '[%(log_color)s%(levelname)s%(reset)s]'

LOG_FORMAT = LOG_FORMAT_TIME + LOG_FORMAT_LVL + LOG_FORMAT_MSG
LOG_FORMAT_COLOR = LOG_FORMAT_TIME + LOG_FORMAT_LVL_COLOR + LOG_FORMAT_MSG

LOG_DATE_FORMAT = '%FT%H:%M:%S%z'

VDDK_LIBDIR = '/opt/vmware-vix-disklib-distrib'
MAX_BLOCK_STATUS_LEN = 2 << 30 # 2GB (4GB requests fail over the 32b protocol)
MAX_PREAD_LEN = 23 << 20 # 23MB (24M requests fail in vddk)

def log_config(filename=None, level=None):
    use_colorlog = False
    try:
        if os.isatty(sys.stdout.fileno()):
            # noinspection PyUnresolvedReferences
            import colorlog
            use_colorlog = True
    except ImportError:
        pass

    if use_colorlog:
        log_formatter = colorlog.ColoredFormatter(LOG_FORMAT_COLOR,
                                                  datefmt=LOG_DATE_FORMAT)
    else:
        log_formatter = logging.Formatter(LOG_FORMAT,
                                          datefmt=LOG_DATE_FORMAT)

    if filename:
        log_handler = logging.FileHandler(filename)
    else:
        log_handler = logging.StreamHandler(stream=sys.stdout)

    log_handler.setLevel(level or logging.DEBUG)
    log_handler.setFormatter(log_formatter)

    state_log_handler = StateHandler()
    state_log_handler.setLevel(level or logging.DEBUG)

    logger = logging.getLogger()
    logger.addHandler(log_handler)
    logger.addHandler(state_log_handler)
    logger.setLevel(level or logging.DEBUG)


""" TODO: Ehm, locking maybe? """
class StateHandler(logging.Handler):
    def emit(self, record):
        state = State().instance
        if record.exc_info:
            state['status'] = 'Failed'
            state['error'] = str(record.exc_info)
        state['last_message'] = self.format(record)
        state.write()


class State(object):  # {{{
    """
    State object (which is a dict inside) implemented as singleton

    This is not just the contain of state file, but it contains all the
    internal configuration.
    """
    class __StateObject:
        def __init__(self, args):
            if args.sync_type != 'initial':
                with open(args.statefile, 'r') as f:
                    self._state = json.load(f)
            else:
                self._state = {}
            self._state['internal'] = {}
            self._state['statefile'] = args.statefile

        def __getattr__(self, name):
            return getattr(self._state, name)

        def __getitem__(self, key):
            return self._state[key]

        def __setitem__(self, key, value):
            self._state[key] = value

        def __delitem__(self, key):
            del self._state[key]

        def __str__(self):
            return repr(self._state)

        def write(self):
            state = self._state.copy()
            del state['internal']
            with open(state['statefile'] + '.tmp', 'w') as f:
                json.dump(state, f)
            os.rename(state['statefile'] + '.tmp', state['statefile'])

    instance = None

    def __init__(self, args=None):
        if not State.instance:
            if not args.statefile:
                raise Exception('Parameter `statefile` required on first use')
            State.instance = State.__StateObject(args)

    def __getattr__(self, name):
        return getattr(self.instance, name)


def parse_uri(uri):
    state = State().instance

    logging.debug('Parsing URI: %s' % uri)
    uri = urlparse(uri)
    logging.debug('Parsed URI as %s' % (uri,))

    state['server'] = uri.hostname
    state['user'] = 'administrator@vsphere.local'
    if uri.username:
        state['user'] = unquote(uri.username)
    state['port'] = uri.port
    state.write()


def connect(uri, password, fingerprint=None, port=None):
    state = State().instance

    context = None
    if state['insecure_connection']:
        logging.debug('Insecure connection requested')
        if hasattr(ssl, '_create_unverified_context'):
            context = ssl._create_unverified_context()
        else:
            error('Cannot connect insecurely with current ssl module')

    if 'server' not in state.keys():
        parse_uri(uri)

    args = { 'host': state['server'],
             'user': state['user'],
             'pwd': password,
             'sslContext': context,
             'thumbprint': fingerprint }
    if state['port'] is not None:
        args['port'] = state['port']

    logging.debug('Connecting to server %s as user %s' %
                  (args['host'], args['user']))
    conn = SmartConnect(**args)
    logging.debug('Connected to server')
    return conn


def get_vm(conn, vm_name):
    state = State().instance

    logging.debug('Looking for VM %s' % vm_name)
    content = conn.content

    if 'vm_uuid' in state.keys():
        logging.debug('Using UUID')
        vm = content.searchIndex.FindByUuid(uuid=state['vm_uuid'],
                                            instanceUuid=True,
                                            vmSearch=True)
    else:
        view = content.viewManager.CreateContainerView(content.rootFolder,
                                                       [vim.VirtualMachine],
                                                       recursive=True)
        logging.debug('Finding the VM in list of %d records' % len(view.view))
        vms = [vm for vm in view.view if vm.name == vm_name]
        if len(vms) > 1:
            error('Multiple VMs with the name %s: %s' % (vm_name,
                                                     list(vm for vm in vms)))
        if len(vms) != 1:
            error('Could not find VM with name %s' % vm_name)

        vm = vms[0]

    logging.debug('Found VM %s: %s' % (vm_name, vm))
    return vm


def error(msg):
    state = State().instance
    state['error'] = msg
    state['status'] = 'Failed'
    state.write()
    logging.error(msg)
    sys.exit(1)


def get_all_disks(config):
    def diskname(disk):
        return '"%s"(key=%s)' % (disk.deviceInfo.label, disk.key)
    disks = [x for x in config.hardware.device \
             if isinstance(x, vim.vm.device.VirtualDisk)]
    logging.debug('Disks found: %d: %s' %
                  (len(disks), ', '.join([diskname(d) for d in disks])))
    return disks


def update_change_ids(vm):
    state = State().instance
    disks = get_all_disks(vm.snapshot.currentSnapshot.config)
    for disk in disks:
        disk_state = state['disks'][str(disk.key)]
        if 'change_ids' not in disk_state.keys():
            disk_state['change_ids'] = []
        logging.debug('Adding change ID `%s` to the list for disk %s' %
                      (disk.backing.changeId, disk.deviceInfo.label))
        disk_state['change_ids'].append(disk.backing.changeId)
    state.write()


def create_snapshot(vm):
    state = State().instance
    if state['sync_type'] == 'initial':
        logging.info('Enabling CBT for the VM')
        config_spec = vim.vm.ConfigSpec(changeTrackingEnabled = True)
        WaitForTask(vm.Reconfigure(config_spec))
        logging.debug('CBT for the VM enabled')

    logging.debug('Creating VM snapshot for CBT')
    WaitForTask(vm.CreateSnapshot(name='v2v_cbt',
                                  description='Snapshot to start CBT',
                                  memory=False,
                                  quiesce=False))
    logging.debug('VM snapshot for CBT created')

    update_change_ids(vm)


def validate_state(sync_type):
    state = State().instance

    if sync_type == 'initial':
        for key in state.keys():
            if key not in ('last_message', 'internal', 'statefile'):
                error('Non-empty state on initial run, extra key: %s' % key)
        state['disks'] = {}
    else:
        if state.get('status') != 'Completed':
            if 'error' in state.keys():
                error('Cannot continue, last run ended with error: %s' %
                      state['error'])
            error('Cannot continue, last run did not complete successfully')

        if 'sync_type' not in state.keys():
            error('Missing `sync_type` from last state')
        if state['sync_type'] == 'final':
            error('Nothing to do after the final sync')

        for key, disk in state['disks'].items():
            disk['status'] = 'Gathering data'
            if 'progress' in disk:
                del disk['progress']

        del state['status']

    state['status'] = 'Running'
    state['sync_type'] = sync_type
    state.write()


def validate_state_vm(vm):
    state = State().instance

    if vm.snapshot:
        error('VM must not have any previous snapshots.  Pass --remove-all-existing-snapshots to clean them beforehand')

    disks = get_all_disks(vm.config)

    if state['sync_type'] == 'initial':
        for disk in disks:
            state['disks'][str(disk.key)] = { 'label': disk.deviceInfo.label,
                                              'path': disk.backing.fileName,
                                              'change_ids': ['*'],
                                              'status': 'prepared',
                                              'size': disk.capacityInBytes}
    else:
        if list(state['disks'].keys()) != [str(x.key) for x in disks]:
            error('Unsupported scenario: disks changed between runs!')

    if state['sync_type'] == 'final' and vm.runtime.powerState != 'poweredOff':
        error('Cannot run final sync with running machine')

    state['status'] = 'Running'
    if 'vm_uuid' not in state.keys():
        state['vm_uuid'] = vm.config.instanceUuid
    if 'vm_moid' not in state.keys():
        state['vm_moid'] = vm._moId

    state.write()


def get_extents(vm):
    state = State().instance

    state['internal']['disk_extents'] = {}

    snapshot = state['internal']['last_snapshot']
    for key, disk in state['disks'].items():
        total_len = 0
        extents = []

        if state['sync_type'] == 'final':
            change_id = disk['change_ids'][-1]
        else:
            # '*' is initially in the list
            change_id = disk['change_ids'][-2]

        while total_len < disk['size']:
            tmp = vm.QueryChangedDiskAreas(snapshot,
                                           int(key),
                                           total_len,
                                           change_id)
            extents += tmp.changedArea
            total_len += tmp.startOffset + tmp.length
        logging.debug('Gathered %d extents to transfer, total size is %d B' %
                      (len(extents), sum(x.length for x in extents)))
        state['internal']['disk_extents'][str(key)] = extents


def get_nbdkit_cmd(disk, key):
    state = State().instance
    logging.debug('Generating nbdkit command')

    env = 'LD_LIBRARY_PATH=%s' % VDDK_LIBDIR
    if 'LD_LIBRARY_PATH' in os.environ:
        env += ':' + os.environ['LD_LIBRARY_PATH']

    logfile = state.get('logfile', 'disk-sync.log')
    logfile = logfile.replace('.log', '-nbdkit-' + key + '.log')
    nbdkit_cmd = [
        'env',
        env,
        'nbdkit',
        '--readonly',
        '--newstyle',
        '--exportname=/',
        '-s',
        '--filter=log',
        '--filter=cacheextents',
        '--exit-with-parent',
        'vddk',
        'libdir=%s' % VDDK_LIBDIR,
        'vm=moref=' + state['vm_moid'],
        'server=%s' % state['server'],
        'thumbprint=%s' % state['vmware_fingerprint'],
        'user=%s' % state['user'],
        'password=+%s' % state['pwdfile'],
        'libdir=%s' % VDDK_LIBDIR,
        'file=%s' % disk['path'],
        'logfile=%s' % logfile,
    ]

    return nbdkit_cmd


def get_block_status(nbd_handle, extent):
    logging.debug('Gathering block status for extent of size %d B at offset %d B' %
                  (extent.length, extent.start))

    blocks = []
    last_offset = extent.start
    def update_blocks(metacontext, offset, extents, err):
        if metacontext != 'base:allocation':
            return
        for length, flags in zip(extents[::2], extents[1::2]):
            blocks.append({
                'offset': offset,
                'length': length,
                'flags': flags,
            })
            offset += length

    while last_offset < extent.start + extent.length:
        nblocks = len(blocks)
        length = min(extent.length, MAX_BLOCK_STATUS_LEN)
        logging.debug('Calling block_status with length=%d offset=%d' %
                      (length, last_offset))
        nbd_handle.block_status(length, last_offset, update_blocks)
        if len(blocks) == nblocks:
            error('Missing block status data from NBD')
        last_offset = blocks[-1]['offset'] + blocks[-1]['length']

    return blocks


def sync_data():
    state = State().instance
    for key, disk in state['disks'].items():
        logging.debug('Opening local file %s' % 'disk-%s.img' % key)
        fd = os.open('disk-%s.img' % key, os.O_WRONLY | os.O_CREAT)

        if len(state['internal']['disk_extents'][key]) == 0:
            logging.debug('No changed extents for disk: %s(key=%s)' %
                          (disk['label'], key))
            if state['sync_type'] == 'initial':
                logging.debug('Truncating file %s to %d B' %
                              ('disk-%s.img' % key, disk['size']))
                os.ftruncate(fd, disk['size'])
            disk['status'] = 'Completed'
            state.write()
            os.close(fd)
            continue

        disk['status'] = 'Starting nbdkit for data access'
        state.write()

        cmd = get_nbdkit_cmd(disk, key)

        nbd_handle = nbd.NBD()
        nbd_handle.add_meta_context("base:allocation")

        logging.debug('Connecting to the nbdkit command')
        nbd_handle.connect_command(cmd)

        logging.debug('Getting block info for disk: %s(key=%s)' %
                      (disk['label'], key))
        disk['status'] = 'Getting block info'
        state.write()

        copied = 0
        pos = 0
        data_blocks = []
        for extent in state['internal']['disk_extents'][key]:
            # Skip over extents smaller than 1MB
            if extent.length < 1 << 20:
                logging.debug('Skibbing block status for extent of size %d B at offset %d B' %
                              (extent.length, extent.start))
                data_blocks.append({
                    'offset': extent.start,
                    'length': extent.length,
                    'flags': 0,
                })
                continue

            logging.debug('Gathering block status for extent of size %d B at offset %d B' %
                          (extent.length, extent.start))

            blocks = get_block_status(nbd_handle, extent)
            logging.debug('Gathered block status of %d: %s' % (len(blocks), blocks))
            data_blocks += [x for x in blocks if not x['flags'] & nbd.STATE_HOLE]

        logging.debug('Block status filtered down to %d data blocks' %
                      len(data_blocks))
        if len(data_blocks) == 0:
            logging.debug('No extents have allocated data for disk: %s(key=%s)' %
                          (disk['label'], key))
            if state['sync_type'] == 'initial':
                logging.debug('Truncating file %s to %d B' %
                              ('disk-%s.img' % key, disk['size']))
                os.ftruncate(fd, disk['size'])
            os.close(fd)
            disk['status'] = 'Completed'
            state.write()
            continue

        to_copy = sum([x['length'] for x in data_blocks])
        logging.debug('Copying %d B of data' % to_copy)

        disk['status'] = 'Copying'
        disk['progress'] = { 'to_copy': to_copy, 'copied': copied }
        state.write()
        for block in data_blocks:
            if block['flags'] & nbd.STATE_ZERO:
                logging.debug('Writing %d B of zeros to offset %d B' %
                              (block['length'], block['offset']))
                # Optimize for memory usage, maybe?
                os.pwrite(fd, [0] * block['length'], block['offset'])
                copied += block['length']
                disk['progress']['copied'] = copied
                state.write()
            else:
                wrote = 0
                while wrote < block['length']:
                    length = min(block['length'] - wrote, MAX_PREAD_LEN)
                    offset = block['offset'] + wrote
                    logging.debug('Reading %d B from offset %d B' %
                                  (length, offset))
                    # Ideally use mmap() without any temporary buffer
                    data = nbd_handle.pread(length, offset)
                    logging.debug('Writing %d B to offset %d B' %
                                  (length, offset))
                    os.pwrite(fd, data, offset)
                    copied += length
                    wrote += length
                    disk['progress']['copied'] = copied
                    state.write()

        if copied == 0:
            logging.debug('Nothing to copy for disk: %s(key=%s)' %
                          (disk['label'], key))
        else:
            logging.debug('Copied %d B for disk: %s(key=%s)' %
                          (copied, disk['label'], key))

        os.ftruncate(fd, disk['size'])
        os.close(fd)
        nbd_handle.shutdown()
        disk['status'] = 'Completed'


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--inputfile',
                        help="File conatining all input data")

    parser.add_argument('-s', '--statefile',
                        help="File used for keeping state around")

    parser.add_argument('-t', '--sync-type',
                        dest='sync_type',
                        choices=['initial', 'intermediate', 'final'],
                        default='intermediate',
                        help="Type of sync [initial, intermediate (default), final]")

    parser.add_argument('--remove-all-existing-snapshots',
                        dest='clear_snaps',
                        action='store_true')

    return parser.parse_args()


def parse_input(args):
    state = State().instance

    with open(args.inputfile, 'r') as f:
        data = json.load(f)

    if 'vm_uuid' not in data and 'vm_name' not in data:
        raise KeyError('Either `vm_name` or `vm_uuid` must be supplied in input data')

    for key in ('vm_uuid', 'vm_name'):
        if key in data:
            if key not in state.keys():
                state[key] = data[key]
            elif state[key] != data[key]:
                raise ValueError('Mismatch in values for key `%s`: "%s" != "%s"' %
                                 (key, state[key], data[key]))

    for key in ('vmware_uri', 'vmware_fingerprint', 'pwdfile', 'statefile'):
        if key not in data:
            raise KeyError('Missing `%s` in input data' % key)
        if state['sync_type'] == 'initial':
            state[key] = data[key]
        elif state[key] != data[key]:
            raise ValueError('Mismatch in values for key `%s`: "%s" != "%s"' %
                             (key, state[key], data[key]))

    if 'loglevel' in data:
        if data['loglevel'] not in ('ERROR', 'WARNING', 'INFO', 'DEBUG'):
            raise ValueError('Unknown loglevel: %s' % data['loglevel'])
        state['loglevel'] = data['loglevel']
    else:
        state['loglevel'] = 'ERROR'

    state['insecure_connection'] = data.get('insecure_connection', False)


def main():
    '''TODO: Add some description here '''

    args = parse_args()
    state = State(args).instance
    validate_state(args.sync_type)
    parse_input(args)
    log_config(filename=state.get('logfile'),
               level=getattr(logging, state['loglevel']))

    logging.info('Connecting')

    with open(state['pwdfile'], 'r') as f:
        password = f.read().rstrip()
        conn = connect(state['vmware_uri'],
                       password,
                       fingerprint=state['vmware_fingerprint'])
    logging.info('Gathering data')
    vm = get_vm(conn, state['vm_name'])

    if args.sync_type == 'initial' and args.clear_snaps:
        while vm.snapshot:
            snapshot = vm.snapshot.rootSnapshotList[0].snapshot
            logging.debug('Removing snapshot %s with children' % snapshot)
            # It ought to be faster to remove whole snapshot chains at a time
            WaitForTask(snapshot.Remove(removeChildren=True))

    # TODO: Check all the limitations from
    # https://pubs.vmware.com/vsphere-50/topic/com.vmware.ICbase/PDF/vddk_prog_guide.pdf
    validate_state_vm(vm)

    last_snapshot = None
    if args.sync_type != 'final':
        logging.info('Creating snapshot')
        create_snapshot(vm)
        last_snapshot = vm.snapshot.currentSnapshot

    state['internal']['last_snapshot'] = last_snapshot

    logging.info('Gathering extents data')
    get_extents(vm)

    logging.info('Copying data')
    sync_data()

    if last_snapshot:
        logging.debug('Cleaning up created snapshot')
        WaitForTask(last_snapshot.Remove(removeChildren=True))

    logging.debug('Looks like everything went fine')
    state['status'] = 'Completed'
    state.write()


if __name__ == '__main__':
    # TODO: remove ipdb
    from ipdb import launch_ipdb_on_exception
    with launch_ipdb_on_exception():
        main()

    sys.exit(0)
