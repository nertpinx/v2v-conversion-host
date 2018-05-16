#!/usr/bin/python2
#
# Copyright (c) 2018 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from contextlib import contextmanager
import json
import logging
import os
import re
import sys
import tempfile
import time

import ovirtsdk4 as sdk
import six

from urlparse import urlparse

if six.PY2:
    import subprocess32 as subprocess
else:
    import subprocess
    xrange = range

LOG_LEVEL = logging.DEBUG
STATE_DIR = '/tmp'
VDSM_LOG_DIR = '/var/log/vdsm/import'
VDSM_MOUNTS = '/rhev/data-center/mnt'
VDSM_UID = 36
VDSM_CA = '/etc/pki/vdsm/certs/cacert.pem'

# For now there are limited possibilities in how we can select allocation type
# and format. The best thing we can do now is to base the allocation on type of
# target storage domain.
PREALLOCATED_STORAGE_TYPES = (
    sdk.types.StorageType.CINDER,
    sdk.types.StorageType.FCP,
    sdk.types.StorageType.GLUSTERFS,
    sdk.types.StorageType.ISCSI,
    sdk.types.StorageType.POSIXFS,
    )

# Tweaks
VDSM = False
DIRECT_BACKEND = not VDSM


def error(msg):
    """
    Function to produce an error and terminate the wrapper.

    WARNING: This can be used only at the early initialization stage! Do NOT
    use this once the password files are written or there are any other
    temporary data that should be removed at exit. This function uses
    sys.exit() which overcomes the code responsible for removing the files.
    """
    logging.error(msg)
    sys.stderr.write(msg)
    sys.exit(1)


def make_vdsm():
    """Makes sure the process runs as vdsm user"""
    uid = os.geteuid()
    if uid == VDSM_UID:
        logging.debug('Already running as vdsm user')
        return
    elif uid == 0:
        logging.debug('Restarting as vdsm user')
        os.chdir('/')
        cmd = '/usr/bin/sudo'
        args = [cmd, '-u', 'vdsm']
        args.extend(sys.argv)
        os.execv(cmd, args)
    sys.stderr.write('Need to run as vdsm user or root!\n')
    sys.exit(1)


def daemonize():
    """Properly deamonizes the process and closes file desriptors."""
    sys.stderr.flush()
    sys.stdout.flush()

    pid = os.fork()
    if pid != 0:
        # Nothing more to do for the parent
        sys.exit(0)

    os.setsid()
    pid = os.fork()
    if pid != 0:
        # Nothing more to do for the parent
        sys.exit(0)

    os.umask(0)
    os.chdir('/')

    dev_null = open('/dev/null', 'w')
    os.dup2(dev_null.fileno(), sys.stdin.fileno())
    os.dup2(dev_null.fileno(), sys.stdout.fileno())
    os.dup2(dev_null.fileno(), sys.stderr.fileno())


class OutputParser(object):

    COPY_DISK_RE = re.compile(br'.*Copying disk (\d+)/(\d+) to.*')
    DISK_PROGRESS_RE = re.compile(br'\s+\((\d+\.\d+)/100%\)')
    NBDKIT_DISK_PATH_RE = re.compile(
        br'nbdkit: debug: Opening file (.*) \(.*\)')

    def __init__(self, v2v_log):
        self._log = open(v2v_log, 'rbU')
        self._current_disk = None
        self._current_path = None

    def parse(self, state):
        line = None
        while line != b'':
            line = self._log.readline()
            m = self.COPY_DISK_RE.match(line)
            if m is not None:
                try:
                    self._current_disk = int(m.group(1))-1
                    self._current_path = None
                    state['disk_count'] = int(m.group(2))
                    logging.info('Copying disk %d/%d',
                                 self._current_disk+1, state['disk_count'])
                    if state['disk_count'] != len(state['disks']):
                        logging.warning(
                            'Number of supplied disk paths (%d) does not match'
                            ' number of disks in VM (%s)',
                            len(state['disks']),
                            state['disk_count'])
                except ValueError:
                    logging.exception('Conversion error')

            m = self.NBDKIT_DISK_PATH_RE.match(line)
            if m is not None:
                self._current_path = m.group(1).decode()
                if self._current_disk is not None:
                    logging.info('Copying path: %s', self._current_path)
                    self._locate_disk(state)

            m = self.DISK_PROGRESS_RE.match(line)
            if m is not None:
                if self._current_path is not None and \
                        self._current_disk is not None:
                    try:
                        state['disks'][self._current_disk]['progress'] = \
                            float(m.group(1))
                        logging.debug('Updated progress: %s', m.group(1))
                    except ValueError:
                        logging.exception('Conversion error')
                else:
                    logging.debug('Skipping progress update for unknown disk')
        return state

    def close(self):
        self._log.close()

    def _locate_disk(self, state):
        if self._current_disk is None:
            # False alarm, not copying yet
            return

        # NOTE: We assume that _current_disk is monotonic
        for i in xrange(self._current_disk, len(state['disks'])):
            if state['disks'][i]['path'] == self._current_path:
                if i == self._current_disk:
                    # We have correct index
                    logging.debug('Found path at correct index')
                else:
                    # Move item to current index
                    logging.debug('Moving path from index %d to %d', i,
                                  self._current_disk)
                    d = state['disks'].pop(i)
                    state['disks'].insert(self._current_disk, d)
                return

        # Path not found
        logging.debug('Path \'%s\' not found in %r', self._current_path,
                      state['disks'])
        state['disks'].insert(
            self._current_disk,
            {
                'path': self._current_path,
                'progress': 0,
            })


@contextmanager
def log_parser(v2v_log):
    parser = None
    try:
        parser = OutputParser(v2v_log)
        yield parser
    finally:
        if parser is not None:
            parser.close()


@contextmanager
def sdk_connection(data):
    connection = None
    url = urlparse(data['rhv_url'])
    username = url.username if url.username is not None else 'admin@internal'
    try:
        connection = sdk.Connection(
            url=str(data['rhv_url']),
            username=str(username),
            password=str(data['rhv_password']),
            ca_file=str(data['rhv_cafile']),
            log=logging.getLogger(),
        )
        yield connection
    finally:
        if connection is not None:
            connection.close()


def is_iso_domain(path):
    """
    Check if domain is ISO domain. @path is path to domain metadata file
    """
    try:
        logging.debug('is_iso_domain check for %s', path)
        with open(path, 'r') as f:
            for line in f:
                if line.rstrip() == 'CLASS=Iso':
                    return True
    except OSError:
        logging.exception('Failed to read domain metadata')
    return False


def find_iso_domain():
    """
    Find path to the ISO domain from available domains mounted on host
    """
    if not os.path.isdir(VDSM_MOUNTS):
        logging.error('Cannot find RHV domains')
        return None
    for sub in os.walk(VDSM_MOUNTS):

        if 'dom_md' in sub[1]:
            # This looks like a domain so focus on metadata only
            try:
                del sub[1][sub[1].index('master')]
            except ValueError:
                pass
            try:
                del sub[1][sub[1].index('images')]
            except ValueError:
                pass
            continue

        if 'metadata' in sub[2] and \
                os.path.basename(sub[0]) == 'dom_md' and \
                is_iso_domain(os.path.join(sub[0], 'metadata')):
            return os.path.join(
                os.path.dirname(sub[0]),
                'images',
                '11111111-1111-1111-1111-111111111111')
    return None


def write_state(state):
    with open(state_file, 'w') as f:
        json.dump(state, f)


def wrapper(data, state_file, v2v_log):
    v2v_args = [
        '/usr/bin/virt-v2v', '-v', '-x',
        data['vm_name'],
        '-ic', data['vmware_uri'],
        '--password-file', data['vmware_password_file'],
        '-of', data['output_format'],
        '--bridge', 'ovirtmgmt',
    ]

    if data['transport_method'] == 'vddk':
        v2v_args.extend([
            '-it', 'vddk',
            '-io', 'vddk-libdir=%s' % '/opt/vmware-vix-disklib-distrib',
            '-io', 'vddk-thumbprint=%s' % data['vmware_fingerprint'],
            ])

    if 'rhv_url' in data:
        v2v_args.extend([
            '-o', 'rhv-upload',
            '-oc', data['rhv_url'],
            '-os', data['rhv_storage'],
            '-op', data['rhv_password_file'],
            '-oo', 'rhv-cafile=%s' % data['rhv_cafile'],
            '-oo', 'rhv-cluster=%s' % data['rhv_cluster'],
            '-oo', 'rhv-direct',
            ])
    elif 'export_domain' in data:
        v2v_args.extend([
            '-o', 'rhv',
            '-os', data['export_domain'],
            ])

    if 'allocation' in data:
        v2v_args.extend([
            '-oa', data['allocation']
            ])

    if 'network_mappings' in data:
        for mapping in data['network_mappings']:
            v2v_args.extend(['--bridge', '%s:%s' %
                            (mapping['source'], mapping['destination'])])

    # Prepare environment
    env = os.environ.copy()
    env['LANG'] = 'C'
    if DIRECT_BACKEND:
        logging.debug('Using direct backend. Hack, hack...')
        env['LIBGUESTFS_BACKEND'] = 'direct'
    if 'virtio_win' in data:
        env['VIRTIO_WIN'] = data['virtio_win']

    proc = None
    with open(v2v_log, 'w') as log:
        logging.info('Starting virt-v2v as: %r', v2v_args)
        proc = subprocess.Popen(
                v2v_args,
                stderr=subprocess.STDOUT,
                stdout=log,
                env=env,
                )

    try:
        state = {
            'started': True,
            'pid': proc.pid,
            'disks': [],
            }
        if 'source_disks' in data:
            logging.debug('Initializing disk list from %r',
                          data['source_disks'])
            for d in data['source_disks']:
                state['disks'].append({
                    'path': d,
                    'progress': 0})
            state['disk_count'] = len(data['source_disks'])

        write_state(state)
        with log_parser(v2v_log) as parser:
            while proc.poll() is None:
                state = parser.parse(state)
                write_state(state)
                time.sleep(5)
            logging.info('virt-v2v terminated with return code %d',
                         proc.returncode)
            state = parser.parse(state)
    except Exception:
        logging.exception('Error while monitoring virt-v2v')
        if proc.poll() is None:
            logging.info('Killing virt-v2v process')
            proc.kill()

    state['return_code'] = proc.returncode
    write_state(state)

    if proc.returncode != 0:
        state['failed'] = True
    state['finished'] = True
    write_state(state)


def write_password(password, password_files):
    pfile = tempfile.mkstemp(suffix='.v2v')
    password_files.append(pfile[1])
    os.write(pfile[0], bytes(password.encode('utf-8')))
    os.close(pfile[0])
    return pfile[1]


###########

log_tag = '%s-%d' % (time.strftime('%Y%m%dT%H%M%S'), os.getpid())
v2v_log = os.path.join(VDSM_LOG_DIR, 'v2v-import-%s.log' % log_tag)
wrapper_log = os.path.join(VDSM_LOG_DIR, 'v2v-import-%s-wrapper.log' % log_tag)
state_file = os.path.join(STATE_DIR, 'v2v-import-%s.state' % log_tag)

logging.basicConfig(
    level=LOG_LEVEL,
    filename=wrapper_log,
    format='%(asctime)s:%(levelname)s: %(message)s (%(module)s:%(lineno)d)')

if VDSM:
    make_vdsm()

logging.info('Will store virt-v2v log in: %s', v2v_log)
logging.info('Will store state file in: %s', state_file)

password_files = []

try:
    logging.info('Processing input data')
    data = json.load(sys.stdin)

    # Make sure all the needed keys are in data. This is rather poor
    # validation, but...
    for k in [
            'vm_name',
            'vmware_fingerprint',
            'vmware_uri',
            'vmware_password',
            ]:
        if k not in data:
            error('Missing argument: %s' % k)

    # Output file format (raw or qcow2)
    if 'output_format' in data:
        if data['output_format'] not in ('raw', 'qcow2'):
            error('Invalid output format %r, expected raw or qcow2' %
                  data['output_format'])
    else:
        data['output_format'] = 'raw'

    # Transports (only VDDK for now)
    if 'transport_method' not in data:
        error('No transport method specified')
    if data['transport_method'] != 'vddk':
        error('Unknown transport method: %s', data['transport_method'])

    # Targets (only export domain for now)
    if 'rhv_url' in data:
        for k in [
                'rhv_cluster',
                'rhv_password',
                'rhv_storage',
                ]:
            if k not in data:
                error('Missing argument: %s' % k)
        if 'rhv_cafile' not in data:
            logging.info('Path to CA certificate not specified,'
                         ' trying VDSM default: %s', VDSM_CA)
            data['rhv_cafile'] = VDSM_CA
    elif 'export_domain' in data:
        pass
    else:
        error('No target specified')

    # Network mappings
    if 'network_mappings' in data:
        if isinstance(data['network_mappings'], list):
            for mapping in data['network_mappings']:
                if not all (k in mapping for k in ("source", "destination")):
                    error("Both 'source' and 'destination' must be provided in network mapping")
        else:
            error("'network_mappings' must be an array")

    # Virtio drivers
    if 'virtio_win' in data:
        if not os.path.isabs(data['virtio_win']):
            iso_domain = find_iso_domain()
            if iso_domain is None:
                error('ISO domain not found')
            full_path = os.path.join(iso_domain, data['virtio_win'])
        else:
            full_path = data['virtio_win']
        if not os.path.isfile(full_path):
            error("'virtio_win' must be a path or file name of image in "
                  "ISO domain")
        data['virtio_win'] = full_path
        logging.info("virtio_win (re)defined as: %s", data['virtio_win'])

    # Allocation type
    if 'allocation' in data:
        if data['allocation'] not in ('preallocated', 'sparse'):
            error('Invalid value for allocation type: %r' % data['allocation'])
    else:
        # Check storage domain type and decide on suitable allocation type
        # Note: This is only temporary. We should get the info from the caller in
        # the future.
        domain_type = None
        with sdk_connection(data) as c:
            service = c.system_service().storage_domains_service()
            domains = service.list(search='name="%s"' % str(data['rhv_storage']))
            if len(domains) != 1:
                error('Found %d domains matching "%s"!' % data['rhv_storage'])
            domain_type = domains[0].storage.type
        logging.info('Storage domain "%s" is of type %r', data['rhv_storage'],
                    domain_type)
        data['allocation'] = 'sparse'
        if domain_type in PREALLOCATED_STORAGE_TYPES:
            data['allocation'] = 'preallocated'
        logging.info('... selected allocation type is %s', data['allocation'])

    #
    # NOTE: don't use error() beyond this point!
    #

    # Store password(s)
    logging.info('Writing password file(s)')
    data['vmware_password_file'] = write_password(data['vmware_password'],
                                                  password_files)
    if 'rhv_password' in data:
        data['rhv_password_file'] = write_password(data['rhv_password'],
                                                   password_files)

    # Send some useful info on stdout in JSON
    print(json.dumps({
        'v2v_log': v2v_log,
        'wrapper_log': wrapper_log,
        'state_file': state_file,
    }))

    # Let's get to work
    logging.info('Daemonizing')
    daemonize()
    wrapper(data, state_file, v2v_log)

    # Remove password files
    logging.info('Removing password files')
    for f in password_files:
        try:
            os.remove(f)
        except OSError:
            logging.exception('Error while removing password file: %s' % f)

except Exception:
    logging.exception('Wrapper failure')
    # Remove password files
    logging.info('Removing password files')
    for f in password_files:
        try:
            os.remove(f)
        except OSError:
            logging.exception('Error removing password file: %s' % f)
    # Re-raise original error
    raise

logging.info('Finished')