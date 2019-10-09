#!/usr/bin/env python
#
# vim: foldmethod=marker foldlevel=99
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

import errno
import json
import logging
import os
import pycurl
import re
import signal
import subprocess
import stat
import sys
import six
import tempfile
import time

from .singleton import State, StateHandler
from .common import error, hard_error, log_command_safe
from .hosts import BaseHost
from .runners import SystemdRunner
from .log_parser import log_parser
from .checks import CHECKS


if six.PY2:
    DEVNULL = open(os.devnull, 'r+')
else:
    xrange = range
    DEVNULL = subprocess.DEVNULL

# Wrapper version
VERSION = "22"

LOG_LEVEL = logging.DEBUG
STATE_DIR = '/tmp'


############################################################################
#
#  Routines {{{
#

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

    # Re-initialize cURL. This is necessary to re-initialze the PKCS #11
    # security tokens in NSS. Otherwise any use of SDK after the fork() would
    # lead to the error:
    #
    #    A PKCS #11 module returned CKR_DEVICE_ERROR, indicating that a
    #    problem has occurred with the token or slot.
    #
    pycurl.global_cleanup()
    pycurl.global_init(pycurl.GLOBAL_ALL)


def prepare_command(data, v2v_caps, agent_sock=None):
    state = State().instance
    v2v_args = [
        '-v', '-x',
        '--root', 'first',
        '--machine-readable=file:{}'.format(state.machine_readable_log),
        '-on', data['dest_vm_name'],
    ]
    if not data['two_phase']:
        v2v_args.append(data['vm_name'])
    elif data['transport_method'] != 'vddk':
        raise RuntimeError("Two-phase is supported only with vddk")

    if data['transport_method'] == 'vddk':
        if data['two_phase']:
            v2v_args.extend([
                '-i', 'libvirtxml',
                state['internal']['pre_copy']['libvirtxml'],
                '--no-copy',
                '--debug-overlays',
            ])
        else:
            v2v_args.extend([
                '-i', 'libvirt',
                '-ic', data['vmware_uri'],
                '-it', 'vddk',
                '-io', 'vddk-libdir=%s' % '/opt/vmware-vix-disklib-distrib',
                '-io', 'vddk-thumbprint=%s' % data['vmware_fingerprint'],
                '--password-file', data['vmware_password_file'],
            ])
    elif data['transport_method'] == 'ssh':
        v2v_args.extend([
            '-i', 'vmx',
            '-it', 'ssh',
        ])

    if 'network_mappings' in data:
        for mapping in data['network_mappings']:
            if 'mac_address' in mapping and 'mac-option' in v2v_caps:
                v2v_args.extend(['--mac', '%s:bridge:%s' %
                                (mapping['mac_address'],
                                    mapping['destination'])])
            else:
                v2v_args.extend(['--bridge', '%s:%s' %
                                (mapping['source'], mapping['destination'])])

    if 'luks_keys_files' in data:
        for luks_key in data['luks_keys_files']:
            v2v_args.extend([
                '--key',
                '%s:file:%s' % (
                    luks_key['device'],
                    luks_key['filename']
                )
            ])

    # Prepare environment
    v2v_env = os.environ.copy()
    v2v_env['LANG'] = 'C'
    if 'backend' in data:
        if data['backend'] == 'direct':
            logging.debug('Using direct backend. Hack, hack...')
        v2v_env['LIBGUESTFS_BACKEND'] = data['backend']
    if 'virtio_win' in data:
        v2v_env['VIRTIO_WIN'] = data['virtio_win']
    if agent_sock is not None:
        v2v_env['SSH_AUTH_SOCK'] = agent_sock

    return (v2v_args, v2v_env)


def throttling_update(runner, initial=None):
    """ Update throttling """
    state = State().instance
    if initial is not None:
        throttling = initial
    else:
        # Read from throttling file
        try:
            with open(state['internal']['throttling_file']) as f:
                throttling = json.load(f)
            # Remove file when finished to prevent spamming logs with repeated
            # messages
            os.remove(state['internal']['throttling_file'])
            logging.info('Fetched updated throttling info from file')
        except IOError as e:
            if e.errno != errno.ENOENT:
                error('Failed to read throttling file', exception=True)
            return
        except ValueError:
            error('Failed to read throttling file', exception=True)
            return

    # Throttling works only when we have (temporary) systemd unit. We do the
    # check here and not at the beginning because we want the throttling file
    # to be removed. We don't want to spam logs with repeated messages.
    if not isinstance(runner, SystemdRunner):
        logging.warn(
            'Not applying throttling because virt-v2v is not in systemd unit')
        return

    processed = {}
    for k, v in six.iteritems(throttling):
        if k == 'cpu':
            if v is None or v == 'unlimited':
                # Treat empty value and 'unlimited' in the same way
                val = 'unlimited'
                set_val = ''
            else:
                m = re.match("([+0-9]+)%?$", v)
                if m is not None:
                    val = r'%s%%' % m.group(1)
                    set_val = val
                else:
                    error(
                        'Failed to parse value for CPU limit',
                        'Failed to parse value for CPU limit: %s', v)
                    continue
            if val != state['throttling']['cpu'] and \
                    runner.systemd_set_property('CPUQuota', set_val):
                processed[k] = val
            else:
                error(
                    'Failed to set CPU limit',
                    'Failed to set CPU limit to %s', val)
        elif k == 'network':
            if v is None or v == 'unlimited':
                # Treat empty value and 'unlimited' in the same way
                val = 'unlimited'
                set_val = 'unlimited'
            else:
                m = re.match("([+0-9]+)$", v)
                if m is not None:
                    val = m.group(1)
                    set_val = val
                else:
                    error(
                        'Failed to parse value for network limit',
                        'Failed to parse value for network limit: %s', v)
                    continue
            if val != state['throttling']['network'] and \
                    runner.set_network_limit(set_val):
                logging.debug(
                    'Changing network throttling to %s (previous: %s)',
                    val, state['throttling']['network'])
                processed[k] = val
            else:
                error(
                    'Failed to set network limit',
                    'Failed to set network limit to %s', val)
        else:
            logging.debug('Ignoring unknown throttling request: %s', k)
    state['throttling'].update(processed)
    logging.info('New throttling setup: %r', state['throttling'])


def wrapper(host, data, v2v_caps, agent_sock=None):
    state = State().instance
    v2v_args, v2v_env = prepare_command(data, v2v_caps, agent_sock)
    v2v_args, v2v_env = host.prepare_command(data, v2v_args, v2v_env, v2v_caps)

    if 'XDG_RUNTIME_DIR' in v2v_env and host.get_uid() != 0:
        # Drop XDG_RUNTIME_DIR from environment. Otherwise it would "leak"
        # throuh our su/sudo call and would cause permissions error for
        # virt-v2v.
        #
        # https://bugzilla.redhat.com/show_bug.cgi?id=967509
        logging.info('Dropping XDG_RUNTIME_DIR from environment.')
        del v2v_env['XDG_RUNTIME_DIR']

    logging.info('Starting virt-v2v:')
    log_command_safe(v2v_args, v2v_env)

    runner = host.create_runner(v2v_args, v2v_env, state.v2v_log)
    try:
        runner.run()
    except RuntimeError as e:
        error('Failed to start virt-v2v', exception=True)
        state['failed'] = True
        state.write()
        return
    state['pid'] = runner.pid
    if 'throttling' in data:
        throttling_update(runner, data['throttling'])

    try:
        state['started'] = True
        state.write()
        with log_parser(not data['daemonize']) as parser:
            while runner.is_running():
                state = parser.parse(state)
                state.write()
                host.update_progress()
                throttling_update(runner)
                time.sleep(5)
            logging.info(
                'virt-v2v terminated with return code %d',
                runner.return_code)
            state = parser.parse(state)
    except Exception:
        state['failed'] = True
        error('Error while monitoring virt-v2v', exception=True)
        logging.info('Killing virt-v2v process')
        runner.kill()

    state['return_code'] = runner.return_code
    state.write()

    if state['return_code'] != 0:
        state['failed'] = True
    state.write()


def write_password(password, password_files, uid, gid):
    pfile = tempfile.mkstemp(suffix='.v2v')
    password_files.append(pfile[1])
    os.fchown(pfile[0], uid, gid)
    os.write(pfile[0], bytes(password.encode('utf-8')))
    os.close(pfile[0])
    return pfile[1]


def spawn_ssh_agent(data, uid, gid):
    cmd = [
        'setpriv', '--reuid=%d' % uid, '--regid=%d' % gid, '--clear-groups',
        'ssh-agent']
    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            stdin=DEVNULL)
    except subprocess.CalledProcessError as e:
        error('Failed to start ssh-agent', exception=True)
        logging.error('Command failed with: %s', e.output)
        return None, None
    logging.debug('ssh-agent: %s' % out)
    sock = re.search(br'^SSH_AUTH_SOCK=([^;]+);', out, re.MULTILINE)
    pid = re.search(br'^echo Agent pid ([0-9]+);', out, re.MULTILINE)
    if not sock or not pid:
        error(
            'Error starting ssh-agent',
            'Incomplete match of ssh-agent output; sock=%r; pid=%r',
            sock, pid)
        return None, None
    try:
        agent_sock = sock.group(1)
        agent_pid = int(pid.group(1))
    except ValueError:
        error('Failed to parse ssh-agent output', exception=True)
        return None, None
    logging.info('SSH Agent started with PID %d', agent_pid)
    env = os.environ.copy()
    env['SSH_AUTH_SOCK'] = agent_sock
    cmd = [
        'setpriv', '--reuid=%d' % uid, '--regid=%d' % gid, '--clear-groups',
        'ssh-add']
    if 'ssh_key_file' in data:
        logging.info('Using custom SSH key')
        cmd.append(data['ssh_key_file'])
    else:
        logging.info('Using SSH key(s) from ~/.ssh')
    try:
        out = subprocess.check_output(
            cmd,
            env=env,
            stderr=subprocess.STDOUT,
            stdin=DEVNULL)
    except subprocess.CalledProcessError as e:
        error('Failed to add SSH keys to the agent', exception=True)
        logging.error("ssh-add output: %s", e.output)
        os.kill(agent_pid, signal.SIGTERM)
        return None, None
    return agent_pid, agent_sock


def virt_v2v_capabilities():
    try:
        out = subprocess.check_output(['virt-v2v', u'--machine-readable'])
        return out.decode('utf-8').split('\n')
    except subprocess.CalledProcessError:
        logging.exception('Failed to start virt-v2v')
        return None


#  }}}
#
############################################################################
#
#  Main {{{
#

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '--checks':
            for check in CHECKS.keys():
                print("%s" % check)
            sys.exit(0)
        if sys.argv[1][:8] == '--check-':
            check = CHECKS.get(sys.argv[1][8:])
            if check is not None and check():
                sys.exit(0)
            else:
                sys.exit(1)
        if sys.argv[1] == '--version':
            print('virt-v2v-wrapper %s' % VERSION)
            sys.exit(0)

    state = State().instance

    # Read and parse input -- hopefully this should be safe to do as root
    data = json.load(sys.stdin)

    # Fill in defaults
    if 'daemonize' not in data:
        data['daemonize'] = state.daemonize
    else:
        state.daemonize = data['daemonize']

    host_type = BaseHost.detect(data)
    host = BaseHost.factory(host_type)

    # The logging is delayed after we now which user runs the wrapper.
    # Otherwise we would have two logs.
    log_tag = host.get_tag()
    log_dirs = host.get_logs()
    state.v2v_log = os.path.join(log_dirs[0], 'v2v-import-%s.log' % log_tag)
    state.machine_readable_log = os.path.join(
        log_dirs[0], 'v2v-import-%s-mr.log' % log_tag)
    wrapper_log = os.path.join(log_dirs[1],
                               'v2v-import-%s-wrapper.log' % log_tag)
    state.state_file = os.path.join(STATE_DIR, 'v2v-import-%s.state' % log_tag)
    pre_copy_dirname = 'v2v-import-%s-precopy' % log_tag
    state['internal']['pre_copy'] = {
        'libvirtxml': os.path.join(STATE_DIR, 'v2v-import-%s.xml' % log_tag),
        'tempdir': os.path.join(STATE_DIR, pre_copy_dirname),
        'logdir': os.path.join(log_dirs[1], pre_copy_dirname),
    }
    os.mkdir(state['internal']['pre_copy']['tempdir'])
    os.chown(state['internal']['pre_copy']['tempdir'],
             host.get_uid(), host.get_gid())

    os.mkdir(state['internal']['pre_copy']['logdir'])
    throttling_file = os.path.join(STATE_DIR,
                                   'v2v-import-%s.throttle' % log_tag)
    state['internal']['throttling_file'] = throttling_file

    log_format = '%(asctime)s:%(levelname)s:' \
        + ' %(message)s (%(module)s:%(lineno)d)'
    logging.basicConfig(
        level=LOG_LEVEL,
        filename=wrapper_log,
        format=log_format)

    state_log_handler = StateHandler()
    state_log_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(state_log_handler)

    logging.info('Wrapper version %s, uid=%d', VERSION, os.getuid())

    logging.info('Will store virt-v2v log in: %s', state.v2v_log)
    logging.info('Will store state file in: %s', state.state_file)
    logging.info('Will read throttling limits from: %s', throttling_file)

    password_files = []

    # Collect virt-v2v capabilities
    virt_v2v_caps = virt_v2v_capabilities()
    if virt_v2v_caps is None:
        hard_error('Could not get virt-v2v capabilities.')
    logging.debug("virt-v2v capabilities: %r" % virt_v2v_caps)

    try:

        # Make sure all the needed keys are in data. This is rather poor
        # validation, but...
        if 'vm_name' not in data:
                hard_error('Missing vm_name')

        # TODO: asdf
        logging.warning('Oh Gods, do something with this')
        data['dest_vm_name'] = data['vm_name'].replace(' ', '_')

        # Transports (only VDDK for now)
        if 'transport_method' not in data:
            hard_error('No transport method specified')
        if data['transport_method'] not in ('ssh', 'vddk'):
            hard_error('Unknown transport method: %s',
                       data['transport_method'])

        if data['transport_method'] == 'vddk':
            for k in [
                    'vmware_fingerprint',
                    'vmware_uri',
                    'vmware_password',
            ]:
                if k not in data:
                    hard_error('Missing argument: %s' % k)

        # Network mappings
        if 'network_mappings' in data:
            if isinstance(data['network_mappings'], list):
                for mapping in data['network_mappings']:
                    if not all(
                            k in mapping for k in ("source", "destination")):
                        hard_error('Both "source" and "destination"'
                                   ' must be provided in network mapping')
            else:
                hard_error('"network_mappings" must be an array')
        else:
            data['network_mappings'] = []

        # Virtio drivers
        if 'virtio_win' in data:
            # This is for backward compatibility
            data['install_drivers'] = True
        if 'install_drivers' in data:
            host.check_install_drivers(data)
        else:
            data['install_drivers'] = False

        if 'warm' not in data:
            data['warm'] = False
        if 'two_phase'not in data:
            data['two_phase'] = bool(data['warm'])

        if data['warm'] and not data['two_phase']:
            hard_error('Warm conversion requires also two-phase conversion ' +
                       'and cannot be performed without it')
        if data['two_phase']:
            if data['transport_method'] != 'vddk':
                hard_error('Two-phase conversion requires ' +
                           'vddk transport method')
            # Disk syncing has more requirements, let's load them only when
            # they are actually needed
            from . import pre_copy
            pre_copy.prepare(data)

        # Method dependent validation
        data = host.validate_data(data)

        #
        # NOTE: don't use hard_error() beyond this point!
        #

        # Store password(s)
        logging.info('Writing password file(s)')
        if 'vmware_password' in data:
            data['vmware_password_file'] = write_password(
                data['vmware_password'], password_files,
                host.get_uid(), host.get_gid())
        if 'rhv_password' in data:
            data['rhv_password_file'] = write_password(data['rhv_password'],
                                                       password_files,
                                                       host.get_uid(),
                                                       host.get_gid())
        if 'ssh_key' in data:
            data['ssh_key_file'] = write_password(data['ssh_key'],
                                                  password_files,
                                                  host.get_uid(),
                                                  host.get_gid())

        if 'luks_keys_vault' not in data:
            data['luks_keys_vault'] = os.path.join(
                os.environ['HOME'],
                '.v2v_luks_keys_vault.json'
            )
        if os.path.exists(data['luks_keys_vault']):
            file_stat = os.stat(data['luks_keys_vault'])
            if file_stat.st_uid != host.get_uid():
                hard_error('LUKS keys vault does\'nt belong to'
                           'user running virt-v2v-wrapper')
            if file_stat.st_mode & stat.S_IRWXO > 0:
                hard_error('LUKS keys vault is accessible to others')
            if file_stat.st_mode & stat.S_IRWXG > 0:
                hard_error('LUKS keys vault is accessible to group')
            luks_keys_vault = json.load(data['luks_keys_vault'])
            if data['vm_name'] in luks_keys_vault:
                data['luks_keys_files'] = []
                for luks_key in luks_keys_vault[data['vm_name']]:
                    data['luks_keys_files'].append({
                        'device': luks_key['device'],
                        'filename': write_password(luks_key['key'],
                                                   password_files,
                                                   host.get_uid(),
                                                   host.get_gid())
                    })

        try:
            if 'source_disks' in data:
                logging.debug('Initializing disk list from %r',
                              data['source_disks'])
                for d in data['source_disks']:
                    state['disks'].append({
                        'path': d,
                        'progress': 0})
                logging.debug('Internal disk list: %r', state['disks'])
                state['disk_count'] = len(data['source_disks'])
            # Create state file before dumping the JSON
            state.write()

            # Send some useful info on stdout in JSON
            outinfo = {
                'v2v_log': state.v2v_log,
                'wrapper_log': wrapper_log,
                'state_file': state.state_file,
                'throttling_file': throttling_file,
            }
            if data['two_phase']:
                outinfo['pre_copy_logdir'] = state['internal']['pre_copy']['logdir']
            print(json.dumps(outinfo))

            # Let's get to work
            if 'daemonize' not in data or data['daemonize']:
                logging.info('Daemonizing')
                daemonize()
            else:
                logging.info('Staying in foreground as requested')
                handler = logging.StreamHandler(sys.stdout)
                handler.setLevel(logging.DEBUG)
                # TODO: drop junk from virt-v2v log
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                logging.getLogger().addHandler(handler)
            agent_pid = None
            agent_sock = None
            if data['transport_method'] == 'ssh':
                agent_pid, agent_sock = spawn_ssh_agent(
                    data, host.get_uid(), host.get_gid())
                if agent_pid is None:
                    raise RuntimeError('Failed to start ssh-agent')
            if data['two_phase']:
                pre_copy.connect(data)
                host.create_disks(data)
                host.attach_disks(data)
                pre_copy.prepare_libvirtxml(data, host)
                if data['warm']:
                    pre_copy.actually_sync_disks_but_first_please_rename_and_implement_me()
                else:
                    pre_copy.start_nbdkits(data)
                    pre_copy.qemu_img_convert(data)
            wrapper(host, data, virt_v2v_caps, agent_sock)
            if agent_pid is not None:
                os.kill(agent_pid, signal.SIGTERM)
            if not state.get('failed', False):
                if data['two_phase']:
                    pre_copy.commit_overlays()
                state['failed'] = not host.handle_finish(data, state)
        except Exception as e:
            # No need to log the exception, it will get logged below
            error(e.args and e.args[0] or "Unknown error",
                  'An error occured, finishing state file...',
                  exception=True)
            state['failed'] = True
            state.write()
            raise
        finally:
            if 'pre_copy' in globals():
                logging.info('Cleaning up pre-copy stuff')
                pre_copy.cleanup()
            if state.get('failed', False):
                # Perform cleanup after failed conversion
                logging.debug('Cleanup phase')
                try:
                    host.handle_cleanup(data, state)
                finally:
                    state['finished'] = True
                    state.write()

        # Remove password files
        logging.info('Removing password files')
        for f in password_files:
            try:
                os.remove(f)
            except OSError:
                error('Error removing password file(s)',
                      'Error removing password file: %s' % f,
                      exception=True)

        state['finished'] = True
        state.write()

    except Exception:
        logging.exception('Wrapper failure')
        if 'pre_copy' in globals():
            pre_copy.cleanup()
        # Remove password files
        logging.info('Removing password files')
        for f in password_files:
            try:
                os.remove(f)
            except OSError:
                error('Error removing password file(s)',
                      'Error removing password file: %s' % f,
                      exception=True)
        # Always make sure the state is marked as finished
        state['finished'] = True
        state.write()
        # Re-raise original error
        raise

    logging.info('Finished')
    if state['failed']:
        sys.exit(2)


# }}}
if __name__ == '__main__':
    main()
