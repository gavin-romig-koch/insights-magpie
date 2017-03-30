#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: magpie
short_description: Gathers extended facts about remote hosts
options:
    None
description:
     - This module gathers extended facts for the Magpie system.
author:
    - "Gavin Romig-Koch"
'''

EXAMPLES = """
# Gather extended facts
# ansible all -m magpie

"""

import os
import re
from subprocess import Popen, PIPE, STDOUT
import errno
import shlex
import logging
import six
import copy
from tempfile import NamedTemporaryFile

OLD_STYLE_ARCHIVE = True


# from constants import InsightsConstants as constants
#class InsightsConstants(object):
class constants(object):
    app_name = 'insights-client'
    version = '2.0.5-5'
    auth_method = 'BASIC'
    log_level = 'DEBUG'
    package_path = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    sleep_time = 300
    user_agent = os.path.join(app_name, 'version')
    default_conf_dir = '/etc/' + app_name + '/'
    log_dir = os.path.join(os.sep, 'var', 'log', app_name)
    default_log_file = os.path.join(log_dir, app_name) + '.log'
    default_conf_file_name = app_name + '.conf'
    default_conf_file = os.path.join(default_conf_dir, default_conf_file_name)
    default_sed_file = os.path.join(default_conf_dir, '.exp.sed')
    default_ca_file = os.path.join(default_conf_dir, 'cert-api.access.redhat.com.pem')
    base_url = 'cert-api.access.redhat.com/r/insights'
    collection_rules_file = os.path.join(default_conf_dir, '.cache.json')
    collection_fallback_file = os.path.join(default_conf_dir, '.fallback.json')
    collection_remove_file_name = 'remove.conf'
    collection_remove_file = os.path.join(default_conf_dir, collection_remove_file_name)
    unregistered_file = os.path.join(default_conf_dir, '.unregistered')
    registered_file = os.path.join(default_conf_dir, '.registered')
    lastupload_file = os.path.join(default_conf_dir, '.lastupload')
    pub_gpg_path = os.path.join(default_conf_dir, 'redhattools.pub.gpg')
    machine_id_file = os.path.join(default_conf_dir, 'machine-id')
    docker_group_id_file = os.path.join(default_conf_dir, 'docker-group-id')
    default_target = [{'type': 'host', 'name': ''}]
    default_branch_info = {'remote_branch': -1, 'remote_leaf': -1}
    docker_image_name = None
    default_cmd_timeout = 600  # default command execution to ten minutes, prevents long running commands that will hang

logger = logging.getLogger(constants.app_name)


class InsightsSpec(object):
    '''
    A spec loaded from the uploader.json
    '''
    def __init__(self, spec, exclude):
        # exclusions patterns for this spec
        self.exclude = exclude
        # pattern for spec collection
        self.pattern = spec['pattern'] if spec['pattern'] else None
        # absolute destination inside the archive for this spec
        self.archive_path = spec['archive_file_name']



def _make_sed_cmd():
    if False:
        cmd = []
        cmd.append("/bin/sed".encode('utf-8'))
        cmd.append("-rf".encode('utf-8'))
        cmd.append(constants.default_sed_file.encode('utf-8'))
        return cmd
    else:
        return ["/bin/cat".encode('utf-8')]

class InsightsCommand(InsightsSpec):
    '''
    A command spec
    '''
    def __init__(self, spec, exclude, mountpoint, target_name, config=None):
        InsightsSpec.__init__(self, spec, exclude)
        # substitute mountpoint for collection
        # have to use .replace instead of .format because there are other
        #  braced keys in the collection spec not used here
        self.command = spec['command'].replace(
            '{CONTAINER_MOUNT_POINT}', mountpoint).replace(
            '{DOCKER_IMAGE_NAME}', target_name).replace(
            '{DOCKER_CONTAINER_NAME}', target_name)
        self.mangled_command = self._mangle_command(self.command)
        # have to re-mangle archive path in case there's a pre-command arg
        self.archive_path = os.path.join(
            os.path.dirname(self.archive_path), self.mangled_command)
        if not six.PY3:
            self.command = self.command.encode('utf-8', 'ignore')
        self.black_list = ['rm', 'kill', 'reboot', 'shutdown']
        self.config = config

    def _mangle_command(self, command, name_max=255):
        """
        Mangle the command name, lifted from sos
        """
        mangledname = re.sub(r"^/(usr/|)(bin|sbin)/", "", command)
        mangledname = re.sub(r"[^\w\-\.\/]+", "_", mangledname)
        mangledname = re.sub(r"/", ".", mangledname).strip(" ._-")
        mangledname = mangledname[0:name_max]
        return mangledname

    def get_output(self):
        '''
        Execute a command through system shell. First checks to see if
        the requested command is executable. Returns (returncode, stdout, 0)
        '''
        # all commands should timeout after a long interval so the client does not hang
        # get the command timeout interval
        if self.config and self.config.has_option(constants.app_name, 'cmd_timeout'):
            timeout_interval = self.config.getint(constants.app_name, 'cmd_timeout')
        else:
            timeout_interval = constants.default_cmd_timeout

        # prepend native nix 'timeout' implementation
        timeout_command = 'timeout %s %s' % (timeout_interval, self.command)

        # ensure consistent locale for collected command output
        cmd_env = {'LC_ALL': 'C'}
        args = shlex.split(timeout_command)

        # never execute this stuff
        if set.intersection(set(args), set(self.black_list)):
            raise RuntimeError("Command Blacklist")

        try:
            logger.debug('Executing: %s', args)
            proc0 = Popen(args, shell=False, stdout=PIPE, stderr=STDOUT,
                          bufsize=-1, env=cmd_env, close_fds=True)
        except OSError as err:
            if err.errno == errno.ENOENT:
                logger.debug('Command %s not found', self.command)
                return
            else:
                raise err

        dirty = False

        sedcmd = Popen(_make_sed_cmd(),
                       stdin=proc0.stdout,
                       stdout=PIPE)
        proc0.stdout.close()
        proc0 = sedcmd

        if self.exclude is not None:
            exclude_file = NamedTemporaryFile()
            exclude_file.write("\n".join(self.exclude))
            exclude_file.flush()
            cmd = "/bin/grep -F -v -f %s" % exclude_file.name
            proc1 = Popen(shlex.split(cmd.encode("utf-8")),
                          stdin=proc0.stdout,
                          stdout=PIPE)
            proc0.stdout.close()
            stderr = None
            if self.pattern is None or len(self.pattern) == 0:
                stdout, stderr = proc1.communicate()

            # always log return codes for debug
            logger.debug('Proc1 Status: %s', proc1.returncode)
            logger.debug('Proc1 stderr: %s', stderr)
            proc0 = proc1

            # if the return code was not zero
            # indicates timeout or absence
            if proc1.returncode > 0:
                logger.debug('Process return code indicates timeout or absence.')
                # no command indicates timeout
                if not self.cmd_exists(self.command):
                    logger.debug('Command %s not found.', self.command)
                else:
                    logger.debug('Command %s found. Timeout occurred.', self.command)

            dirty = True

        if self.pattern is not None and len(self.pattern):
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(self.pattern))
            pattern_file.flush()
            cmd = "/bin/grep -F -f %s" % pattern_file.name
            proc2 = Popen(shlex.split(cmd.encode("utf-8")),
                          stdin=proc0.stdout,
                          stdout=PIPE)
            proc0.stdout.close()
            stdout, stderr = proc2.communicate()

            # always log return codes for debug
            logger.debug('Proc2 Status: %s', proc2.returncode)
            logger.debug('Proc2 stderr: %s', stderr)

            # if the return code was not zero
            # indicates timeout or absence
            if proc2.returncode > 0:
                logger.debug('Process return code indicates timeout or absence.')
                # no command indicates timeout
                if not self.cmd_exists(self.command):
                    logger.debug('Command %s not found.', self.command)
                else:
                    logger.debug('Command %s found. Timeout occurred.', self.command)

            dirty = True

        if not dirty:
            stdout, stderr = proc0.communicate()

        # Required hack while we still pass shell=True to Popen; a Popen
        # call with shell=False for a non-existant binary will raise OSError.
        if proc0.returncode == 126 or proc0.returncode == 127:
            stdout = "Could not find cmd: %s", self.command

        logger.debug("Proc0 Status: %s", proc0.returncode)
        logger.debug("Proc0 stderr: %s", stderr)
        return stdout.decode('utf-8', 'ignore')

    def cmd_exists(self, command):
        """
        Check if a command exists using native which
        Returns False if 'which' does not find the command path
        Otherwise returns True
        """
        args = shlex.split("which %s" % (command))
        logger.debug('Checking %s command exists.', args[1])
        proc_check = Popen([args[0], args[1]], shell=False, stdout=PIPE, stderr=STDOUT,
                           bufsize=-1, close_fds=True)
        stdout, stderr = proc_check.communicate()
        logger.debug('Which returns %s for %s.', proc_check.returncode, args[1])
        if proc_check.returncode > 0:
            return False
        else:
            return True


class InsightsFile(InsightsSpec):
    '''
    A file spec
    '''
    def __init__(self, spec, exclude, mountpoint, target_name):
        InsightsSpec.__init__(self, spec, exclude)
        # substitute mountpoint for collection
        self.real_path = spec['file'].replace(
            '{CONTAINER_MOUNT_POINT}', mountpoint).replace(
            '{DOCKER_IMAGE_NAME}', target_name).replace(
            '{DOCKER_CONTAINER_NAME}', target_name)
        self.relative_path = spec['file'].replace(
            '{CONTAINER_MOUNT_POINT}', '').replace(
            '{DOCKER_IMAGE_NAME}', target_name).replace(
            '{DOCKER_CONTAINER_NAME}', target_name)
        self.archive_path = self.archive_path.replace('{EXPANDED_FILE_NAME}', self.real_path)

    def get_output(self):
        '''
        Get file content, selecting only lines we are interested in
        '''
        if not os.path.isfile(self.real_path):
            logger.debug('File %s does not exist', self.real_path)
            return

        logger.debug('Copying %s to %s with filters %s',
                     self.real_path, self.archive_path, str(self.pattern))

        cmd = _make_sed_cmd()
        cmd.append(self.real_path.encode('utf8'))
        sedcmd = Popen(cmd,
                       stdout=PIPE)

        if self.exclude is not None:
            exclude_file = NamedTemporaryFile()
            exclude_file.write("\n".join(self.exclude))
            exclude_file.flush()

            cmd = "/bin/grep -v -F -f %s" % exclude_file.name
            args = shlex.split(cmd.encode("utf-8"))
            proc = Popen(args, stdin=sedcmd.stdout, stdout=PIPE)
            sedcmd.stdout.close()
            stdin = proc.stdout
            if self.pattern is None:
                output = proc.communicate()[0]
            else:
                sedcmd = proc

        if self.pattern is not None:
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(self.pattern))
            pattern_file.flush()

            cmd = "/bin/grep -F -f %s" % pattern_file.name
            args = shlex.split(cmd.encode("utf-8"))
            proc1 = Popen(args, stdin=sedcmd.stdout, stdout=PIPE)
            sedcmd.stdout.close()

            if self.exclude is not None:
                stdin.close()

            output = proc1.communicate()[0]

        if self.pattern is None and self.exclude is None:
            output = sedcmd.communicate()[0]

        return output.decode('utf-8', 'ignore').strip()

class DictInsightsArchive(object):

    """
    This class is an interface for adding command output
    and files to the insights archive
    """

    def __init__(self):
        """
        Initialize the Dict Insights Archive
        This is just like an Insights Archive except it stores stuff in a dictionary
        """
        self.archive_dict = {}

    def add_to_archive(self, spec):
        '''
        Add files and commands to archive
        Use InsightsSpec.get_output() to get data
        '''
        self.archive_dict[spec.archive_path.lstrip('/')] = spec.get_output()

    def add_metadata_to_archive(self, metadata, meta_path):
        '''
        Add metadata to archive
        '''
        self.archive_dict[meta_path.lstrip('/')] = metadata


def _expand_paths(path):
    """
    Expand wildcarded paths
    """
    import re
    dir_name = os.path.dirname(path)
    paths = []
    logger.debug("Attempting to expand %s", path)
    if os.path.isdir(dir_name):
        files = os.listdir(dir_name)
        match = os.path.basename(path)
        for file_path in files:
            if re.match(match, file_path):
                expanded_path = os.path.join(dir_name, file_path)
                paths.append(expanded_path)
        logger.debug("Expanded paths %s", paths)
        return paths
    else:
        logger.debug("Could not expand %s", path)

class DataCollector(object):
    '''
    Run commands and collect files
    '''
    def __init__(self, archive_=None, config=None, mountpoint=None, target_name='', target_type='host'):
        self.archive = archive_ if archive_ else archive.InsightsArchive()
        self.mountpoint = '/'
        if mountpoint:
            self.mountpoint = mountpoint
        self.target_name = target_name
        self.target_type = target_type
        self.config = config

    def _get_meta_path(self, specname, conf):
        # should really never need these
        #   since spec should always have an "archive_file_name"
        #   unless we are running old style spec
        default_meta_spec = {'analysis_target': '/insights_data/analysis_target',
                             'branch_info': '/branch_info',
                             'machine-id': '/insights_data/machine-id',
                             'uploader_log': '/insights_data/insights_logs/insights.log'}
        try:
            archive_path = conf['meta_specs'][specname]['archive_file_name']
        except LookupError:
            logger.debug('%s spec not found. Using default.', specname)
            archive_path = default_meta_spec[specname]
        return archive_path

    def _write_branch_info(self, conf, branch_info):
        logger.debug("Writing branch information to archive...")
        self.archive.add_metadata_to_archive(json.dumps(branch_info),
                                             self._get_meta_path('branch_info', conf))

    def _write_analysis_target_type(self, conf):
        logger.debug('Writing target type to archive...')
        self.archive.add_metadata_to_archive(self.target_type,
                                             self._get_meta_path('analysis_target', conf))

    def _write_analysis_target_id(self, conf):
        if False:
            # AKA machine-id
            logger.debug('Writing machine-id to archive...')
            machine_id = generate_analysis_target_id(self.target_type, self.target_name)
            self.archive.add_metadata_to_archive(machine_id,
                                                 self._get_meta_path('machine-id', conf))

    def _write_uploader_log(self, conf):
        if False:
            logger.debug('Writing insights.log to archive...')
            with open(constants.default_log_file) as logfile:
                self.archive.add_metadata_to_archive(logfile.read().strip(),
                                                     self._get_meta_path('uploader_log', conf))

    def _run_pre_command(self, pre_cmd):
        '''
        Run a pre command to get external args for a command
        '''
        logger.debug('Executing pre-command: %s', pre_cmd)
        try:
            pre_proc = Popen(pre_cmd, stdout=PIPE, stderr=STDOUT, shell=True)
        except OSError as err:
            if err.errno == errno.ENOENT:
                logger.debug('Command %s not found', pre_cmd)
            return
        stdout, stderr = pre_proc.communicate()
        the_return_code = pre_proc.poll()
        logger.debug("Pre-command results:")
        logger.debug("STDOUT: %s", stdout)
        logger.debug("STDERR: %s", stderr)
        logger.debug("Return Code: %s", the_return_code)
        if the_return_code != 0:
            return []
        return stdout.splitlines()

    def _parse_file_spec(self, spec):
        '''
        Separate wildcard specs into more specs
        '''
        # separate wildcard specs into more specs
        if '*' in spec['file']:
            expanded_paths = _expand_paths(spec['file'].replace(
                '{CONTAINER_MOUNT_POINT}', self.mountpoint).replace(
                '{DOCKER_IMAGE_NAME}', self.target_name).replace(
                '{DOCKER_CONTAINER_NAME}', self.target_name))
            if not expanded_paths:
                return []

            expanded_specs = []
            for p in expanded_paths:
                _spec = copy.copy(spec)
                _spec['file'] = p
                expanded_specs.append(_spec)
            return expanded_specs

        else:
            return [spec]

    def _parse_glob_spec(self, spec):
        '''
        Grab globs of things
        '''
        import glob
        some_globs = glob.glob(spec['glob'])
        if not some_globs:
            return []
        el_globs = []
        for g in some_globs:
            _spec = copy.copy(spec)
            _spec['file'] = g
            el_globs.append(_spec)
        return el_globs

    def _parse_command_spec(self, spec, precmds):
        '''
        Run pre_commands
        '''
        if 'pre_command' in spec:
            precmd_alias = spec['pre_command']
            try:
                precmd = precmds[precmd_alias]
                args = self._run_pre_command(precmd)
                logger.debug('Pre-command results: %s', args)

                expanded_specs = []
                for arg in args:
                    _spec = copy.copy(spec)
                    _spec['command'] = _spec['command'] + ' ' + arg
                    expanded_specs.append(_spec)
                return expanded_specs
            except LookupError:
                logger.debug('Pre-command %s not found. Skipping %s...',
                             precmd_alias, spec['command'])
                return []
        else:
            return [spec]

    def _run_old_collection(self, conf, rm_conf, exclude, branch_info):
        # wrap old collection into specs for backward compatibility
        for f in conf['files']:
            if rm_conf and 'files' in rm_conf and f['file'] in rm_conf['files']:
                logger.warn("WARNING: Skipping file %s", f['file'])
                continue
            else:
                file_specs = self._parse_file_spec(f)
                for s in file_specs:
                    # spoof archive_file_name
                    # use _, archive path will be re-mangled anyway
                    s['archive_file_name'] = s['file']
                    file_spec = InsightsFile(s, exclude, self.mountpoint, self.target_name)
                    self.archive.add_to_archive(file_spec)
        for c in conf['commands']:
            if rm_conf and 'commands' in rm_conf and c['command'] in rm_conf['commands']:
                logger.warn("WARNING: Skipping command %s", c['command'])
                continue
            else:
                cmd_specs = self._parse_command_spec(c, conf['pre_commands'])
                for s in cmd_specs:
                    # spoof archive_file_name, will be reassembled in InsightsCommand()
                    s['archive_file_name'] = os.path.join('insights_commands', '_')
                    cmd_spec = InsightsCommand(s, exclude, self.mountpoint, self.target_name, self.config)
                    self.archive.add_to_archive(cmd_spec)
        logger.debug('Spec collection finished.')
        # collect metadata
        logger.debug('Collecting metadata...')
        self._write_branch_info(conf, branch_info)
        logger.debug('Metadata collection finished.')

    def run_collection(self, conf, rm_conf, branch_info):
        '''
        Run specs and collect all the data
        '''
        logger.debug('Beginning to run collection spec...')
        exclude = None
        if rm_conf:
            try:
                exclude = rm_conf['patterns']
            except LookupError:
                logger.debug('Could not parse remove.conf. Ignoring...')

        if 'specs' not in conf or OLD_STYLE_ARCHIVE: # or InsightsClient.options.original_style_specs:
            # old style collection
            self._run_old_collection(conf, rm_conf, exclude, branch_info)
            return

        for specname in conf['specs']:
            try:
                # spec group for a symbolic name
                spec_group = conf['specs'][specname]
                # list of specs for a target
                # there might be more than one spec (for compatability)
                spec_list = spec_group[self.target_type]
                for spec in spec_list:
                    if 'file' in spec:
                        if rm_conf and 'files' in rm_conf and spec['file'] in rm_conf['files']:
                            logger.warn("WARNING: Skipping file %s", spec['file'])
                            continue
                        else:
                            file_specs = self._parse_file_spec(spec)
                            for s in file_specs:
                                file_spec = InsightsFile(s, exclude, self.mountpoint, self.target_name)
                                self.archive.add_to_archive(file_spec)
                    elif 'glob' in spec:
                        glob_specs = self._parse_glob_spec(spec)
                        for g in glob_specs:
                            if rm_conf and 'files' in rm_conf and g['file'] in rm_conf['files']:
                                logger.warn("WARNING: Skipping file %s", g)
                                continue
                            else:
                                glob_spec = InsightsFile(g, exclude, self.mountpoint, self.target_name)
                                self.archive.add_to_archive(glob_spec)
                    elif 'command' in spec:
                        if rm_conf and 'commands' in rm_conf and spec['command'] in rm_conf['commands']:
                            logger.warn("WARNING: Skipping command %s", spec['command'])
                            continue
                        else:
                            cmd_specs = self._parse_command_spec(spec, conf['pre_commands'])
                            for s in cmd_specs:
                                cmd_spec = InsightsCommand(s, exclude, self.mountpoint, self.target_name, self.config)
                                self.archive.add_to_archive(cmd_spec)
            except LookupError:
                logger.debug('Target type %s not found in spec %s. Skipping...', self.target_type, specname)
                continue
        logger.debug('Spec collection finished.')

        # collect metadata
        logger.debug('Collecting metadata...')
        self._write_analysis_target_type(conf)
        self._write_branch_info(conf, branch_info)
        self._write_analysis_target_id(conf)
        logger.debug('Metadata collection finished.')

    def done(self, conf, rm_conf):
        """
        Do finalization stuff
        """
        self._write_uploader_log(conf)
        return self.archive.archive_dict

def magpie_facts(module):
    dc = DataCollector(archive_=DictInsightsArchive())
    dc.run_collection(specs, None, None)
    return dc.done(specs, None)

def main():
    import yaml
    print(yaml.dump(magpie_facts(None),default_flow_style=False))

def ansible_main():
    module = AnsibleModule(
        argument_spec = dict(
        ),
        supports_check_mode = True,
    )

    if False:
        result = get_all_facts(module)
        #i don't know why i do the following
        #del result['ansible_facts']['module_setup']
    else:
        result = dict(ansible_facts={})

    for (k, v) in magpie_facts(module).items():
        # newer versions of insights-client replace dashes with underscores
        result['ansible_facts']["magpie_%s" % (k if OLD_STYLE_ARCHIVE else k.replace('-', '_'))] = v

    module.exit_json(**result)

specs = {
    "files": [
        {
            "pattern": [],
            "file": "/boot/grub/grub.conf"
        },
        {
            "pattern": [],
            "file": "/boot/grub2/grub.cfg"
        },
        {
            "pattern": [
                "no_root_squash"
            ],
            "file": "/etc/()*exports"
        },
        {
            "pattern": [
                "</policymap>",
                "<policy",
                "<policymap>"
            ],
            "file": "/etc/ImageMagick/()*policy\\.xml"
        },
        {
            "pattern": [],
            "file": "/etc/audit/auditd.conf"
        },
        {
            "pattern": [],
            "file": "/etc/ceilometer/ceilometer.conf"
        },
        {
            "pattern": [],
            "file": "/etc/chrony.conf"
        },
        {
            "pattern": [],
            "file": "/etc/cinder/cinder.conf"
        },
        {
            "pattern": [
                "<lvm",
                "clusternode name="
            ],
            "file": "/etc/cluster/cluster.conf"
        },
        {
            "pattern": [
                "no_root_squash"
            ],
            "file": "/etc/exports.d/()*.*\\.exports"
        },
        {
            "pattern": [],
            "file": "/etc/fstab"
        },
        {
            "pattern": [],
            "file": "/etc/haproxy/haproxy.cfg"
        },
        {
            "pattern": [],
            "file": "/etc/heat/heat.conf"
        },
        {
            "pattern": [],
            "file": "/etc/hosts"
        },
        {
            "pattern": [
                "</IfModule>",
                "<IfModule prefork.c>",
                "<IfModule worker.c>",
                "FcgidPassHeader",
                "MaxClients",
                "NSSProtocol",
                "RequestHeader",
                "SSLCipherSuite",
                "SSLProtocol"
            ],
            "file": "/etc/httpd/conf.d/()*.+\\.conf"
        },
        {
            "pattern": [
                "</IfModule>",
                "<IfModule prefork.c>",
                "<IfModule worker.c>",
                "FcgidPassHeader",
                "MaxClients",
                "NSSProtocol",
                "RequestHeader",
                "SSLCipherSuite",
                "SSLProtocol"
            ],
            "file": "/etc/httpd/conf/()*httpd\\.conf"
        },
        {
            "pattern": [],
            "file": "/etc/kdump.conf"
        },
        {
            "pattern": [
                "auto_activation_volume_list",
                "filter",
                "locking_type",
                "volume_list"
            ],
            "file": "/etc/lvm/lvm.conf"
        },
        {
            "pattern": [],
            "file": "/etc/modprobe.conf"
        },
        {
            "pattern": [],
            "file": "/etc/modprobe.d/()*.*\\.conf"
        },
        {
            "pattern": [],
            "file": "/etc/multipath.conf"
        },
        {
            "pattern": [],
            "file": "/etc/my.cnf.d/galera.cnf"
        },
        {
            "pattern": [],
            "file": "/etc/neutron/plugin.ini"
        },
        {
            "pattern": [],
            "file": "/etc/nova/nova.conf"
        },
        {
            "pattern": [
                "enable-cache"
            ],
            "file": "/etc/nscd.conf"
        },
        {
            "pattern": [
                "HOSTS:",
                "hosts:"
            ],
            "file": "/etc/nsswitch.conf"
        },
        {
            "pattern": [],
            "file": "/etc/ntp.conf"
        },
        {
            "pattern": [],
            "file": "/etc/origin/node/node-config.yaml"
        },
        {
            "pattern": [
                "ENGINE_TMP="
            ],
            "file": "/etc/ovirt-engine/engine.conf.d/()*.*"
        },
        {
            "pattern": [],
            "file": "/etc/pam.d/password-auth"
        },
        {
            "pattern": [],
            "file": "/etc/pam.d/vsftpd"
        },
        {
            "pattern": [],
            "file": "/etc/rc.d/rc.local"
        },
        {
            "pattern": [],
            "file": "/etc/redhat-access-insights/machine-id"
        },
        {
            "pattern": [],
            "file": "/etc/redhat-release"
        },
        {
            "pattern": [],
            "file": "/etc/redhat_access_proactive/machine-id"
        },
        {
            "pattern": [],
            "file": "/etc/resolv.conf"
        },
        {
            "pattern": [],
            "file": "/etc/rhn/rhn.conf"
        },
        {
            "pattern": [
                "imtcp",
                "regex"
            ],
            "file": "/etc/rsyslog.conf"
        },
        {
            "pattern": [
                "REALM",
                "SECURITY",
                "realm",
                "security"
            ],
            "file": "/etc/samba/smb.conf"
        },
        {
            "pattern": [],
            "file": "/etc/security/limits.conf"
        },
        {
            "pattern": [],
            "file": "/etc/security/limits.d/()*.*"
        },
        {
            "pattern": [],
            "file": "/etc/security/limits.d/()*.*-nproc\\.conf"
        },
        {
            "pattern": [],
            "file": "/etc/selinux/config"
        },
        {
            "pattern": [
                "ALLOWUSERS",
                "AllowUsers",
                "CHALLENGERESPONSEAUTHENTICATION",
                "CIPHERS",
                "CLIENTALIVECOUNTMAX",
                "CLIENTALIVEINTERVAL",
                "ChallengeResponseAuthentication",
                "Ciphers",
                "ClientAliveCountMax",
                "ClientAliveInterval",
                "DENYUSERS",
                "DenyUsers",
                "KBDINTERACTIVEAUTHENTICATION",
                "KbdInteractiveAuthentication",
                "LOGINGRACETIME",
                "LoginGraceTime",
                "MACS",
                "MACs",
                "MAXAUTHTRIES",
                "MAXSTARTUPS",
                "Macs",
                "MaxAuthTries",
                "MaxStartups",
                "PERMITEMPTYPASSWORDS",
                "PERMITROOTLOGIN",
                "PROTOCOL",
                "PermitEmptyPasswords",
                "PermitRootLogin",
                "Protocol",
                "USEPAM",
                "UsePAM",
                "UsePam",
                "allowusers",
                "challengeresponseauthentication",
                "ciphers",
                "clientalivecountmax",
                "clientaliveinterval",
                "denyusers",
                "kbdinteractiveauthentication",
                "logingracetime",
                "macs",
                "maxauthtries",
                "maxstartups",
                "permitemptypasswords",
                "permitrootlogin",
                "protocol",
                "usepam"
            ],
            "file": "/etc/ssh/sshd_config"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/corosync"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/docker"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/docker-storage-setup"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/netconsole"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/network-scripts/()*ifcfg-.*"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/ntpd"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/rhn/()*rhn-entitlement-cert\\.xml.*"
        },
        {
            "pattern": [],
            "file": "/etc/sysconfig/rhn/up2date"
        },
        {
            "pattern": [],
            "file": "/etc/sysctl.conf"
        },
        {
            "pattern": [],
            "file": "/etc/systemd/system.conf"
        },
        {
            "pattern": [],
            "file": "/etc/vdsm/vdsm.conf"
        },
        {
            "pattern": [],
            "file": "/etc/vdsm/vdsm.id"
        },
        {
            "pattern": [
                "LOCAL_ENABLE",
                "local_enable",
                "ssl_enable",
                "ssl_sslv3"
            ],
            "file": "/etc/vsftpd/vsftpd.conf"
        },
        {
            "pattern": [],
            "file": "/etc/xinetd.conf"
        },
        {
            "pattern": [],
            "file": "/etc/xinetd.d/()*.*"
        },
        {
            "pattern": [],
            "file": "/etc/yum.conf"
        },
        {
            "pattern": [],
            "file": "/etc/yum.repos.d/()*.*.repo"
        },
        {
            "pattern": [],
            "file": "/etc/yum/pluginconf.d/()*\\w+\\.conf"
        },
        {
            "pattern": [],
            "file": "/proc/cmdline"
        },
        {
            "pattern": [],
            "file": "/proc/cpuinfo"
        },
        {
            "pattern": [],
            "file": "/proc/driver/cciss/()*cciss.*"
        },
        {
            "pattern": [],
            "file": "/proc/interrupts"
        },
        {
            "pattern": [],
            "file": "/proc/mdstat"
        },
        {
            "pattern": [],
            "file": "/proc/meminfo"
        },
        {
            "pattern": [],
            "file": "/proc/net/bonding/()*bond.*"
        },
        {
            "pattern": [],
            "file": "/proc/net/netfilter/nfnetlink_queue"
        },
        {
            "pattern": [],
            "file": "/proc/scsi/scsi"
        },
        {
            "pattern": [],
            "file": "/sos_commands/process/ps_auxwww"
        },
        {
            "pattern": [],
            "file": "/sys/devices/system/clocksource/clocksource0/current_clocksource"
        },
        {
            "pattern": [],
            "file": "/sys/kernel/kexec_crash_loaded"
        },
        {
            "pattern": [],
            "file": "/sys/kernel/kexec_crash_size"
        },
        {
            "pattern": [],
            "file": "/sys/kernel/mm/ksm/run"
        },
        {
            "pattern": [
                "</policymap>",
                "<policy",
                "<policymap>"
            ],
            "file": "/usr/lib/ImageMagick-6.5.4/config/()*policy\\.xml"
        },
        {
            "pattern": [],
            "file": "/usr/lib/systemd/system/docker.service"
        },
        {
            "pattern": [
                "</policymap>",
                "<policy",
                "<policymap>"
            ],
            "file": "/usr/lib64/ImageMagick-6.5.4/config/()*policy\\.xml"
        },
        {
            "pattern": [],
            "file": "/usr/share/foreman/lib/satellite/version.rb"
        },
        {
            "pattern": [],
            "file": "/var/lib/pacemaker/cib/cib.xml"
        },
        {
            "pattern": [
                "ERROR:",
                "checkpoints are occurring too frequently"
            ],
            "file": "/var/lib/pgsql/data/pg_log/()*postgresql-.+\\.log"
        },
        {
            "pattern": [],
            "file": "/var/lib/pgsql/data/postgresql.conf"
        },
        {
            "pattern": [
                "Image cloning unsuccessful for image",
                "Message: NFS file could not be discovered.",
                "[Errno 24] Too many open files"
            ],
            "file": "/var/log/cinder/volume.log"
        },
        {
            "pattern": [
                "'Ifcfg' object has no attribute 'runningConfig",
                "Abort command issued",
                "DMA Status error.  Resetting chip",
                "Dazed and confused, but trying to continue",
                "Device offlined - not ready after error recovery",
                "Error running DeviceResume dm_task_run failed",
                "Machine",
                "Out of MCCQ wrbs",
                "Out of memory: kill process",
                "SCSI device reset on",
                "SELinux is preventing /usr/sbin/logrotate from getattr access on the file",
                "Sense Key : Illegal Request [current]",
                "Temperature above threshold",
                "Uhhuh. NMI received for unknown reason",
                "Virtualization daemon",
                "WATCHDOG",
                "WRITE SAME failed. Manually zeroing",
                "be2net",
                "blocked FC remote port time out",
                "dev_watchdog",
                "does not seem to be present, delaying initialization",
                "ext4_ext_search_left",
                "fiid_obj_get: 'present_countdown_value': data not available",
                "firewalld - dynamic firewall daemon",
                "heated above trip temperature",
                "irq handler for vector (irq -1)",
                "is beyond advertised capabilities",
                "kernel: CIFS VFS: Unexpected SMB signature",
                "kernel: bnx2fc: byte_count",
                "kernel: megasas: Found FW in FAULT state, will reset adapter.",
                "khash_super_prune_nolock",
                "megaraid_sas: FW detected to be in faultstate, restarting it",
                "mode:0x20",
                "modprobe: FATAL: Error inserting nfsd",
                "multipathd.service operation timed out. Terminating",
                "nf_conntrack: expectation table full",
                "nf_conntrack: table full, dropping packet",
                "page allocation failure",
                "per_source_limit from",
                "skb_copy",
                "skb_over_panic",
                "start request repeated too quickly for docker.service",
                "swapper: page allocation failure",
                "tg3_start_xmit",
                "timeout; kill it",
                "udevd"
            ],
            "file": "/var/log/messages"
        },
        {
            "pattern": [
                "No tenant network is available for allocation"
            ],
            "file": "/var/log/neutron/server.log"
        },
        {
            "pattern": [
                "Timed out waiting for a reply to message ID"
            ],
            "file": "/var/log/nova/nova-api.log"
        },
        {
            "pattern": [
                "Duplicate ID 'virtio-serial0' for device",
                "XML error: Multiple 'virtio-serial' controllers with index '0'",
                "[org.ovirt.engine.core.vdsbroker.VmsStatisticsFetcher]",
                "has paused due to storage I/O problem"
            ],
            "file": "/var/log/ovirt-engine/engine.log"
        },
        {
            "pattern": [
                "pcmk_dbus_find_error"
            ],
            "file": "/var/log/pacemaker.log"
        },
        {
            "pattern": [
                "Event crashed log handler:"
            ],
            "file": "/var/log/rabbitmq/startup_log"
        },
        {
            "pattern": [
                "error: session_pty_req: session"
            ],
            "file": "/var/log/secure"
        },
        {
            "pattern": [
                "(waitForMigrationDestinationPrepare)",
                "ImageIsNotLegalChain: Image is not a legal chain:",
                "ImagePathError: Image path does not exist or cannot be accessed/created:",
                "Migration is stuck: Hasn't progressed in",
                "The name org.fedoraproject.FirewallD1 was not provided by any .service files",
                "Timeout while waiting for path preparation"
            ],
            "file": "/var/log/vdsm/vdsm.log"
        },
        {
            "pattern": [
                "nss-softokn-3.14.3",
                "nss-softokn-freebl-3.14.3"
            ],
            "file": "/var/log/yum.log"
        },
        {
            "pattern": [],
            "file": "/var/log/redhat-access-insights/redhat-access-insights.log"
        },
        {
            "pattern": [],
            "file": "/var/log/redhat_access_proactive/redhat_access_proactive.log"
        }
    ],
    "meta_specs": {
        "analysis_target": {
            "archive_file_name": "/insights_data/analysis_target"
        },
        "branch_info": {
            "archive_file_name": "/branch_info"
        },
        "machine-id": {
            "archive_file_name": "/insights_data/machine-id"
        },
        "uploader_log": {
            "archive_file_name": "/insights_data/insights_logs/insights.log"
        }
    },
    "commands": [
        {
            "pattern": [],
            "command": "/bin/date"
        },
        {
            "pattern": [],
            "command": "/bin/date --utc"
        },
        {
            "pattern": [],
            "command": "/bin/df -alP"
        },
        {
            "pattern": [],
            "command": "/bin/df -li"
        },
        {
            "pattern": [
                "CSUM",
                "CVE-2016-5195",
                "Dropping TSO",
                "HP HPSA",
                "Linux version",
                "NUMA: ",
                "P220i",
                "P420i",
                "WRITE SAME failed. Manually zeroing",
                "blocked FC remote port time out",
                "crashkernel reservation failed",
                "crashkernel=auto resulted in zero bytes of reserved memory"
            ],
            "command": "/bin/dmesg"
        },
        {
            "pattern": [],
            "command": "/bin/hostname"
        },
        {
            "pattern": [],
            "command": "/bin/ls -l /boot/grub/grub.conf"
        },
        {
            "pattern": [],
            "command": "/bin/ls -l /boot/grub2/grub.cfg"
        },
        {
            "pattern": [],
            "command": "/bin/ls -l /etc/ssh/sshd_config"
        },
        {
            "pattern": [],
            "command": "/bin/ls -la /var/log /var/log/audit"
        },
        {
            "pattern": [],
            "command": "/bin/ls -lanR /boot"
        },
        {
            "pattern": [],
            "command": "/bin/ls -lanR /dev"
        },
        {
            "pattern": [],
            "command": "/bin/ls -lanR /dev/disk/by-*"
        },
        {
            "pattern": [],
            "command": "/bin/ls -lanR /etc"
        },
        {
            "pattern": [],
            "command": "/bin/ls -lanR /sys/firmware"
        },
        {
            "pattern": [],
            "command": "/bin/lsblk"
        },
        {
            "pattern": [],
            "command": "/bin/lsblk -P -o NAME,KNAME,MAJ:MIN,FSTYPE,MOUNTPOINT,LABEL,UUID,RA,RO,RM,MODEL,SIZE,STATE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,RQ-SIZE,TYPE,DISC-ALN,DISC-GRAN,DISC-MAX,DISC-ZERO"
        },
        {
            "pattern": [],
            "command": "/bin/lsinitrd /boot/initramfs-*kdump.img -f /etc/sysctl.conf /etc/sysctl.d/*.conf"
        },
        {
            "pattern": [],
            "command": "/bin/mount"
        },
        {
            "pattern": [],
            "command": "/bin/netstat -agn"
        },
        {
            "pattern": [],
            "command": "/bin/netstat -i"
        },
        {
            "pattern": [],
            "command": "/bin/netstat -neopa"
        },
        {
            "pattern": [],
            "command": "/bin/netstat -s"
        },
        {
            "pattern": [
                "/usr/bin/docker daemon",
                "/usr/bin/docker-current daemon",
                "COMMAND",
                "STAP",
                "chronyd",
                "keystone-all",
                "ntpd",
                "phc2sys",
                "ptp4l"
            ],
            "command": "/bin/ps aux"
        },
        {
            "pattern": [],
            "command": "/bin/ps auxcww"
        },
        {
            "pattern": [],
            "command": "/bin/rpm -V coreutils procps procps-ng shadow-utils passwd sudo"
        },
        {
            "pattern": [],
            "command": "/bin/rpm -qa --qf='%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME:date}\t%{BUILDTIME}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\n'"
        },
        {
            "pattern": [],
            "command": "/bin/systemctl list-unit-files"
        },
        {
            "pattern": [],
            "command": "/bin/systemctl show openstack-cinder-volume"
        },
        {
            "pattern": [],
            "command": "/bin/uname -a"
        },
        {
            "pattern": [],
            "command": "/sbin/chkconfig --list"
        },
        {
            "pattern": [],
            "pre_command": "iface",
            "command": "/sbin/dcbtool gc  dcb"
        },
        {
            "pattern": [],
            "pre_command": "dumpdev",
            "command": "/sbin/dumpe2fs -h"
        },
        {
            "pattern": [],
            "pre_command": "iface",
            "command": "/sbin/ethtool"
        },
        {
            "pattern": [],
            "pre_command": "iface",
            "command": "/sbin/ethtool -S"
        },
        {
            "pattern": [],
            "pre_command": "iface",
            "command": "/sbin/ethtool -g"
        },
        {
            "pattern": [],
            "pre_command": "iface",
            "command": "/sbin/ethtool -i"
        },
        {
            "pattern": [],
            "pre_command": "iface",
            "command": "/sbin/ethtool -k"
        },
        {
            "pattern": [],
            "command": "/sbin/ip -4 neighbor show nud all"
        },
        {
            "pattern": [],
            "command": "/sbin/ip -6 neighbor show nud all"
        },
        {
            "pattern": [],
            "command": "/sbin/ip addr"
        },
        {
            "pattern": [],
            "command": "/sbin/ip route show table all"
        },
        {
            "pattern": [],
            "command": "/sbin/iptables-save"
        },
        {
            "pattern": [],
            "command": "/sbin/lsmod"
        },
        {
            "pattern": [],
            "command": "/sbin/lspci"
        },
        {
            "pattern": [],
            "command": "/sbin/lvs --nameprefixes --noheadings --separator='|' -a -o lv_name,vg_name,lv_size,region_size,mirror_log,lv_attr,devices,region_size --config=\"global{locking_type=0}\""
        },
        {
            "pattern": [],
            "command": "/sbin/multipath -v4 -ll"
        },
        {
            "pattern": [],
            "command": "/sbin/pvs --nameprefixes --noheadings --separator='|' -a -o pv_all,vg_name --config=\"global{locking_type=0}\""
        },
        {
            "pattern": [],
            "command": "/sbin/sysctl -a"
        },
        {
            "pattern": [],
            "command": "/sbin/tuned-adm list"
        },
        {
            "pattern": [
                "Clustered",
                "Couldn't find device with uuid",
                "LV Name",
                "Mirrored volumes",
                "VG Name"
            ],
            "command": "/sbin/vgdisplay"
        },
        {
            "pattern": [],
            "command": "/sbin/vgs --nameprefixes --noheadings --separator='|' -a -o vg_all --config=\"global{locking_type=0}\""
        },
        {
            "pattern": [],
            "pre_command": "ceph_socket_files",
            "command": "/usr/bin/ceph daemon  config show"
        },
        {
            "pattern": [],
            "command": "/usr/bin/ceph osd dump -f json-pretty"
        },
        {
            "pattern": [],
            "command": "/usr/bin/chronyc sources"
        },
        {
            "pattern": [
                "heat-manage"
            ],
            "command": "/usr/bin/crontab -l -u heat"
        },
        {
            "pattern": [
                "heat-manage",
                "keystone-manage"
            ],
            "command": "/usr/bin/crontab -l -u keystone"
        },
        {
            "pattern": [
                "heat-manage"
            ],
            "command": "/usr/bin/crontab -l -u root"
        },
        {
            "pattern": [
                "ANSWER SECTION",
                "DNSKEY",
                "RRSIG"
            ],
            "command": "/usr/bin/dig +dnssec . DNSKEY"
        },
        {
            "pattern": [],
            "command": "/usr/bin/docker images --all --no-trunc --digests"
        },
        {
            "pattern": [],
            "command": "/usr/bin/docker info"
        },
        {
            "pattern": [],
            "command": "/usr/bin/docker inspect --type=container {DOCKER_CONTAINER_NAME}"
        },
        {
            "pattern": [],
            "command": "/usr/bin/docker ps --all --no-trunc --size"
        },
        {
            "pattern": [],
            "command": "/usr/bin/facter"
        },
        {
            "pattern": [],
            "command": "/usr/bin/file -L /etc/localtime"
        },
        {
            "pattern": [],
            "command": "/usr/bin/find /sys/devices/virtual/net/ -name multicast_querier -print -exec cat {} \\;"
        },
        {
            "pattern": [],
            "command": "/usr/bin/find /var/crash /var/tmp -path '*.reports-*/whoopsie-report'"
        },
        {
            "pattern": [],
            "command": "/usr/bin/lpstat -p"
        },
        {
            "pattern": [],
            "command": "/usr/bin/oc get project -o yaml --all-namespaces"
        },
        {
            "pattern": [],
            "command": "/usr/bin/oc get role -o yaml --all-namespaces"
        },
        {
            "pattern": [],
            "command": "/usr/bin/oc get rolebinding -o yaml --all-namespaces"
        },
        {
            "pattern": [],
            "pre_command": "crt",
            "command": "/usr/bin/openssl x509 -noout -enddate -in"
        },
        {
            "pattern": [],
            "command": "/usr/bin/ovs-vsctl show"
        },
        {
            "pattern": [],
            "command": "/usr/bin/uptime"
        },
        {
            "pattern": [],
            "command": "/usr/bin/yum -C repolist"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/blkid -c /dev/null"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/brctl show"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/dmidecode"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/getenforce"
        },
        {
            "pattern": [
                "COMMAND",
                "libcrypto",
                "libssl",
                "libssl.so"
            ],
            "command": "/usr/sbin/lsof"
        },
        {
            "pattern": [
                "DNSSEC-ENABLE",
                "dnssec-enable"
            ],
            "command": "/usr/sbin/named-checkconf -p"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/ntpq -c 'rv 0 leap'"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/ntpq -pn"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/ntptime"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/rabbitmqctl list_queues name messages consumers auto_delete"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/rabbitmqctl list_users"
        },
        {
            "pattern": [
                "total_limit"
            ],
            "command": "/usr/sbin/rabbitmqctl report"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/sestatus -b"
        },
        {
            "pattern": [],
            "command": "/usr/sbin/virt-what"
        }
    ],
    "pre_commands": {
        "ceph_socket_files": "/bin/ls /var/run/ceph/ceph-*.*.asok",
        "iface": "/sbin/ip -o link | awk -F ': ' '/.*link\\/ether/ {print $2}'",
        "crt": "/usr/bin/find /etc/origin/node /etc/origin/master -type f -path '*.crt'",
        "module": "/bin/ls /sys/module",
        "getblockschedulers": "for device in $(ls /sys/block); do echo /sys/block/$device/queue/scheduler; done",
        "block": "/bin/ls /sys/block | awk '!/^ram|^\\.+$/ {print \"/dev/\" $1 \" unit s print\"}'"
    },
    "version": "2017-03-20T11:09:05.869807",
    "specs": {
        "machine-id1": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/redhat-access-insights/machine-id",
                    "file": "/etc/redhat-access-insights/machine-id"
                }
            ]
        },
        "machine-id2": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/redhat_access_proactive/machine-id",
                    "file": "/etc/redhat_access_proactive/machine-id"
                }
            ]
        },
        "auditd.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/audit/auditd.conf",
                    "file": "/etc/audit/auditd.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/audit/auditd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/audit/auditd.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/audit/auditd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/audit/auditd.conf"
                }
            ]
        },
        "blkid": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/blkid -c /dev/null",
                    "archive_file_name": "/insights_commands/blkid_-c_.dev.null"
                }
            ]
        },
        "bond": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/proc/net/bonding/()*bond.*"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/net/bonding/()*bond.*"
                }
            ]
        },
        "brctl_show": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/brctl show",
                    "archive_file_name": "/insights_commands/brctl_show"
                }
            ]
        },
        "cciss": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/proc/driver/cciss/()*cciss.*"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/driver/cciss/()*cciss.*"
                }
            ]
        },
        "ceilometer.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/ceilometer/ceilometer.conf",
                    "file": "/etc/ceilometer/ceilometer.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/ceilometer/ceilometer.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ceilometer/ceilometer.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/ceilometer/ceilometer.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ceilometer/ceilometer.conf"
                }
            ]
        },
        "ceph_config_show": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "ceph_socket_files",
                    "command": "/usr/bin/ceph daemon  config show",
                    "archive_file_name": "/insights_commands/ceph_daemon__config_show"
                }
            ]
        },
        "ceph_osd_dump": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/ceph osd dump -f json-pretty",
                    "archive_file_name": "/insights_commands/ceph_osd_dump_-f_json-pretty"
                }
            ]
        },
        "chkconfig": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/chkconfig --list",
                    "archive_file_name": "/insights_commands/chkconfig_--list"
                }
            ]
        },
        "chrony.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/chrony.conf",
                    "file": "/etc/chrony.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/chrony.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/chrony.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/chrony.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/chrony.conf"
                }
            ]
        },
        "chronyc_sources": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/chronyc sources",
                    "archive_file_name": "/insights_commands/chronyc_sources"
                }
            ]
        },
        "cib.xml": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/var/lib/pacemaker/cib/cib.xml",
                    "file": "/var/lib/pacemaker/cib/cib.xml"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/var/lib/pacemaker/cib/cib.xml",
                    "file": "{CONTAINER_MOUNT_POINT}/var/lib/pacemaker/cib/cib.xml"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/var/lib/pacemaker/cib/cib.xml",
                    "file": "{CONTAINER_MOUNT_POINT}/var/lib/pacemaker/cib/cib.xml"
                }
            ]
        },
        "cinder.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/cinder/cinder.conf",
                    "file": "/etc/cinder/cinder.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/cinder/cinder.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/cinder/cinder.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/cinder/cinder.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/cinder/cinder.conf"
                }
            ]
        },
        "cinder_volume.log": {
            "host": [
                {
                    "pattern": [
                        "Image cloning unsuccessful for image",
                        "[Errno 24] Too many open files",
                        "Message: NFS file could not be discovered."
                    ],
                    "archive_file_name": "/var/log/cinder/volume.log",
                    "file": "/var/log/cinder/volume.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "Image cloning unsuccessful for image",
                        "[Errno 24] Too many open files",
                        "Message: NFS file could not be discovered."
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/cinder/volume.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/cinder/volume.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "Image cloning unsuccessful for image",
                        "[Errno 24] Too many open files",
                        "Message: NFS file could not be discovered."
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/cinder/volume.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/cinder/volume.log"
                }
            ]
        },
        "cluster.conf": {
            "host": [
                {
                    "pattern": [
                        "<lvm",
                        "clusternode name="
                    ],
                    "archive_file_name": "/etc/cluster/cluster.conf",
                    "file": "/etc/cluster/cluster.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "<lvm",
                        "clusternode name="
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/cluster/cluster.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/cluster/cluster.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "<lvm",
                        "clusternode name="
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/cluster/cluster.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/cluster/cluster.conf"
                }
            ]
        },
        "cmdline": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/proc/cmdline",
                    "file": "/proc/cmdline"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/proc/cmdline",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/cmdline"
                }
            ]
        },
        "corosync": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/sysconfig/corosync",
                    "file": "/etc/sysconfig/corosync"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/sysconfig/corosync",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/corosync"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/sysconfig/corosync",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/corosync"
                }
            ]
        },
        "cpuinfo": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/proc/cpuinfo",
                    "file": "/proc/cpuinfo"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/proc/cpuinfo",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/cpuinfo"
                }
            ]
        },
        "current_clocksource": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/sys/devices/system/clocksource/clocksource0/current_clocksource",
                    "file": "/sys/devices/system/clocksource/clocksource0/current_clocksource"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/sys/devices/system/clocksource/clocksource0/current_clocksource",
                    "file": "{CONTAINER_MOUNT_POINT}/sys/devices/system/clocksource/clocksource0/current_clocksource"
                }
            ]
        },
        "date": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/date",
                    "archive_file_name": "/insights_commands/date"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/date",
                    "archive_file_name": "/insights_data/container/commands/date"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/date",
                    "archive_file_name": "/insights_data/image/commands/date"
                }
            ]
        },
        "date_utc": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/date --utc",
                    "archive_file_name": "/insights_commands/date_--utc"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/date --utc",
                    "archive_file_name": "/insights_data/container/commands/date_--utc"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/date --utc",
                    "archive_file_name": "/insights_data/image/commands/date_--utc"
                }
            ]
        },
        "dcbtool_gc_dcb": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "iface",
                    "command": "/sbin/dcbtool gc  dcb",
                    "archive_file_name": "/insights_commands/dcbtool_gc__dcb"
                }
            ]
        },
        "df_-alP": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/df -alP",
                    "archive_file_name": "/insights_commands/df_-alP"
                }
            ]
        },
        "df_-li": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/df -li",
                    "archive_file_name": "/insights_commands/df_-li"
                }
            ]
        },
        "dig": {
            "host": [
                {
                    "pattern": [
                        "DNSKEY",
                        "ANSWER SECTION",
                        "RRSIG"
                    ],
                    "command": "/usr/bin/dig +dnssec . DNSKEY",
                    "archive_file_name": "/insights_commands/dig_dnssec_._DNSKEY"
                }
            ]
        },
        "dmesg": {
            "host": [
                {
                    "pattern": [
                        "crashkernel reservation failed",
                        "crashkernel=auto resulted in zero bytes of reserved memory",
                        "Linux version",
                        "P220i",
                        "WRITE SAME failed. Manually zeroing",
                        "blocked FC remote port time out",
                        "HP HPSA",
                        "Dropping TSO",
                        "P420i",
                        "CSUM",
                        "CVE-2016-5195",
                        "NUMA: "
                    ],
                    "command": "/bin/dmesg",
                    "archive_file_name": "/insights_commands/dmesg"
                }
            ]
        },
        "dmidecode": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/dmidecode",
                    "archive_file_name": "/insights_commands/dmidecode"
                }
            ]
        },
        "docker_container_inspect": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/docker inspect --type=container {DOCKER_CONTAINER_NAME}",
                    "archive_file_name": "/insights_data/dockerhost/commands/docker_inspect_--type_container_{DOCKER_CONTAINER_NAME}"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/usr/bin/docker inspect --type=container {DOCKER_CONTAINER_NAME}",
                    "archive_file_name": "/insights_data/container/dockerhost/commands/docker_inspect_--type_container_{DOCKER_CONTAINER_NAME}"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/usr/bin/docker inspect --type=container {DOCKER_CONTAINER_NAME}",
                    "archive_file_name": "/insights_data/image/dockerhost/commands/docker_inspect_--type_container_{DOCKER_CONTAINER_NAME}"
                }
            ]
        },
        "docker_host_machine-id": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/dockerhost/rootfs/etc/redhat-access-insights/machine-id",
                    "file": "/etc/redhat-access-insights/machine-id"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/dockerhost/rootfs/etc/redhat-access-insights/machine-id",
                    "file": "/etc/redhat-access-insights/machine-id"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/dockerhost/rootfs/etc/redhat-access-insights/machine-id",
                    "file": "/etc/redhat-access-insights/machine-id"
                }
            ]
        },
        "docker_info": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/docker info",
                    "archive_file_name": "/insights_commands/docker_info"
                }
            ]
        },
        "docker_list_containers": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/docker ps --all --no-trunc --size",
                    "archive_file_name": "/insights_commands/docker_ps_--all_--no-trunc_--size"
                }
            ]
        },
        "docker_list_images": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/docker images --all --no-trunc --digests",
                    "archive_file_name": "/insights_commands/docker_images_--all_--no-trunc_--digests"
                }
            ]
        },
        "docker_storage_setup": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/dockerhost/rootfs/etc/sysconfig/docker-storage-setup",
                    "file": "/etc/sysconfig/docker-storage-setup"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/dockerhost/rootfs/etc/sysconfig/docker-storage-setup",
                    "file": "/etc/sysconfig/docker-storage-setup"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/dockerhost/rootfs/etc/sysconfig/docker-storage-setup",
                    "file": "/etc/sysconfig/docker-storage-setup"
                }
            ]
        },
        "docker_sysconfig": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/dockerhost/rootfs/etc/sysconfig/docker",
                    "file": "/etc/sysconfig/docker"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/dockerhost/rootfs/etc/sysconfig/docker",
                    "file": "/etc/sysconfig/docker"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/dockerhost/rootfs/etc/sysconfig/docker",
                    "file": "/etc/sysconfig/docker"
                }
            ]
        },
        "dumpe2fs-h": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "dumpdev",
                    "command": "/sbin/dumpe2fs -h",
                    "archive_file_name": "/insights_commands/dumpe2fs_-h_"
                }
            ]
        },
        "engine.log": {
            "host": [
                {
                    "pattern": [
                        "[org.ovirt.engine.core.vdsbroker.VmsStatisticsFetcher]",
                        "Duplicate ID 'virtio-serial0' for device",
                        "XML error: Multiple 'virtio-serial' controllers with index '0'",
                        "has paused due to storage I/O problem"
                    ],
                    "archive_file_name": "/var/log/ovirt-engine/engine.log",
                    "file": "/var/log/ovirt-engine/engine.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "[org.ovirt.engine.core.vdsbroker.VmsStatisticsFetcher]",
                        "Duplicate ID 'virtio-serial0' for device",
                        "XML error: Multiple 'virtio-serial' controllers with index '0'",
                        "has paused due to storage I/O problem"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/ovirt-engine/engine.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/ovirt-engine/engine.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "[org.ovirt.engine.core.vdsbroker.VmsStatisticsFetcher]",
                        "Duplicate ID 'virtio-serial0' for device",
                        "XML error: Multiple 'virtio-serial' controllers with index '0'",
                        "has paused due to storage I/O problem"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/ovirt-engine/engine.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/ovirt-engine/engine.log"
                }
            ]
        },
        "ethtool": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "iface",
                    "command": "/sbin/ethtool",
                    "archive_file_name": "/insights_commands/ethtool_"
                }
            ]
        },
        "ethtool-S": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "iface",
                    "command": "/sbin/ethtool -S",
                    "archive_file_name": "/insights_commands/ethtool_-S_"
                }
            ]
        },
        "ethtool-g": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "iface",
                    "command": "/sbin/ethtool -g",
                    "archive_file_name": "/insights_commands/ethtool_-g_"
                }
            ]
        },
        "ethtool-i": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "iface",
                    "command": "/sbin/ethtool -i",
                    "archive_file_name": "/insights_commands/ethtool_-i_"
                }
            ]
        },
        "ethtool-k": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "iface",
                    "command": "/sbin/ethtool -k",
                    "archive_file_name": "/insights_commands/ethtool_-k_"
                }
            ]
        },
        "facter": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/facter",
                    "archive_file_name": "/insights_commands/facter"
                }
            ]
        },
        "fstab": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/fstab",
                    "file": "/etc/fstab"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/fstab",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/fstab"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/fstab",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/fstab"
                }
            ]
        },
        "galera.cnf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/my.cnf.d/galera.cnf",
                    "file": "/etc/my.cnf.d/galera.cnf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/my.cnf.d/galera.cnf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/my.cnf.d/galera.cnf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/my.cnf.d/galera.cnf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/my.cnf.d/galera.cnf"
                }
            ]
        },
        "getenforce": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/getenforce",
                    "archive_file_name": "/insights_commands/getenforce"
                }
            ]
        },
        "grub.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/boot/grub/grub.conf",
                    "file": "/boot/grub/grub.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/boot/grub/grub.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/boot/grub/grub.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/boot/grub/grub.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/boot/grub/grub.conf"
                }
            ]
        },
        "grub1_config_perms": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l /boot/grub/grub.conf",
                    "archive_file_name": "/insights_commands/ls_-l_.boot.grub.grub.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l {CONTAINER_MOUNT_POINT}/boot/grub/grub.conf",
                    "archive_file_name": "/insights_data/container/commands/ls_-l_.boot.grub.grub.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l {CONTAINER_MOUNT_POINT}/boot/grub/grub.conf",
                    "archive_file_name": "/insights_data/image/commands/ls_-l_.boot.grub.grub.conf"
                }
            ]
        },
        "grub2.cfg": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/boot/grub2/grub.cfg",
                    "file": "/boot/grub2/grub.cfg"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/boot/grub2/grub.cfg",
                    "file": "{CONTAINER_MOUNT_POINT}/boot/grub2/grub.cfg"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/boot/grub2/grub.cfg",
                    "file": "{CONTAINER_MOUNT_POINT}/boot/grub2/grub.cfg"
                }
            ]
        },
        "grub_config_perms": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l /boot/grub2/grub.cfg",
                    "archive_file_name": "/insights_commands/ls_-l_.boot.grub2.grub.cfg"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l {CONTAINER_MOUNT_POINT}/boot/grub2/grub.cfg",
                    "archive_file_name": "/insights_data/container/commands/ls_-l_.boot.grub2.grub.cfg"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l {CONTAINER_MOUNT_POINT}/boot/grub2/grub.cfg",
                    "archive_file_name": "/insights_data/image/commands/ls_-l_.boot.grub2.grub.cfg"
                }
            ]
        },
        "haproxy_cfg": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/haproxy/haproxy.cfg",
                    "file": "/etc/haproxy/haproxy.cfg"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/haproxy/haproxy.cfg",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/haproxy/haproxy.cfg"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/haproxy/haproxy.cfg",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/haproxy/haproxy.cfg"
                }
            ]
        },
        "heat.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/heat/heat.conf",
                    "file": "/etc/heat/heat.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/heat/heat.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/heat/heat.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/heat/heat.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/heat/heat.conf"
                }
            ]
        },
        "heat_crontab": {
            "host": [
                {
                    "pattern": [
                        "heat-manage"
                    ],
                    "command": "/usr/bin/crontab -l -u heat",
                    "archive_file_name": "/insights_commands/crontab_-l_-u_heat"
                }
            ]
        },
        "hostname": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/hostname",
                    "archive_file_name": "/insights_commands/hostname"
                }
            ]
        },
        "hosts": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/hosts",
                    "file": "/etc/hosts"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/hosts",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/hosts"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/hosts",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/hosts"
                }
            ]
        },
        "httpd.conf": {
            "host": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol",
                        "RequestHeader",
                        "</IfModule>",
                        "FcgidPassHeader",
                        "<IfModule prefork.c>",
                        "MaxClients",
                        "<IfModule worker.c>"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/httpd/conf/()*httpd\\.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol",
                        "RequestHeader",
                        "</IfModule>",
                        "FcgidPassHeader",
                        "<IfModule prefork.c>",
                        "MaxClients",
                        "<IfModule worker.c>"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/httpd/conf/()*httpd\\.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol",
                        "RequestHeader",
                        "</IfModule>",
                        "FcgidPassHeader",
                        "<IfModule prefork.c>",
                        "MaxClients",
                        "<IfModule worker.c>"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/httpd/conf/()*httpd\\.conf"
                }
            ]
        },
        "httpd.conf.d": {
            "host": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol",
                        "RequestHeader",
                        "</IfModule>",
                        "FcgidPassHeader",
                        "<IfModule prefork.c>",
                        "MaxClients",
                        "<IfModule worker.c>"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/httpd/conf.d/()*.+\\.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol",
                        "RequestHeader",
                        "</IfModule>",
                        "FcgidPassHeader",
                        "<IfModule prefork.c>",
                        "MaxClients",
                        "<IfModule worker.c>"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/httpd/conf.d/()*.+\\.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "SSLProtocol",
                        "SSLCipherSuite",
                        "NSSProtocol",
                        "RequestHeader",
                        "</IfModule>",
                        "FcgidPassHeader",
                        "<IfModule prefork.c>",
                        "MaxClients",
                        "<IfModule worker.c>"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/httpd/conf.d/()*.+\\.conf"
                }
            ]
        },
        "ifcfg": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/sysconfig/network-scripts/()*ifcfg-.*"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/network-scripts/()*ifcfg-.*"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/network-scripts/()*ifcfg-.*"
                }
            ]
        },
        "imagemagick_policy": {
            "host": [
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/ImageMagick/()*policy\\.xml"
                },
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/usr/lib64/ImageMagick-6.5.4/config/()*policy\\.xml"
                },
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/usr/lib/ImageMagick-6.5.4/config/()*policy\\.xml"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ImageMagick/()*policy\\.xml"
                },
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/lib64/ImageMagick-6.5.4/config/()*policy\\.xml"
                },
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/lib/ImageMagick-6.5.4/config/()*policy\\.xml"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ImageMagick/()*policy\\.xml"
                },
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/lib64/ImageMagick-6.5.4/config/()*policy\\.xml"
                },
                {
                    "pattern": [
                        "</policymap>",
                        "<policymap>",
                        "<policy"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/lib/ImageMagick-6.5.4/config/()*policy\\.xml"
                }
            ]
        },
        "installed-rpms": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/rpm -qa --qf='%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME:date}\t%{BUILDTIME}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\n'",
                    "archive_file_name": "/insights_commands/rpm_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_BUILDTIME_RSAHEADER_pgpsig_DSAHEADER_pgpsig"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/rpm --root={CONTAINER_MOUNT_POINT} -qa '--qf=%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME:date}\t%{BUILDTIME}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\n'",
                    "archive_file_name": "/insights_data/container/commands/rpm_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_BUILDTIME_RSAHEADER_pgpsig_DSAHEADER_pgpsig"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/rpm --root={CONTAINER_MOUNT_POINT} -qa '--qf=%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME:date}\t%{BUILDTIME}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\n'",
                    "archive_file_name": "/insights_data/image/commands/rpm_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_BUILDTIME_RSAHEADER_pgpsig_DSAHEADER_pgpsig"
                }
            ]
        },
        "interrupts": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/proc/interrupts",
                    "file": "/proc/interrupts"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/proc/interrupts",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/interrupts"
                }
            ]
        },
        "ip_addr": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/ip addr",
                    "archive_file_name": "/insights_commands/ip_addr"
                }
            ]
        },
        "ip_route_show_table_all": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/ip route show table all",
                    "archive_file_name": "/insights_commands/ip_route_show_table_all"
                }
            ]
        },
        "iptables": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/iptables-save",
                    "archive_file_name": "/insights_commands/iptables-save"
                }
            ]
        },
        "ipv4_neigh": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/ip -4 neighbor show nud all",
                    "archive_file_name": "/insights_commands/ip_-4_neighbor_show_nud_all"
                }
            ]
        },
        "ipv6_neigh": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/ip -6 neighbor show nud all",
                    "archive_file_name": "/insights_commands/ip_-6_neighbor_show_nud_all"
                }
            ]
        },
        "kdump.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/kdump.conf",
                    "file": "/etc/kdump.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/kdump.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/kdump.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/kdump.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/kdump.conf"
                }
            ]
        },
        "kexec_crash_loaded": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/sys/kernel/kexec_crash_loaded",
                    "file": "/sys/kernel/kexec_crash_loaded"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/sys/kernel/kexec_crash_loaded",
                    "file": "{CONTAINER_MOUNT_POINT}/sys/kernel/kexec_crash_loaded"
                }
            ]
        },
        "kexec_crash_size": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/sys/kernel/kexec_crash_size",
                    "file": "/sys/kernel/kexec_crash_size"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/sys/kernel/kexec_crash_size",
                    "file": "{CONTAINER_MOUNT_POINT}/sys/kernel/kexec_crash_size"
                }
            ]
        },
        "keystone_crontab": {
            "host": [
                {
                    "pattern": [
                        "heat-manage",
                        "keystone-manage"
                    ],
                    "command": "/usr/bin/crontab -l -u keystone",
                    "archive_file_name": "/insights_commands/crontab_-l_-u_keystone"
                }
            ]
        },
        "ksmstate": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/sys/kernel/mm/ksm/run",
                    "file": "/sys/kernel/mm/ksm/run"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/sys/kernel/mm/ksm/run",
                    "file": "{CONTAINER_MOUNT_POINT}/sys/kernel/mm/ksm/run"
                }
            ]
        },
        "limits.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/security/limits.conf",
                    "file": "/etc/security/limits.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/security/limits.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/security/limits.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/security/limits.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/security/limits.conf"
                }
            ]
        },
        "limits.d": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/security/limits.d/()*.*"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/security/limits.d/()*.*"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/security/limits.d/()*.*"
                }
            ]
        },
        "localtime": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/file -L /etc/localtime",
                    "archive_file_name": "/insights_commands/file_-L_.etc.localtime"
                }
            ]
        },
        "lpstat_p": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/lpstat -p",
                    "archive_file_name": "/insights_commands/lpstat_-p"
                }
            ]
        },
        "ls_boot": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR /boot",
                    "archive_file_name": "/insights_commands/ls_-lanR_.boot"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/boot",
                    "archive_file_name": "/insights_data/container/commands/ls_-lanR_.boot"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/boot",
                    "archive_file_name": "/insights_data/image/commands/ls_-lanR_.boot"
                }
            ]
        },
        "ls_dev": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR /dev",
                    "archive_file_name": "/insights_commands/ls_-lanR_.dev"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/dev",
                    "archive_file_name": "/insights_data/container/commands/ls_-lanR_.dev"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/dev",
                    "archive_file_name": "/insights_data/image/commands/ls_-lanR_.dev"
                }
            ]
        },
        "ls_disk": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR /dev/disk/by-*",
                    "archive_file_name": "/insights_commands/ls_-lanR_.dev.disk.by"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/dev/disk/by-*",
                    "archive_file_name": "/insights_data/container/commands/ls_-lanR_.dev.disk.by"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/dev/disk/by-*",
                    "archive_file_name": "/insights_data/image/commands/ls_-lanR_.dev.disk.by"
                }
            ]
        },
        "ls_etc": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR /etc",
                    "archive_file_name": "/insights_commands/ls_-lanR_.etc"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/etc",
                    "archive_file_name": "/insights_data/container/commands/ls_-lanR_.etc"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/etc",
                    "archive_file_name": "/insights_data/image/commands/ls_-lanR_.etc"
                }
            ]
        },
        "ls_sys_firmware": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR /sys/firmware",
                    "archive_file_name": "/insights_commands/ls_-lanR_.sys.firmware"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/sys/firmware",
                    "archive_file_name": "/insights_data/container/commands/ls_-lanR_.sys.firmware"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -lanR {CONTAINER_MOUNT_POINT}/sys/firmware",
                    "archive_file_name": "/insights_data/image/commands/ls_-lanR_.sys.firmware"
                }
            ]
        },
        "ls_var_log": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -la /var/log /var/log/audit",
                    "archive_file_name": "/insights_commands/ls_-la_.var.log_.var.log.audit"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -la {CONTAINER_MOUNT_POINT}/var/log {CONTAINER_MOUNT_POINT}/var/log/audit",
                    "archive_file_name": "/insights_data/container/commands/ls_-la_.var.log_.var.log.audit"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -la {CONTAINER_MOUNT_POINT}/var/log {CONTAINER_MOUNT_POINT}/var/log/audit",
                    "archive_file_name": "/insights_data/image/commands/ls_-la_.var.log_.var.log.audit"
                }
            ]
        },
        "lsblk": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/lsblk",
                    "archive_file_name": "/insights_commands/lsblk"
                }
            ]
        },
        "lsblk_pairs": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/lsblk -P -o NAME,KNAME,MAJ:MIN,FSTYPE,MOUNTPOINT,LABEL,UUID,RA,RO,RM,MODEL,SIZE,STATE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,RQ-SIZE,TYPE,DISC-ALN,DISC-GRAN,DISC-MAX,DISC-ZERO",
                    "archive_file_name": "/insights_commands/lsblk_-P_-o_NAME_KNAME_MAJ_MIN_FSTYPE_MOUNTPOINT_LABEL_UUID_RA_RO_RM_MODEL_SIZE_STATE_OWNER_GROUP_MODE_ALIGNMENT_MIN-IO_OPT-IO_PHY-SEC_LOG-SEC_ROTA_SCHED_RQ-SIZE_TYPE_DISC-ALN_DISC-GRAN_DISC-MAX_DISC-ZERO"
                }
            ]
        },
        "lsmod": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/lsmod",
                    "archive_file_name": "/insights_commands/lsmod"
                }
            ]
        },
        "lsof": {
            "host": [
                {
                    "pattern": [
                        "libssl.so",
                        "libcrypto",
                        "COMMAND",
                        "libssl"
                    ],
                    "command": "/usr/sbin/lsof",
                    "archive_file_name": "/insights_commands/lsof"
                }
            ]
        },
        "lspci": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/lspci",
                    "archive_file_name": "/insights_commands/lspci"
                }
            ]
        },
        "lvm.conf": {
            "host": [
                {
                    "pattern": [
                        "filter",
                        "locking_type",
                        "auto_activation_volume_list",
                        "volume_list"
                    ],
                    "archive_file_name": "/etc/lvm/lvm.conf",
                    "file": "/etc/lvm/lvm.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "filter",
                        "locking_type",
                        "auto_activation_volume_list",
                        "volume_list"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/lvm/lvm.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/lvm/lvm.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "filter",
                        "locking_type",
                        "auto_activation_volume_list",
                        "volume_list"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/lvm/lvm.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/lvm/lvm.conf"
                }
            ]
        },
        "lvs_noheadings": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/lvs --nameprefixes --noheadings --separator='|' -a -o lv_name,vg_name,lv_size,region_size,mirror_log,lv_attr,devices,region_size --config=\"global{locking_type=0}\"",
                    "archive_file_name": "/insights_commands/lvs_--nameprefixes_--noheadings_--separator_-a_-o_lv_name_vg_name_lv_size_region_size_mirror_log_lv_attr_devices_region_size_--config_global_locking_type_0"
                }
            ]
        },
        "mdstat": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/proc/mdstat",
                    "file": "/proc/mdstat"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/proc/mdstat",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/mdstat"
                }
            ]
        },
        "meminfo": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/proc/meminfo",
                    "file": "/proc/meminfo"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/proc/meminfo",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/meminfo"
                }
            ]
        },
        "messages": {
            "host": [
                {
                    "pattern": [
                        "Error running DeviceResume dm_task_run failed",
                        "kernel: megasas: Found FW in FAULT state, will reset adapter.",
                        "tg3_start_xmit",
                        "does not seem to be present, delaying initialization",
                        "Machine",
                        "swapper: page allocation failure",
                        "is beyond advertised capabilities",
                        "modprobe: FATAL: Error inserting nfsd",
                        "be2net",
                        "Temperature above threshold",
                        "Virtualization daemon",
                        "fiid_obj_get: 'present_countdown_value': data not available",
                        "kernel: bnx2fc: byte_count",
                        "timeout; kill it",
                        "nf_conntrack: table full, dropping packet",
                        "nf_conntrack: expectation table full",
                        "multipathd.service operation timed out. Terminating",
                        "Dazed and confused, but trying to continue",
                        "per_source_limit from",
                        "Uhhuh. NMI received for unknown reason",
                        "megaraid_sas: FW detected to be in faultstate, restarting it",
                        "start request repeated too quickly for docker.service",
                        "dev_watchdog",
                        "irq handler for vector (irq -1)",
                        "SELinux is preventing /usr/sbin/logrotate from getattr access on the file",
                        "firewalld - dynamic firewall daemon",
                        "kernel: CIFS VFS: Unexpected SMB signature",
                        "skb_copy",
                        "mode:0x20",
                        "blocked FC remote port time out",
                        "Out of memory: kill process",
                        "WATCHDOG",
                        "SCSI device reset on",
                        "heated above trip temperature",
                        "ext4_ext_search_left",
                        "skb_over_panic",
                        "Out of MCCQ wrbs",
                        "'Ifcfg' object has no attribute 'runningConfig",
                        "WRITE SAME failed. Manually zeroing",
                        "Abort command issued",
                        "DMA Status error.  Resetting chip",
                        "Device offlined - not ready after error recovery",
                        "khash_super_prune_nolock",
                        "page allocation failure",
                        "Sense Key : Illegal Request [current]",
                        "udevd"
                    ],
                    "archive_file_name": "/var/log/messages",
                    "file": "/var/log/messages"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "Error running DeviceResume dm_task_run failed",
                        "kernel: megasas: Found FW in FAULT state, will reset adapter.",
                        "tg3_start_xmit",
                        "does not seem to be present, delaying initialization",
                        "Machine",
                        "swapper: page allocation failure",
                        "is beyond advertised capabilities",
                        "modprobe: FATAL: Error inserting nfsd",
                        "be2net",
                        "Temperature above threshold",
                        "Virtualization daemon",
                        "fiid_obj_get: 'present_countdown_value': data not available",
                        "kernel: bnx2fc: byte_count",
                        "timeout; kill it",
                        "nf_conntrack: table full, dropping packet",
                        "nf_conntrack: expectation table full",
                        "multipathd.service operation timed out. Terminating",
                        "Dazed and confused, but trying to continue",
                        "per_source_limit from",
                        "Uhhuh. NMI received for unknown reason",
                        "megaraid_sas: FW detected to be in faultstate, restarting it",
                        "start request repeated too quickly for docker.service",
                        "dev_watchdog",
                        "irq handler for vector (irq -1)",
                        "SELinux is preventing /usr/sbin/logrotate from getattr access on the file",
                        "firewalld - dynamic firewall daemon",
                        "kernel: CIFS VFS: Unexpected SMB signature",
                        "skb_copy",
                        "mode:0x20",
                        "blocked FC remote port time out",
                        "Out of memory: kill process",
                        "WATCHDOG",
                        "SCSI device reset on",
                        "heated above trip temperature",
                        "ext4_ext_search_left",
                        "skb_over_panic",
                        "Out of MCCQ wrbs",
                        "'Ifcfg' object has no attribute 'runningConfig",
                        "WRITE SAME failed. Manually zeroing",
                        "Abort command issued",
                        "DMA Status error.  Resetting chip",
                        "Device offlined - not ready after error recovery",
                        "khash_super_prune_nolock",
                        "page allocation failure",
                        "Sense Key : Illegal Request [current]",
                        "udevd"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/messages",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/messages"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "Error running DeviceResume dm_task_run failed",
                        "kernel: megasas: Found FW in FAULT state, will reset adapter.",
                        "tg3_start_xmit",
                        "does not seem to be present, delaying initialization",
                        "Machine",
                        "swapper: page allocation failure",
                        "is beyond advertised capabilities",
                        "modprobe: FATAL: Error inserting nfsd",
                        "be2net",
                        "Temperature above threshold",
                        "Virtualization daemon",
                        "fiid_obj_get: 'present_countdown_value': data not available",
                        "kernel: bnx2fc: byte_count",
                        "timeout; kill it",
                        "nf_conntrack: table full, dropping packet",
                        "nf_conntrack: expectation table full",
                        "multipathd.service operation timed out. Terminating",
                        "Dazed and confused, but trying to continue",
                        "per_source_limit from",
                        "Uhhuh. NMI received for unknown reason",
                        "megaraid_sas: FW detected to be in faultstate, restarting it",
                        "start request repeated too quickly for docker.service",
                        "dev_watchdog",
                        "irq handler for vector (irq -1)",
                        "SELinux is preventing /usr/sbin/logrotate from getattr access on the file",
                        "firewalld - dynamic firewall daemon",
                        "kernel: CIFS VFS: Unexpected SMB signature",
                        "skb_copy",
                        "mode:0x20",
                        "blocked FC remote port time out",
                        "Out of memory: kill process",
                        "WATCHDOG",
                        "SCSI device reset on",
                        "heated above trip temperature",
                        "ext4_ext_search_left",
                        "skb_over_panic",
                        "Out of MCCQ wrbs",
                        "'Ifcfg' object has no attribute 'runningConfig",
                        "WRITE SAME failed. Manually zeroing",
                        "Abort command issued",
                        "DMA Status error.  Resetting chip",
                        "Device offlined - not ready after error recovery",
                        "khash_super_prune_nolock",
                        "page allocation failure",
                        "Sense Key : Illegal Request [current]",
                        "udevd"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/messages",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/messages"
                }
            ]
        },
        "modprobe.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/modprobe.conf",
                    "file": "/etc/modprobe.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/modprobe.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/modprobe.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/modprobe.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/modprobe.conf"
                }
            ]
        },
        "modprobe.d": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/modprobe.d/()*.*\\.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/modprobe.d/()*.*\\.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/modprobe.d/()*.*\\.conf"
                }
            ]
        },
        "mount": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/mount",
                    "archive_file_name": "/insights_commands/mount"
                }
            ]
        },
        "multicast_querier": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/find /sys/devices/virtual/net/ -name multicast_querier -print -exec cat {} \\;",
                    "archive_file_name": "/insights_commands/find_.sys.devices.virtual.net._-name_multicast_querier_-print_-exec_cat"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/usr/bin/find {CONTAINER_MOUNT_POINT}/sys/devices/virtual/net/ -name multicast_querier -print -exec cat {} ;",
                    "archive_file_name": "/insights_data/container/commands/find_.sys.devices.virtual.net._-name_multicast_querier_-print_-exec_cat"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/usr/bin/find {CONTAINER_MOUNT_POINT}/sys/devices/virtual/net/ -name multicast_querier -print -exec cat {} ;",
                    "archive_file_name": "/insights_data/image/commands/find_.sys.devices.virtual.net._-name_multicast_querier_-print_-exec_cat"
                }
            ]
        },
        "multipath.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/multipath.conf",
                    "file": "/etc/multipath.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/multipath.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/multipath.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/multipath.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/multipath.conf"
                }
            ]
        },
        "multipath_-v4_-ll": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/multipath -v4 -ll",
                    "archive_file_name": "/insights_commands/multipath_-v4_-ll"
                }
            ]
        },
        "named-checkconf_p": {
            "host": [
                {
                    "pattern": [
                        "dnssec-enable",
                        "DNSSEC-ENABLE"
                    ],
                    "command": "/usr/sbin/named-checkconf -p",
                    "archive_file_name": "/insights_commands/named-checkconf_-p"
                }
            ]
        },
        "netconsole": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/sysconfig/netconsole",
                    "file": "/etc/sysconfig/netconsole"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/sysconfig/netconsole",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/netconsole"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/sysconfig/netconsole",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/netconsole"
                }
            ]
        },
        "netstat": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/netstat -neopa",
                    "archive_file_name": "/insights_commands/netstat_-neopa"
                }
            ]
        },
        "netstat-i": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/netstat -i",
                    "archive_file_name": "/insights_commands/netstat_-i"
                }
            ]
        },
        "netstat-s": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/netstat -s",
                    "archive_file_name": "/insights_commands/netstat_-s"
                }
            ]
        },
        "netstat_-agn": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/netstat -agn",
                    "archive_file_name": "/insights_commands/netstat_-agn"
                }
            ]
        },
        "neutron_plugin.ini": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/neutron/plugin.ini",
                    "file": "/etc/neutron/plugin.ini"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/neutron/plugin.ini",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/neutron/plugin.ini"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/neutron/plugin.ini",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/neutron/plugin.ini"
                }
            ]
        },
        "neutron_server_log": {
            "host": [
                {
                    "pattern": [
                        "No tenant network is available for allocation"
                    ],
                    "archive_file_name": "/var/log/neutron/server.log",
                    "file": "/var/log/neutron/server.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "No tenant network is available for allocation"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/neutron/server.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/neutron/server.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "No tenant network is available for allocation"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/neutron/server.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/neutron/server.log"
                }
            ]
        },
        "nfnetlink_queue": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/proc/net/netfilter/nfnetlink_queue",
                    "file": "/proc/net/netfilter/nfnetlink_queue"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/proc/net/netfilter/nfnetlink_queue",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/net/netfilter/nfnetlink_queue"
                }
            ]
        },
        "nfs_exports": {
            "host": [
                {
                    "pattern": [
                        "no_root_squash"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/()*exports"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "no_root_squash"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/()*exports"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "no_root_squash"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/()*exports"
                }
            ]
        },
        "nfs_exports.d": {
            "host": [
                {
                    "pattern": [
                        "no_root_squash"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/exports.d/()*.*\\.exports"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "no_root_squash"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/exports.d/()*.*\\.exports"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "no_root_squash"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/exports.d/()*.*\\.exports"
                }
            ]
        },
        "nova-api_log": {
            "host": [
                {
                    "pattern": [
                        "Timed out waiting for a reply to message ID"
                    ],
                    "archive_file_name": "/var/log/nova/nova-api.log",
                    "file": "/var/log/nova/nova-api.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "Timed out waiting for a reply to message ID"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/nova/nova-api.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/nova/nova-api.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "Timed out waiting for a reply to message ID"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/nova/nova-api.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/nova/nova-api.log"
                }
            ]
        },
        "nova.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/nova/nova.conf",
                    "file": "/etc/nova/nova.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/nova/nova.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/nova/nova.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/nova/nova.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/nova/nova.conf"
                }
            ]
        },
        "nproc.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/security/limits.d/()*.*-nproc\\.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/security/limits.d/()*.*-nproc\\.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/security/limits.d/()*.*-nproc\\.conf"
                }
            ]
        },
        "nscd.conf": {
            "host": [
                {
                    "pattern": [
                        "enable-cache"
                    ],
                    "archive_file_name": "/etc/nscd.conf",
                    "file": "/etc/nscd.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "enable-cache"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/nscd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/nscd.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "enable-cache"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/nscd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/nscd.conf"
                }
            ]
        },
        "nsswitch.conf": {
            "host": [
                {
                    "pattern": [
                        "HOSTS:",
                        "hosts:"
                    ],
                    "archive_file_name": "/etc/nsswitch.conf",
                    "file": "/etc/nsswitch.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "HOSTS:",
                        "hosts:"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/nsswitch.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/nsswitch.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "HOSTS:",
                        "hosts:"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/nsswitch.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/nsswitch.conf"
                }
            ]
        },
        "ntp.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/ntp.conf",
                    "file": "/etc/ntp.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/ntp.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ntp.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/ntp.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ntp.conf"
                }
            ]
        },
        "ntpq_leap": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/ntpq -c 'rv 0 leap'",
                    "archive_file_name": "/insights_commands/ntpq_-c_rv_0_leap"
                }
            ]
        },
        "ntpq_pn": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/ntpq -pn",
                    "archive_file_name": "/insights_commands/ntpq_-pn"
                }
            ]
        },
        "ntptime": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/ntptime",
                    "archive_file_name": "/insights_commands/ntptime"
                }
            ]
        },
        "oc_get_project": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/oc get project -o yaml --all-namespaces",
                    "archive_file_name": "/insights_commands/oc_get_project_-o_yaml_--all-namespaces"
                }
            ]
        },
        "oc_get_role": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/oc get role -o yaml --all-namespaces",
                    "archive_file_name": "/insights_commands/oc_get_role_-o_yaml_--all-namespaces"
                }
            ]
        },
        "oc_get_rolebinding": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/oc get rolebinding -o yaml --all-namespaces",
                    "archive_file_name": "/insights_commands/oc_get_rolebinding_-o_yaml_--all-namespaces"
                }
            ]
        },
        "openshift_certificates": {
            "host": [
                {
                    "pattern": [],
                    "pre_command": "crt",
                    "command": "/usr/bin/openssl x509 -noout -enddate -in",
                    "archive_file_name": "/insights_commands/openssl_x509_-noout_-enddate_-in_"
                }
            ]
        },
        "ose_node_config": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/origin/node/node-config.yaml",
                    "file": "/etc/origin/node/node-config.yaml"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/origin/node/node-config.yaml",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/origin/node/node-config.yaml"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/origin/node/node-config.yaml",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/origin/node/node-config.yaml"
                }
            ]
        },
        "ovirt_engine_confd": {
            "host": [
                {
                    "pattern": [
                        "ENGINE_TMP="
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/ovirt-engine/engine.conf.d/()*.*"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "ENGINE_TMP="
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ovirt-engine/engine.conf.d/()*.*"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "ENGINE_TMP="
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ovirt-engine/engine.conf.d/()*.*"
                }
            ]
        },
        "ovs-vsctl_show": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/ovs-vsctl show",
                    "archive_file_name": "/insights_commands/ovs-vsctl_show"
                }
            ]
        },
        "pacemaker.log": {
            "host": [
                {
                    "pattern": [
                        "pcmk_dbus_find_error"
                    ],
                    "archive_file_name": "/var/log/pacemaker.log",
                    "file": "/var/log/pacemaker.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "pcmk_dbus_find_error"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/pacemaker.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/pacemaker.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "pcmk_dbus_find_error"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/pacemaker.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/pacemaker.log"
                }
            ]
        },
        "password-auth": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/pam.d/password-auth",
                    "file": "/etc/pam.d/password-auth"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/pam.d/password-auth",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/pam.d/password-auth"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/pam.d/password-auth",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/pam.d/password-auth"
                }
            ]
        },
        "pluginconf.d": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/yum/pluginconf.d/()*\\w+\\.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/yum/pluginconf.d/()*\\w+\\.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/yum/pluginconf.d/()*\\w+\\.conf"
                }
            ]
        },
        "postgresql.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/var/lib/pgsql/data/postgresql.conf",
                    "file": "/var/lib/pgsql/data/postgresql.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/var/lib/pgsql/data/postgresql.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/var/lib/pgsql/data/postgresql.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/var/lib/pgsql/data/postgresql.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/var/lib/pgsql/data/postgresql.conf"
                }
            ]
        },
        "postgresql.log": {
            "host": [
                {
                    "pattern": [
                        "checkpoints are occurring too frequently",
                        "ERROR:"
                    ],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/var/lib/pgsql/data/pg_log/()*postgresql-.+\\.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "checkpoints are occurring too frequently",
                        "ERROR:"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/var/lib/pgsql/data/pg_log/()*postgresql-.+\\.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "checkpoints are occurring too frequently",
                        "ERROR:"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/var/lib/pgsql/data/pg_log/()*postgresql-.+\\.log"
                }
            ]
        },
        "ps_aux": {
            "host": [
                {
                    "pattern": [
                        "phc2sys",
                        "/usr/bin/docker daemon",
                        "chronyd",
                        "ptp4l",
                        "STAP",
                        "COMMAND",
                        "ntpd",
                        "keystone-all",
                        "/usr/bin/docker-current daemon"
                    ],
                    "command": "/bin/ps aux",
                    "archive_file_name": "/insights_commands/ps_aux"
                }
            ]
        },
        "ps_auxcww": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ps auxcww",
                    "archive_file_name": "/insights_commands/ps_auxcww"
                }
            ]
        },
        "ps_auxwww": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/sos_commands/process/ps_auxwww",
                    "file": "/sos_commands/process/ps_auxwww"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/sos_commands/process/ps_auxwww",
                    "file": "{CONTAINER_MOUNT_POINT}/sos_commands/process/ps_auxwww"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/sos_commands/process/ps_auxwww",
                    "file": "{CONTAINER_MOUNT_POINT}/sos_commands/process/ps_auxwww"
                }
            ]
        },
        "pvs_noheadings": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/pvs --nameprefixes --noheadings --separator='|' -a -o pv_all,vg_name --config=\"global{locking_type=0}\"",
                    "archive_file_name": "/insights_commands/pvs_--nameprefixes_--noheadings_--separator_-a_-o_pv_all_vg_name_--config_global_locking_type_0"
                }
            ]
        },
        "rabbitmq_queues": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/rabbitmqctl list_queues name messages consumers auto_delete",
                    "archive_file_name": "/insights_commands/rabbitmqctl_list_queues_name_messages_consumers_auto_delete"
                }
            ]
        },
        "rabbitmq_report": {
            "host": [
                {
                    "pattern": [
                        "total_limit"
                    ],
                    "command": "/usr/sbin/rabbitmqctl report",
                    "archive_file_name": "/insights_commands/rabbitmqctl_report"
                }
            ]
        },
        "rabbitmq_startup_log": {
            "host": [
                {
                    "pattern": [
                        "Event crashed log handler:"
                    ],
                    "archive_file_name": "/var/log/rabbitmq/startup_log",
                    "file": "/var/log/rabbitmq/startup_log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "Event crashed log handler:"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/rabbitmq/startup_log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/rabbitmq/startup_log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "Event crashed log handler:"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/rabbitmq/startup_log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/rabbitmq/startup_log"
                }
            ]
        },
        "rabbitmq_users": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/rabbitmqctl list_users",
                    "archive_file_name": "/insights_commands/rabbitmqctl_list_users"
                }
            ]
        },
        "rc.local": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/rc.d/rc.local",
                    "file": "/etc/rc.d/rc.local"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/rc.d/rc.local",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/rc.d/rc.local"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/rc.d/rc.local",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/rc.d/rc.local"
                }
            ]
        },
        "redhat-release": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/redhat-release",
                    "file": "/etc/redhat-release"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/redhat-release",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/redhat-release"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/redhat-release",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/redhat-release"
                }
            ]
        },
        "resolv.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/resolv.conf",
                    "file": "/etc/resolv.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/resolv.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/resolv.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/resolv.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/resolv.conf"
                }
            ]
        },
        "rhn-entitlement-cert.xml": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/sysconfig/rhn/()*rhn-entitlement-cert\\.xml.*"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/rhn/()*rhn-entitlement-cert\\.xml.*"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/rhn/()*rhn-entitlement-cert\\.xml.*"
                }
            ]
        },
        "rhn.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/rhn/rhn.conf",
                    "file": "/etc/rhn/rhn.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/rhn/rhn.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/rhn/rhn.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/rhn/rhn.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/rhn/rhn.conf"
                }
            ]
        },
        "root_crontab": {
            "host": [
                {
                    "pattern": [
                        "heat-manage"
                    ],
                    "command": "/usr/bin/crontab -l -u root",
                    "archive_file_name": "/insights_commands/crontab_-l_-u_root"
                }
            ]
        },
        "rpm_-V_packages": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/rpm -V coreutils procps procps-ng shadow-utils passwd sudo",
                    "archive_file_name": "/insights_commands/rpm_-V_coreutils_procps_procps-ng_shadow-utils_passwd_sudo"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/rpm --root={CONTAINER_MOUNT_POINT} -V coreutils procps procps-ng shadow-utils passwd sudo",
                    "archive_file_name": "/insights_data/container/commands/rpm_-V_coreutils_procps_procps-ng_shadow-utils_passwd_sudo"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/rpm --root={CONTAINER_MOUNT_POINT} -V coreutils procps procps-ng shadow-utils passwd sudo",
                    "archive_file_name": "/insights_data/image/commands/rpm_-V_coreutils_procps_procps-ng_shadow-utils_passwd_sudo"
                }
            ]
        },
        "rsyslog.conf": {
            "host": [
                {
                    "pattern": [
                        "regex",
                        "imtcp"
                    ],
                    "archive_file_name": "/etc/rsyslog.conf",
                    "file": "/etc/rsyslog.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "regex",
                        "imtcp"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/rsyslog.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/rsyslog.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "regex",
                        "imtcp"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/rsyslog.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/rsyslog.conf"
                }
            ]
        },
        "samba": {
            "host": [
                {
                    "pattern": [
                        "REALM",
                        "security",
                        "realm",
                        "SECURITY"
                    ],
                    "archive_file_name": "/etc/samba/smb.conf",
                    "file": "/etc/samba/smb.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "REALM",
                        "security",
                        "realm",
                        "SECURITY"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/samba/smb.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/samba/smb.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "REALM",
                        "security",
                        "realm",
                        "SECURITY"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/samba/smb.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/samba/smb.conf"
                }
            ]
        },
        "satellite_version.rb": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/usr/share/foreman/lib/satellite/version.rb",
                    "file": "/usr/share/foreman/lib/satellite/version.rb"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/usr/share/foreman/lib/satellite/version.rb",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/share/foreman/lib/satellite/version.rb"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/usr/share/foreman/lib/satellite/version.rb",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/share/foreman/lib/satellite/version.rb"
                }
            ]
        },
        "scsi": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/proc/scsi/scsi",
                    "file": "/proc/scsi/scsi"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/proc/scsi/scsi",
                    "file": "{CONTAINER_MOUNT_POINT}/proc/scsi/scsi"
                }
            ]
        },
        "secure": {
            "host": [
                {
                    "pattern": [
                        "error: session_pty_req: session"
                    ],
                    "archive_file_name": "/var/log/secure",
                    "file": "/var/log/secure"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "error: session_pty_req: session"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/secure",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/secure"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "error: session_pty_req: session"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/secure",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/secure"
                }
            ]
        },
        "selinux-config": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/selinux/config",
                    "file": "/etc/selinux/config"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/selinux/config",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/selinux/config"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/selinux/config",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/selinux/config"
                }
            ]
        },
        "sestatus": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/sestatus -b",
                    "archive_file_name": "/insights_commands/sestatus_-b"
                }
            ]
        },
        "sshd_config": {
            "host": [
                {
                    "pattern": [
                        "LOGINGRACETIME",
                        "CIPHERS",
                        "protocol",
                        "PermitEmptyPasswords",
                        "CLIENTALIVEINTERVAL",
                        "PermitRootLogin",
                        "permitemptypasswords",
                        "usepam",
                        "allowusers",
                        "maxstartups",
                        "macs",
                        "CHALLENGERESPONSEAUTHENTICATION",
                        "clientalivecountmax",
                        "denyusers",
                        "MaxStartups",
                        "Macs",
                        "Ciphers",
                        "AllowUsers",
                        "permitrootlogin",
                        "PERMITROOTLOGIN",
                        "USEPAM",
                        "KBDINTERACTIVEAUTHENTICATION",
                        "logingracetime",
                        "PROTOCOL",
                        "UsePam",
                        "MaxAuthTries",
                        "ciphers",
                        "ClientAliveInterval",
                        "kbdinteractiveauthentication",
                        "MACs",
                        "ChallengeResponseAuthentication",
                        "ClientAliveCountMax",
                        "DenyUsers",
                        "LoginGraceTime",
                        "UsePAM",
                        "Protocol",
                        "maxauthtries",
                        "MAXAUTHTRIES",
                        "PERMITEMPTYPASSWORDS",
                        "ALLOWUSERS",
                        "clientaliveinterval",
                        "KbdInteractiveAuthentication",
                        "MAXSTARTUPS",
                        "MACS",
                        "challengeresponseauthentication",
                        "CLIENTALIVECOUNTMAX",
                        "DENYUSERS"
                    ],
                    "archive_file_name": "/etc/ssh/sshd_config",
                    "file": "/etc/ssh/sshd_config"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "LOGINGRACETIME",
                        "CIPHERS",
                        "protocol",
                        "PermitEmptyPasswords",
                        "CLIENTALIVEINTERVAL",
                        "PermitRootLogin",
                        "permitemptypasswords",
                        "usepam",
                        "allowusers",
                        "maxstartups",
                        "macs",
                        "CHALLENGERESPONSEAUTHENTICATION",
                        "clientalivecountmax",
                        "denyusers",
                        "MaxStartups",
                        "Macs",
                        "Ciphers",
                        "AllowUsers",
                        "permitrootlogin",
                        "PERMITROOTLOGIN",
                        "USEPAM",
                        "KBDINTERACTIVEAUTHENTICATION",
                        "logingracetime",
                        "PROTOCOL",
                        "UsePam",
                        "MaxAuthTries",
                        "ciphers",
                        "ClientAliveInterval",
                        "kbdinteractiveauthentication",
                        "MACs",
                        "ChallengeResponseAuthentication",
                        "ClientAliveCountMax",
                        "DenyUsers",
                        "LoginGraceTime",
                        "UsePAM",
                        "Protocol",
                        "maxauthtries",
                        "MAXAUTHTRIES",
                        "PERMITEMPTYPASSWORDS",
                        "ALLOWUSERS",
                        "clientaliveinterval",
                        "KbdInteractiveAuthentication",
                        "MAXSTARTUPS",
                        "MACS",
                        "challengeresponseauthentication",
                        "CLIENTALIVECOUNTMAX",
                        "DENYUSERS"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/ssh/sshd_config",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ssh/sshd_config"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "LOGINGRACETIME",
                        "CIPHERS",
                        "protocol",
                        "PermitEmptyPasswords",
                        "CLIENTALIVEINTERVAL",
                        "PermitRootLogin",
                        "permitemptypasswords",
                        "usepam",
                        "allowusers",
                        "maxstartups",
                        "macs",
                        "CHALLENGERESPONSEAUTHENTICATION",
                        "clientalivecountmax",
                        "denyusers",
                        "MaxStartups",
                        "Macs",
                        "Ciphers",
                        "AllowUsers",
                        "permitrootlogin",
                        "PERMITROOTLOGIN",
                        "USEPAM",
                        "KBDINTERACTIVEAUTHENTICATION",
                        "logingracetime",
                        "PROTOCOL",
                        "UsePam",
                        "MaxAuthTries",
                        "ciphers",
                        "ClientAliveInterval",
                        "kbdinteractiveauthentication",
                        "MACs",
                        "ChallengeResponseAuthentication",
                        "ClientAliveCountMax",
                        "DenyUsers",
                        "LoginGraceTime",
                        "UsePAM",
                        "Protocol",
                        "maxauthtries",
                        "MAXAUTHTRIES",
                        "PERMITEMPTYPASSWORDS",
                        "ALLOWUSERS",
                        "clientaliveinterval",
                        "KbdInteractiveAuthentication",
                        "MAXSTARTUPS",
                        "MACS",
                        "challengeresponseauthentication",
                        "CLIENTALIVECOUNTMAX",
                        "DENYUSERS"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/ssh/sshd_config",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/ssh/sshd_config"
                }
            ]
        },
        "sshd_config_perms": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l /etc/ssh/sshd_config",
                    "archive_file_name": "/insights_commands/ls_-l_.etc.ssh.sshd_config"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l {CONTAINER_MOUNT_POINT}/etc/ssh/sshd_config",
                    "archive_file_name": "/insights_data/container/commands/ls_-l_.etc.ssh.sshd_config"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/ls -l {CONTAINER_MOUNT_POINT}/etc/ssh/sshd_config",
                    "archive_file_name": "/insights_data/image/commands/ls_-l_.etc.ssh.sshd_config"
                }
            ]
        },
        "sysconfig_ntpd": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/sysconfig/ntpd",
                    "file": "/etc/sysconfig/ntpd"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/sysconfig/ntpd",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/ntpd"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/sysconfig/ntpd",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/ntpd"
                }
            ]
        },
        "sysctl": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/sysctl -a",
                    "archive_file_name": "/insights_commands/sysctl_-a"
                }
            ]
        },
        "sysctl.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/sysctl.conf",
                    "file": "/etc/sysctl.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/sysctl.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysctl.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/sysctl.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysctl.conf"
                }
            ]
        },
        "sysctl.conf_initramfs": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/lsinitrd /boot/initramfs-*kdump.img -f /etc/sysctl.conf /etc/sysctl.d/*.conf",
                    "archive_file_name": "/insights_commands/lsinitrd_.boot.initramfs-_kdump.img_-f_.etc.sysctl.conf_.etc.sysctl.d._.conf"
                }
            ]
        },
        "systemctl_cinder-volume": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/systemctl show openstack-cinder-volume",
                    "archive_file_name": "/insights_commands/systemctl_show_openstack-cinder-volume"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/systemctl --root={CONTAINER_MOUNT_POINT} show openstack-cinder-volume",
                    "archive_file_name": "/insights_data/container/commands/systemctl_show_openstack-cinder-volume"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/systemctl --root={CONTAINER_MOUNT_POINT} show openstack-cinder-volume",
                    "archive_file_name": "/insights_data/image/commands/systemctl_show_openstack-cinder-volume"
                }
            ]
        },
        "systemctl_list-unit-files": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/systemctl list-unit-files",
                    "archive_file_name": "/insights_commands/systemctl_list-unit-files"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/bin/systemctl --root={CONTAINER_MOUNT_POINT} list-unit-files",
                    "archive_file_name": "/insights_data/container/commands/systemctl_list-unit-files"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/bin/systemctl --root={CONTAINER_MOUNT_POINT} list-unit-files",
                    "archive_file_name": "/insights_data/image/commands/systemctl_list-unit-files"
                }
            ]
        },
        "systemd_docker": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/usr/lib/systemd/system/docker.service",
                    "file": "/usr/lib/systemd/system/docker.service"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/usr/lib/systemd/system/docker.service",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/lib/systemd/system/docker.service"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/usr/lib/systemd/system/docker.service",
                    "file": "{CONTAINER_MOUNT_POINT}/usr/lib/systemd/system/docker.service"
                }
            ]
        },
        "systemd_system.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/systemd/system.conf",
                    "file": "/etc/systemd/system.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/systemd/system.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/systemd/system.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/systemd/system.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/systemd/system.conf"
                }
            ]
        },
        "tuned-adm": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/tuned-adm list",
                    "archive_file_name": "/insights_commands/tuned-adm_list"
                }
            ]
        },
        "uname": {
            "host": [
                {
                    "pattern": [],
                    "command": "/bin/uname -a",
                    "archive_file_name": "/insights_commands/uname_-a"
                }
            ]
        },
        "up2date": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/sysconfig/rhn/up2date",
                    "file": "/etc/sysconfig/rhn/up2date"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/sysconfig/rhn/up2date",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/rhn/up2date"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/sysconfig/rhn/up2date",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/sysconfig/rhn/up2date"
                }
            ]
        },
        "uptime": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/uptime",
                    "archive_file_name": "/insights_commands/uptime"
                }
            ]
        },
        "vdsm.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/vdsm/vdsm.conf",
                    "file": "/etc/vdsm/vdsm.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/vdsm/vdsm.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/vdsm/vdsm.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/vdsm/vdsm.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/vdsm/vdsm.conf"
                }
            ]
        },
        "vdsm.log": {
            "host": [
                {
                    "pattern": [
                        "Migration is stuck: Hasn't progressed in",
                        "ImageIsNotLegalChain: Image is not a legal chain:",
                        "The name org.fedoraproject.FirewallD1 was not provided by any .service files",
                        "Timeout while waiting for path preparation",
                        "ImagePathError: Image path does not exist or cannot be accessed/created:",
                        "(waitForMigrationDestinationPrepare)"
                    ],
                    "archive_file_name": "/var/log/vdsm/vdsm.log",
                    "file": "/var/log/vdsm/vdsm.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "Migration is stuck: Hasn't progressed in",
                        "ImageIsNotLegalChain: Image is not a legal chain:",
                        "The name org.fedoraproject.FirewallD1 was not provided by any .service files",
                        "Timeout while waiting for path preparation",
                        "ImagePathError: Image path does not exist or cannot be accessed/created:",
                        "(waitForMigrationDestinationPrepare)"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/vdsm/vdsm.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/vdsm/vdsm.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "Migration is stuck: Hasn't progressed in",
                        "ImageIsNotLegalChain: Image is not a legal chain:",
                        "The name org.fedoraproject.FirewallD1 was not provided by any .service files",
                        "Timeout while waiting for path preparation",
                        "ImagePathError: Image path does not exist or cannot be accessed/created:",
                        "(waitForMigrationDestinationPrepare)"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/vdsm/vdsm.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/vdsm/vdsm.log"
                }
            ]
        },
        "vdsm_id": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/vdsm/vdsm.id",
                    "file": "/etc/vdsm/vdsm.id"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/vdsm/vdsm.id",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/vdsm/vdsm.id"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/vdsm/vdsm.id",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/vdsm/vdsm.id"
                }
            ]
        },
        "vgdisplay": {
            "host": [
                {
                    "pattern": [
                        "Clustered",
                        "Couldn't find device with uuid",
                        "Mirrored volumes",
                        "LV Name",
                        "VG Name"
                    ],
                    "command": "/sbin/vgdisplay",
                    "archive_file_name": "/insights_commands/vgdisplay"
                }
            ]
        },
        "vgs_noheadings": {
            "host": [
                {
                    "pattern": [],
                    "command": "/sbin/vgs --nameprefixes --noheadings --separator='|' -a -o vg_all --config=\"global{locking_type=0}\"",
                    "archive_file_name": "/insights_commands/vgs_--nameprefixes_--noheadings_--separator_-a_-o_vg_all_--config_global_locking_type_0"
                }
            ]
        },
        "virt-what": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/sbin/virt-what",
                    "archive_file_name": "/insights_commands/virt-what"
                }
            ]
        },
        "vsftpd": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/pam.d/vsftpd",
                    "file": "/etc/pam.d/vsftpd"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/pam.d/vsftpd",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/pam.d/vsftpd"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/pam.d/vsftpd",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/pam.d/vsftpd"
                }
            ]
        },
        "vsftpd.conf": {
            "host": [
                {
                    "pattern": [
                        "ssl_sslv3",
                        "local_enable",
                        "ssl_enable",
                        "LOCAL_ENABLE"
                    ],
                    "archive_file_name": "/etc/vsftpd/vsftpd.conf",
                    "file": "/etc/vsftpd/vsftpd.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "ssl_sslv3",
                        "local_enable",
                        "ssl_enable",
                        "LOCAL_ENABLE"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/etc/vsftpd/vsftpd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/vsftpd/vsftpd.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "ssl_sslv3",
                        "local_enable",
                        "ssl_enable",
                        "LOCAL_ENABLE"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/etc/vsftpd/vsftpd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/vsftpd/vsftpd.conf"
                }
            ]
        },
        "woopsie": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/find /var/crash /var/tmp -path '*.reports-*/whoopsie-report'",
                    "archive_file_name": "/insights_commands/find_.var.crash_.var.tmp_-path_.reports-_.whoopsie-report"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/usr/bin/find {CONTAINER_MOUNT_POINT}/var/crash {CONTAINER_MOUNT_POINT}/var/tmp -path *.reports-*/whoopsie-report",
                    "archive_file_name": "/insights_data/container/commands/find_.var.crash_.var.tmp_-path_.reports-_.whoopsie-report"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/usr/bin/find {CONTAINER_MOUNT_POINT}/var/crash {CONTAINER_MOUNT_POINT}/var/tmp -path *.reports-*/whoopsie-report",
                    "archive_file_name": "/insights_data/image/commands/find_.var.crash_.var.tmp_-path_.reports-_.whoopsie-report"
                }
            ]
        },
        "xinetd.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/xinetd.conf",
                    "file": "/etc/xinetd.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/xinetd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/xinetd.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/xinetd.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/xinetd.conf"
                }
            ]
        },
        "xinetd.d": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/xinetd.d/()*.*"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/xinetd.d/()*.*"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/xinetd.d/()*.*"
                }
            ]
        },
        "yum-repolist": {
            "host": [
                {
                    "pattern": [],
                    "command": "/usr/bin/yum -C repolist",
                    "archive_file_name": "/insights_commands/yum_-C_repolist"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "command": "/usr/bin/yum --installroot={CONTAINER_MOUNT_POINT} -C repolist",
                    "archive_file_name": "/insights_data/container/commands/yum_-C_repolist"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "command": "/usr/bin/yum --installroot={CONTAINER_MOUNT_POINT} -C repolist",
                    "archive_file_name": "/insights_data/image/commands/yum_-C_repolist"
                }
            ]
        },
        "yum.conf": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/etc/yum.conf",
                    "file": "/etc/yum.conf"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/etc/yum.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/yum.conf"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/etc/yum.conf",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/yum.conf"
                }
            ]
        },
        "yum.log": {
            "host": [
                {
                    "pattern": [
                        "nss-softokn-freebl-3.14.3",
                        "nss-softokn-3.14.3"
                    ],
                    "archive_file_name": "/var/log/yum.log",
                    "file": "/var/log/yum.log"
                }
            ],
            "docker_container": [
                {
                    "pattern": [
                        "nss-softokn-freebl-3.14.3",
                        "nss-softokn-3.14.3"
                    ],
                    "archive_file_name": "/insights_data/container/rootfs/var/log/yum.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/yum.log"
                }
            ],
            "docker_image": [
                {
                    "pattern": [
                        "nss-softokn-freebl-3.14.3",
                        "nss-softokn-3.14.3"
                    ],
                    "archive_file_name": "/insights_data/image/rootfs/var/log/yum.log",
                    "file": "{CONTAINER_MOUNT_POINT}/var/log/yum.log"
                }
            ]
        },
        "yum.repos.d": {
            "host": [
                {
                    "pattern": [],
                    "archive_file_name": "/{EXPANDED_FILE_NAME}",
                    "file": "/etc/yum.repos.d/()*.*.repo"
                }
            ],
            "docker_container": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/container/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/yum.repos.d/()*.*.repo"
                }
            ],
            "docker_image": [
                {
                    "pattern": [],
                    "archive_file_name": "/insights_data/image/rootfs/{EXPANDED_FILE_NAME}",
                    "file": "{CONTAINER_MOUNT_POINT}/etc/yum.repos.d/()*.*.repo"
                }
            ]
        }
    }
}


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.facts import *

if __name__ == '__main__':
    ansible_main()



