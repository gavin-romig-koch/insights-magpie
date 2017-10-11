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
import glob
from tempfile import NamedTemporaryFile


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

        if 'specs' not in conf:
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

def magpie_facts(module, specs):
    dc = DataCollector(archive_=DictInsightsArchive())
    dc.run_collection(specs, None, None)
    return dc.done(specs, None)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            specs={'required': True, 'type': 'dict' },
        ),
        supports_check_mode = True,
    )

    specs = module.params['specs']
    old_style = 'specs' not in specs

    if False:
        result = get_all_facts(module)
        #i don't know why i do the following
        #del result['ansible_facts']['module_setup']
    else:
        result = dict(ansible_facts={})

    for (k, v) in magpie_facts(module, specs).items():
        # newer versions of insights-client replace dashes with underscores
        result['ansible_facts']["magpie_%s" % (k if old_style else k.replace('-', '_'))] = v

    module.exit_json(**result)


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.facts import *

if __name__ == '__main__':
    main()
