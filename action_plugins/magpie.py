# (c) 2015, Ansible Inc,
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.action import ActionBase

"""
Handle adding files and preparing the archive for upload
"""
import tempfile
import time
import os
import shutil
import subprocess
import shlex
import logging
import atexit
import ConfigParser
import requests
import sys
import json

# from constants import InsightsConstants as constants
#class InsightsConstants(object):
class constants(object):
    app_name = 'insights-client'
    version = '0.0.1'
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
    default_ca_file = "false" #os.path.join(default_conf_dir, 'cert-api.access.redhat.com.pem')
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

APP_NAME = constants.app_name
#logger = logging.getLogger(APP_NAME)


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


class AnsibleLogger:
    def error(self, format, *args):
        display.error(format % args)

    def warning(self, format, *args):
        display.warning(format % args)

    def debug(self, format, *args):
        display.vvvv(format % args)

    def info(self, format, *args):
        display.vvv(format % args)

logger = AnsibleLogger()

class InsightsClient:
    class options:
        retries = 1
        container_mode = False

def parse_config_file(conf_file):
    """
    Parse the configuration from the file
    """
    parsedconfig = ConfigParser.RawConfigParser(
        {'loglevel': constants.log_level,
         'trace': 'False',
         'app_name': constants.app_name,
         'auto_config': 'True',
         'authmethod': constants.auth_method,
         'base_url': constants.base_url,
         'upload_url': None,
         'api_url': None,
         'branch_info_url': None,
         'auto_update': 'True',
         'collection_rules_url': None,
         'obfuscate': 'False',
         'obfuscate_hostname': 'False',
         'cert_verify': constants.default_ca_file,
         'gpg': 'True',
         'username': '',
         'password': '',
         'systemid': None,
         'proxy': None,
         'insecure_connection': 'False',
         'no_schedule': 'False',
         'docker_image_name': '',
         'display_name': None})
    try:
        parsedconfig.read(conf_file)
    except ConfigParser.Error:
        logger.error("ERROR: Could not read configuration file, using defaults")
    try:
        # Try to add the insights-client section
        parsedconfig.add_section(APP_NAME)
        # Try to add the redhat_access_insights section for back compat
        parsedconfig.add_section('redhat_access_insights')
    except ConfigParser.Error:
        pass
    return parsedconfig

def determine_hostname(display_name=None):
    return display_name if display_name else "cato"

SAVED_MACHINE_ID = None

def generate_machine_id(new=False, docker_group=False):
    """
    We can't (yet) do registration, so
    we can only do systems that already have a machine-id
    /etc/insights-client/machine-id
    """
    return SAVED_MACHINE_ID


def write_data_to_file(data, filepath):
    '''
    Write data to file
    '''
    if data == None:
        return

    try:
        os.makedirs(os.path.dirname(filepath), 0o700)
    except OSError:
        pass

    with open(filepath, 'w') as _file:
        _file.write(data)

def magic_plan_b(filename):
    '''
    Use this in instances where
    python-magic is MIA and can't be installed
    for whatever reason
    '''
    cmd = shlex.split('file --mime-type --mime-encoding ' + filename)
    stdout, stderr = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()
    mime_str = stdout.split(filename + ': ')[1].strip()
    return mime_str


class DefaultArgument:
    pass

class InsightsConnection(object):

    """
    Helper class to manage details about the connection
    """

    def __init__(self, username=DefaultArgument, password=DefaultArgument):
        self.user_agent = constants.user_agent
        self.username = username if username != DefaultArgument else InsightsClient.config.get(APP_NAME, "username")
        self.password = password if password != DefaultArgument else InsightsClient.config.get(APP_NAME, "password")

        self.cert_verify = InsightsClient.config.get(APP_NAME, "cert_verify")
        if self.cert_verify.lower() == 'false':
            self.cert_verify = False
        elif self.cert_verify.lower() == 'true':
            self.cert_verify = True

        protocol = "https://"
        insecure_connection = InsightsClient.config.getboolean(APP_NAME,
                                                               "insecure_connection")
        if insecure_connection:
            # This really should not be used.
            protocol = "http://"
            self.cert_verify = False

        self.auto_config = InsightsClient.config.getboolean(APP_NAME,
                                                            'auto_config')
        self.base_url = protocol + InsightsClient.config.get(APP_NAME, "base_url")
        self.upload_url = InsightsClient.config.get(APP_NAME, "upload_url")
        if self.upload_url is None:
            self.upload_url = self.base_url + "/uploads"
        self.api_url = InsightsClient.config.get(APP_NAME, "api_url")
        if self.api_url is None:
            self.api_url = self.base_url
        self.branch_info_url = InsightsClient.config.get(APP_NAME, "branch_info_url")
        if self.branch_info_url is None:
            self.branch_info_url = self.base_url + "/v1/branch_info"
        self.authmethod = InsightsClient.config.get(APP_NAME, 'authmethod')
        self.systemid = InsightsClient.config.get(APP_NAME, 'systemid')
        self.get_proxies()
        self._validate_hostnames()
        self.session = self._init_session()
        # need this global -- [barfing intensifies]
        # tuple of self-signed cert flag & cert chain list
        self.cert_chain = (False, [])

    def _init_session(self):
        """
        Set up the session, auth is handled here
        """
        session = requests.Session()
        session.headers = {'User-Agent': self.user_agent,
                           'Accept': 'application/json'}
        if self.systemid is not None:
            session.headers.update({'systemid': self.systemid})
        if self.authmethod == "BASIC":
            session.auth = (self.username, self.password)
        elif self.authmethod == "CERT":
            cert = rhsmCertificate.certpath()
            key = rhsmCertificate.keypath()
            if rhsmCertificate.exists():
                session.cert = (cert, key)
            else:
                logger.error('ERROR: Certificates not found.')
        session.verify = self.cert_verify
        session.proxies = self.proxies
        session.trust_env = False
        if self.proxy_auth:
            # HACKY
            try:
                # Need to make a request that will fail to get proxies set up
                session.request(
                    "GET", "https://cert-api.access.redhat.com/r/insights")
            except requests.ConnectionError:
                pass
            # Major hack, requests/urllib3 does not make access to
            # proxy_headers easy
            proxy_mgr = session.adapters['https://'].proxy_manager[self.proxies['https']]
            auth_map = {'Proxy-Authorization': self.proxy_auth}
            proxy_mgr.proxy_headers = auth_map
            proxy_mgr.connection_pool_kw['_proxy_headers'] = auth_map
            conns = proxy_mgr.pools._container
            for conn in conns:
                connection = conns[conn]
                connection.proxy_headers = auth_map
        return session

    def get_proxies(self):
        """
        Determine proxy configuration
        """
        # Get proxy from ENV or Config
        from urlparse import urlparse
        proxies = None
        proxy_auth = None
        no_proxy = os.environ.get('NO_PROXY')
        logger.debug("NO PROXY: %s", no_proxy)

        # CONF PROXY TAKES PRECEDENCE OVER ENV PROXY
        conf_proxy = InsightsClient.config.get(APP_NAME, 'proxy')
        if ((conf_proxy is not None and
             conf_proxy.lower() != 'None'.lower() and
             conf_proxy != "")):
            if '@' in conf_proxy:
                scheme = conf_proxy.split(':')[0] + '://'
                logger.debug("Proxy Scheme: %s", scheme)
                location = conf_proxy.split('@')[1]
                logger.debug("Proxy Location: %s", location)
                username = conf_proxy.split(
                    '@')[0].split(':')[1].replace('/', '')
                logger.debug("Proxy User: %s", username)
                password = conf_proxy.split('@')[0].split(':')[2]
                proxy_auth = requests.auth._basic_auth_str(username, password)
                conf_proxy = scheme + location
            logger.debug("CONF Proxy: %s", conf_proxy)
            proxies = {"https": conf_proxy}

        # HANDLE NO PROXY CONF PROXY EXCEPTION VERBIAGE
        if no_proxy and conf_proxy:
            logger.debug("You have environment variable NO_PROXY set "
                         "as well as 'proxy' set in your configuration file. "
                         "NO_PROXY environment variable will be ignored.")

        # IF NO CONF PROXY, GET ENV PROXY AND NO PROXY
        if proxies is None:
            env_proxy = os.environ.get('HTTPS_PROXY')
            if env_proxy:
                if '@' in env_proxy:
                    scheme = env_proxy.split(':')[0] + '://'
                    logger.debug("Proxy Scheme: %s", scheme)
                    location = env_proxy.split('@')[1]
                    logger.debug("Proxy Location: %s", location)
                    username = env_proxy.split('@')[0].split(':')[1].replace('/', '')
                    logger.debug("Proxy User: %s", username)
                    password = env_proxy.split('@')[0].split(':')[2]
                    proxy_auth = requests.auth._basic_auth_str(username, password)
                    env_proxy = scheme + location
                logger.debug("ENV Proxy: %s", env_proxy)
                proxies = {"https": env_proxy}
            if no_proxy:
                insights_service_host = urlparse(self.base_url).hostname
                logger.debug('Found NO_PROXY set. Checking NO_PROXY %s against base URL %s.', no_proxy, insights_service_host)
                for no_proxy_host in no_proxy.split(','):
                    logger.debug('Checking %s against %s', no_proxy_host, insights_service_host)
                    if no_proxy_host == '*':
                        proxies = None
                        proxy_auth = None
                        logger.debug('Found NO_PROXY asterisk(*) wildcard, disabling all proxies.')
                        break
                    elif no_proxy_host.startswith('.') or no_proxy_host.startswith('*'):
                        if insights_service_host.endswith(no_proxy_host.replace('*', '')):
                            proxies = None
                            proxy_auth = None
                            logger.debug('Found NO_PROXY range %s matching %s', no_proxy_host, insights_service_host)
                            break
                    elif no_proxy_host == insights_service_host:
                        proxies = None
                        proxy_auth = None
                        logger.debug('Found NO_PROXY %s exactly matching %s', no_proxy_host, insights_service_host)
                        break

        self.proxies = proxies
        self.proxy_auth = proxy_auth

    def _validate_hostnames(self):
        """
        Validate that the hostnames we got from config are sane
        """
        from urlparse import urlparse
        import socket
        endpoint_url = urlparse(self.upload_url)
        try:
            # Ensure we have something in the scheme and netloc
            if endpoint_url.scheme == "" or endpoint_url.netloc == "":
                logger.error("Invalid upload_url: " + self.upload_url + "\n"
                             "Be sure to include a protocol "
                             "(e.g. https://) and a "
                             "fully qualified domain name in " +
                             constants.default_conf_file)
                sys.exit()
            endpoint_addr = socket.gethostbyname(
                endpoint_url.netloc.split(':')[0])
            logger.debug(
                "hostname: %s ip: %s", endpoint_url.netloc, endpoint_addr)
        except socket.gaierror as e:
            logger.debug(e)
            logger.error(
                "Could not resolve hostname: %s", endpoint_url.geturl())
            sys.exit(1)
        if self.proxies is not None:
            proxy_url = urlparse(self.proxies['https'])
            try:
                # Ensure we have something in the scheme and netloc
                if proxy_url.scheme == "" or proxy_url.netloc == "":
                    logger.error("Proxies: %s", self.proxies)
                    logger.error("Invalid proxy!"
                                 "Please verify the proxy setting"
                                 " in " + constants.default_conf_file)
                    sys.exit()
                proxy_addr = socket.gethostbyname(
                    proxy_url.netloc.split(':')[0])
                logger.debug(
                    "Proxy hostname: %s ip: %s", proxy_url.netloc, proxy_addr)
            except socket.gaierror as e:
                logger.debug(e)
                logger.error("Could not resolve proxy %s", proxy_url.geturl())
                sys.exit(1)

    def _test_urls(self, url, method):
        """
        Actually test the url
        """
        from urlparse import urlparse
        # tell the api we're just testing the URL
        test_flag = {'test': 'test'}
        url = urlparse(url)
        test_url = url.scheme + "://" + url.netloc
        last_ex = None
        for ext in (url.path + '/', '', '/r', '/r/insights'):
            try:
                logger.info("Testing: %s", test_url + ext)
                if method is "POST":
                    test_req = self.session.post(
                        test_url + ext, timeout=10, data=test_flag)
                elif method is "GET":
                    test_req = self.session.get(test_url + ext, timeout=10)
                logger.info("HTTP Status Code: %d", test_req.status_code)
                logger.info("HTTP Status Text: %s", test_req.reason)
                logger.debug("HTTP Response Text: %s", test_req.text)
                # Strata returns 405 on a GET sometimes, this isn't a big deal
                if test_req.status_code == 200 or test_req.status_code == 201:
                    logger.info(
                        "Successfully connected to: %s", test_url + ext)
                    return True
                else:
                    logger.info("Connection failed")
                    return False
            except requests.ConnectionError, exc:
                last_ex = exc
                logger.error(
                    "Could not successfully connect to: %s", test_url + ext)
                logger.error(exc)
        if last_ex:
            raise last_ex

    def _verify_check(self, conn, cert, err, depth, ret):
        del conn
        # add cert to chain
        self.cert_chain[1].append(cert)
        logger.info('depth=' + str(depth))
        logger.info('verify error:num=' + str(err))
        logger.info('verify return:' + str(ret))
        if err == 19:
            # self-signed cert
            self.cert_chain[0] = True
        return True

    def _generate_cert_str(self, cert_data, prefix):
        return prefix + '/'.join(['='.join(a) for a in
                                  cert_data.get_components()])

    def _test_openssl(self):
        '''
        Run a test with openssl to detect any MITM proxies
        '''
        from urlparse import urlparse
        from OpenSSL import SSL, crypto
        import socket
        success = True
        hostname = urlparse(self.base_url).netloc.split(':')
        sock = socket.socket()
        sock.setblocking(1)
        if self.proxies:
            connect_str = 'CONNECT {0} HTTP/1.0\r\n'.format(hostname[0])
            if self.proxy_auth:
                connect_str += 'Proxy-Authorization: {0}\r\n'.format(self.proxy_auth)
            connect_str += '\r\n'
            proxy = urlparse(self.proxies['https']).netloc.split(':')
            try:
                sock.connect((proxy[0], int(proxy[1])))
            except Exception as e:
                logger.debug(e)
                logger.error('Failed to connect to proxy %s. Connection refused.', self.proxies['https'])
                sys.exit(1)
            sock.send(connect_str)
            res = sock.recv(4096)
            if '200 Connection established' not in res:
                logger.error('Failed to connect to %s. Invalid hostname.', self.base_url)
                sys.exit(1)
        else:
            try:
                sock.connect((hostname[0], 443))
            except socket.gaierror:
                logger.error('Error: Failed to connect to %s. Invalid hostname.', self.base_url)
                sys.exit(1)
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        if type(self.cert_verify) is not bool:
            if os.path.isfile(self.cert_verify):
                ctx.load_verify_locations(self.cert_verify, None)
            else:
                logger.error('Error: Invalid cert path: %s', self.cert_verify)
                sys.exit(1)
        ctx.set_verify(SSL.VERIFY_PEER, self._verify_check)
        ssl_conn = SSL.Connection(ctx, sock)
        ssl_conn.set_connect_state()
        try:
            # output from verify generated here
            ssl_conn.do_handshake()
            # print cert chain
            certs = self.cert_chain[1]
            # put them in the right order
            certs.reverse()
            logger.info('---\nCertificate chain')
            for depth, c in enumerate(certs):
                logger.info(self._generate_cert_str(c.get_subject(),
                                                    str(depth) + ' s :/'))
                logger.info(self._generate_cert_str(c.get_issuer(),
                                                    '  i :/'))
            # print server cert
            server_cert = ssl_conn.get_peer_certificate()
            logger.info('---\nServer certificate')
            logger.info(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
            logger.info(self._generate_cert_str(server_cert.get_subject(), 'subject=/'))
            logger.info(self._generate_cert_str(server_cert.get_issuer(), 'issuer=/'))
            logger.info('---')
        except SSL.Error as e:
            logger.debug('SSL error: %s', e)
            success = False
            logger.error('Certificate chain test failed!')
        ssl_conn.shutdown()
        ssl_conn.close()
        if self.cert_chain[0]:
            logger.error('Certificate chain test failed!  Self '
                         'signed certificate detected in chain')
        return success and not self.cert_chain[0]

    def test_connection(self, rc=0):
        """
        Test connection to Red Hat
        """
        logger.info("Connection test config:")
        logger.info("Proxy config: %s", self.proxies)
        logger.info("Certificate Verification: %s", self.cert_verify)
        try:
            logger.info("=== Begin Certificate Chain Test ===")
            cert_success = self._test_openssl()
            logger.info("=== End Certificate Chain Test: %s ===\n",
                        "SUCCESS" if cert_success else "FAILURE")
            logger.info("=== Begin Upload URL Connection Test ===")
            upload_success = self._test_urls(self.upload_url, "POST")
            logger.info("=== End Upload URL Connection Test: %s ===\n",
                        "SUCCESS" if upload_success else "FAILURE")
            logger.info("=== Begin API URL Connection Test ===")
            api_success = self._test_urls(self.api_url, "GET")
            logger.info("=== End API URL Connection Test: %s ===\n",
                        "SUCCESS" if api_success else "FAILURE")
            if cert_success and upload_success and api_success:
                logger.info("\nConnectivity tests completed successfully")
            else:
                logger.info("\nConnectivity tests completed with some errors")
                rc = 1
        except requests.ConnectionError, exc:
            logger.error(exc)
            logger.error('Connectivity test failed! '
                         'Please check your network configuration')
            logger.error('Additional information may be in'
                         ' /var/log/' + APP_NAME + "/" + APP_NAME + ".log")
            sys.exit(1)
        sys.exit(rc)

    def handle_fail_rcs(self, req):
        """
        Bail out if we get a 401 and leave a message
        """

        # always display HTTP response information
        try:
            logger.info("HTTP Status Code: %s", req.status_code)
            logger.info("HTTP Response Text: %s", req.text)
            logger.debug("HTTP Response Reason: %s", req.reason)
            logger.debug("HTTP Response Content: %s", req.content)
        except:
            logger.error("Malformed HTTP Request.")

        # attempt to read the HTTP response JSON message
        try:
            logger.info("HTTP Response Message: %s", req.json()["message"])
        except:
            logger.debug("No HTTP Response message present.")

        # handle specific status codes
        if req.status_code >= 400:
            logger.error("ERROR: Upload failed!")
            logger.info("Debug Information:\nHTTP Status Code: %s",
                        req.status_code)
            logger.info("HTTP Status Text: %s", req.reason)
            if req.status_code == 401:
                logger.error("Authorization Required.")
                logger.error("Please ensure correct credentials "
                             "in " + constants.default_conf_file)
                logger.debug("HTTP Response Text: %s", req.text)
            if req.status_code == 402:
                # failed registration because of entitlement limit hit
                logger.debug('Registration failed by 402 error.')
                try:
                    logger.error(req.json()["message"])
                except LookupError:
                    logger.error("Got 402 but no message")
                    logger.debug("HTTP Response Text: %s", req.text)
                except:
                    logger.error("Got 402 but no message")
                    logger.debug("HTTP Response Text: %s", req.text)
            if req.status_code == 403 and self.auto_config:
                # Insights disabled in satellite
                from urlparse import urlparse
                rhsm_hostname = urlparse(self.base_url).hostname
                if (rhsm_hostname != 'subscription.rhn.redhat.com' and
                   rhsm_hostname != 'subscription.rhsm.redhat.com'):
                    logger.error('Please enable Insights on Satellite server '
                                 '%s to continue.', rhsm_hostname)
            if req.status_code == 412:
                try:
                    unreg_date = req.json()["unregistered_at"]
                    logger.error(req.json()["message"])
                    write_unregistered_file(unreg_date)
                except LookupError:
                    unreg_date = "412, but no unreg_date or message"
                    logger.debug("HTTP Response Text: %s", req.text)
                except:
                    unreg_date = "412, but no unreg_date or message"
                    logger.debug("HTTP Response Text: %s", req.text)
            sys.exit(1)

    if False:
        # don't do this because we aren't on host machine
        def get_satellite5_info(self, branch_info):
            """
            Get remote_leaf for Satellite 5 Managed box
            """
            logger.debug(
                "Remote branch not -1 but remote leaf is -1, must be Satellite 5")
            if os.path.isfile('/etc/sysconfig/rhn/systemid'):
                logger.debug("Found systemid file")
                sat5_conf = ET.parse('/etc/sysconfig/rhn/systemid').getroot()
                leaf_id = None
                for member in sat5_conf.getiterator('member'):
                    if member.find('name').text == 'system_id':
                        logger.debug("Found member 'system_id'")
                        leaf_id = member.find('value').find(
                            'string').text.split('ID-')[1]
                        logger.debug("Found leaf id: %s", leaf_id)
                        branch_info['remote_leaf'] = leaf_id
                if leaf_id is None:
                    sys.exit("Could not determine leaf_id!  Exiting!")

    def branch_info(self):
        """
        Retrieve branch_info from Satellite Server
        """
        logger.debug("Obtaining branch information from %s",
                     self.branch_info_url)
        branch_info = self.session.get(self.branch_info_url)
        logger.debug("GET branch_info status: %s", branch_info.status_code)
        try:
            logger.debug("Branch information: %s",
                         json.dumps(branch_info.json()))
        except ValueError:
            raise LookupError
        branch_info = branch_info.json()

        if 'remote_branch' not in branch_info or 'remote_leaf' not in branch_info:
            raise LookupError

        # Determine if we are connected to Satellite 5
        if ((branch_info['remote_branch'] is not -1 and
             branch_info['remote_leaf'] is -1)):
            # don't do this because we aren't on host machine
            self.get_satellite5_info(branch_info)

        return branch_info

    def create_system(self, new_machine_id=False):
        """
        Create the machine via the API
        """
        client_hostname = determine_hostname()
        machine_id = generate_machine_id(new_machine_id)

        try:
            branch_info = self.branch_info()
            remote_branch = branch_info['remote_branch']
            remote_leaf = branch_info['remote_leaf']

        except LookupError:
            logger.error(
                "ERROR: Could not determine branch information, exiting!")
            logger.error(
                "Could not register system, running configuration test")
            self.test_connection(1)

        except requests.ConnectionError as e:
            logger.debug(e)
            logger.error(
                "ERROR: Could not determine branch information, exiting!")
            logger.error(
                "Could not register system, running configuration test")
            self.test_connection(1)

        data = {'machine_id': machine_id,
                'remote_branch': remote_branch,
                'remote_leaf': remote_leaf,
                'hostname': client_hostname}
        if InsightsClient.config.get(APP_NAME, 'display_name') is not None:
            data['display_name'] = InsightsClient.config.get(APP_NAME, 'display_name')
        if InsightsClient.options.display_name is not None:
            data['display_name'] = InsightsClient.options.display_name
        data = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        post_system_url = self.api_url + '/v1/systems'
        logger.debug("POST System: %s", post_system_url)
        logger.debug(data)
        system = None
        try:
            system = self.session.post(post_system_url,
                                       headers=headers,
                                       data=data)
            logger.debug("POST System status: %d", system.status_code)
        except requests.ConnectionError as e:
            logger.debug(e)
            logger.error(
                "Could not register system, running configuration test")
            self.test_connection(1)
        return system

    def do_group(self):
        """
        Do grouping on register
        """
        group_id = InsightsClient.options.group
        api_group_id = None
        headers = {'Content-Type': 'application/json'}
        group_path = self.api_url + '/v1/groups'
        group_get_path = group_path + ('?display_name=%s' % group_id)

        logger.debug("GET group: %s", group_get_path)
        get_group = self.session.get(group_get_path)
        logger.debug("GET group status: %s", get_group.status_code)
        if get_group.status_code == 200:
            api_group_id = get_group.json()['id']

        if get_group.status_code == 404:
            # Group does not exist, POST to create
            logger.debug("POST group")
            data = json.dumps({'display_name': group_id})
            post_group = self.session.post(group_path,
                                           headers=headers,
                                           data=data)
            logger.debug("POST group status: %s", post_group.status_code)
            logger.debug("POST Group: %s", post_group.json())
            self.handle_fail_rcs(post_group)
            api_group_id = post_group.json()['id']

        logger.debug("PUT group")
        data = json.dumps({'machine_id': generate_machine_id()})
        put_group = self.session.put(group_path +
                                     ('/%s/systems' % api_group_id),
                                     headers=headers,
                                     data=data)
        logger.debug("PUT group status: %d", put_group.status_code)
        logger.debug("PUT Group: %s", put_group.json())

    def api_registration_check(self):
        '''
        Check registration status through API
        '''
        logger.debug('Checking registration status...')
        machine_id = generate_machine_id()
        try:
            res = self.session.get(self.api_url + '/v1/systems/' + machine_id, timeout=10)
        except requests.ConnectionError as e:
            # can't connect, run connection test
            logger.error('Connection timed out. Running connection test...')
            self.test_connection()
            return False
        # had to do a quick bugfix changing this around,
        #   which makes the None-False-True dichotomy seem fucking weird
        #   TODO: reconsider what gets returned, probably this:
        #       True for registered
        #       False for unregistered
        #       None for system 404
        try:
            # check the 'unregistered_at' key of the response
            unreg_status = json.loads(res.content).get('unregistered_at', 'undefined')
            # set the global account number
            InsightsClient.account_number = json.loads(res.content).get('account_number', 'undefined')
        except ValueError:
            # bad response, no json object
            return False
        if unreg_status == 'undefined':
            # key not found, machine not yet registered
            return None
        elif unreg_status is None:
            # unregistered_at = null, means this machine IS registered
            return True
        else:
            # machine has been unregistered, this is a timestamp
            return unreg_status

    def unregister(self):
        """
        Unregister this system from the insights service
        """
        machine_id = generate_machine_id()
        try:
            logger.debug("Unregistering %s", machine_id)
            self.session.delete(self.api_url + "/v1/systems/" + machine_id)
            logger.info(
                "Successfully unregistered from the Red Hat Insights Service")
            write_unregistered_file()
            InsightsSchedule().remove_scheduling()
        except requests.ConnectionError as e:
            logger.debug(e)
            logger.error("Could not unregister this system")

    def register(self):
        """
        Register this machine
        """

        delete_unregistered_file()

        client_hostname = determine_hostname()
        # This will undo a blacklist
        logger.debug("API: Create system")
        system = self.create_system(new_machine_id=False)

        # If we get a 409, we know we need to generate a new machine-id
        if system.status_code == 409:
            system = self.create_system(new_machine_id=True)
        self.handle_fail_rcs(system)

        logger.debug("System: %s", system.json())

        message = system.headers.get("x-rh-message", "")

        write_registered_file()

        # Do grouping
        if InsightsClient.options.group is not None:
            self.do_group()

        # Display registration success messasge to STDOUT and logs
        if system.status_code == 201:
            try:
                system_json = system.json()
                machine_id = system_json["machine_id"]
                account_number = system_json["account_number"]
                logger.info("You successfully registered %s to account %s." % (machine_id, account_number))
            except:
                logger.debug('Received invalid JSON on system registration.')
                logger.debug('API still indicates valid registration with 201 status code.')
                logger.debug(system)
                logger.debug(system.json())

        if InsightsClient.options.group is not None:
            return (message, client_hostname, InsightsClient.options.group, InsightsClient.options.display_name)
        elif InsightsClient.options.display_name is not None:
            return (message, client_hostname, "None", InsightsClient.options.display_name)
        else:
            return (message, client_hostname, "None", "")

    def upload_archive(self, data_collected, duration, cluster=None):
        """
        Do an HTTPS Upload of the archive
        """
        file_name = os.path.basename(data_collected)
        try:
            import magic
            m = magic.open(magic.MAGIC_MIME)
            m.load()
            mime_type = m.file(data_collected)
        except ImportError:
            magic = None
            logger.debug('python-magic not installed, using backup function...')
            mime_type = magic_plan_b(data_collected)

        fo = open(data_collected, 'rb')

        files = {
            'file': (file_name, fo, mime_type)}

        if cluster:
            upload_url = self.upload_url + '/' + cluster
        else:
            upload_url = self.upload_url + '/' + generate_machine_id()

        logger.debug("Uploading %s to %s", data_collected, upload_url)

        headers = {'x-rh-collection-time': duration}
        upload = self.session.post(upload_url, files=files, headers=headers)

        logger.debug("Upload status: %s %s %s",
                     upload.status_code, upload.reason, upload.text)
        logger.debug("Upload duration: %s", upload.elapsed)
        return upload

class InsightsArchive(object):

    """
    This class is an interface for adding command output
    and files to the insights archive
    """

    def __init__(self, compressor="gz", target_name=None):
        """
        Archive creation proceeds in two steps: data collection followed by actual archive creation.

        During data collection, data is collected into a directory tree, each command's output,
        and each files copy, is written to it's own special place in this directory tree according
        to it's spec information.

        Once all the data is collected for all specs, a tar file is created from the directory tree,
        after which the directory tree is deleted.

        The name of the directory tree and the main name of the tar file are the same: 
        **archive_name** which needs to follow a predictable pattern so the Insights Server can
        parse it.

        To prevent attacks based on being able to guess **archive_name**, both the directory
        tree and the actual tar file are created in mkdtemp created directories.  To keep 
        compatibility with the archives expected by the Insights server, the archive tar 
        command needs to start the archive with '.', all the file names stored in the archive start
        with the directory '.', so the directory tree and archive itself must be in separate mkdtemp 
        directories:

        **tree_tmp_dir** is the mkdtemp directory which holds the directory tree, and only the
        directory tree.  The directory tree is accessed directly as **tree_dir**.

        **tar_tmp_dir** is the mkdtemp directory which holds the tar file.

        """
        self.tar_tmp_dir = tempfile.mkdtemp(prefix='/var/tmp/')
        self.tree_tmp_dir = tempfile.mkdtemp(prefix='/var/tmp/')
        name = determine_hostname(target_name)
        self.archive_name = ("insights-%s-%s" %
                             (name,
                              time.strftime("%Y%m%d%H%M%S")))
        self.tree_dir = self.create_tree_dir()
        self.cmd_dir = self.create_command_dir()
        self.compressor = compressor

    def create_tree_dir(self):
        """
        Create the archive dir
        """
        tree_dir = os.path.join(self.tree_tmp_dir, self.archive_name)
        os.makedirs(tree_dir, 0o700)
        return tree_dir

    def create_command_dir(self):
        """
        Create the "sos_commands" dir
        """
        cmd_dir = os.path.join(self.tree_dir, "insights_commands")
        os.makedirs(cmd_dir, 0o700)
        return cmd_dir

    def get_full_archive_path(self, path):
        """
        Returns the full archive path
        """
        return os.path.join(self.tree_dir, path.lstrip('/'))

    def _copy_file(self, path):
        """
        Copy just a single file
        """
        full_path = self.get_full_archive_path(path)
        # Try to make the dir, eat exception if it fails
        try:
            os.makedirs(os.path.dirname(full_path))
        except OSError:
            pass
        logger.debug("Copying %s to %s", path, full_path)
        shutil.copyfile(path, full_path)
        return path

    def copy_file(self, path):
        """
        Copy a single file or regex, creating the necessary directories
        """
        if "*" in path:
            paths = _expand_paths(path)
            if paths:
                for path in paths:
                    self._copy_file(path)
        else:
            if os.path.isfile(path):
                return self._copy_file(path)
            else:
                logger.debug("File %s does not exist", path)
                return False

    def copy_dir(self, path):
        """
        Recursively copy directory
        """
        for directory in path:
            if os.path.isdir(path):
                full_path = os.path.join(self.tree_dir, directory.lstrip('/'))
                logger.debug("Copying %s to %s", directory, full_path)
                shutil.copytree(directory, full_path)
            else:
                logger.debug("Not a directory: %s", directory)
        return path

    def get_compression_flag(self, compressor):
        return {
            "gz": "z",
            "xz": "J",
            "bz2": "j",
            "none": ""
        }.get(compressor, "z")

    def create_tar_file(self):
        """
        Create tar file to be compressed
        """
        tar_file_name = os.path.join(self.tar_tmp_dir, self.archive_name)
        ext = "" if self.compressor == "none" else ".%s" % self.compressor
        tar_file_name = tar_file_name + ".tar" + ext
        tar_cmd = "tar c%sfS %s -C %s ." % (
            self.get_compression_flag(self.compressor),
            tar_file_name,
            self.tree_tmp_dir)
        logger.debug("Tar File: " + tar_file_name)
        logger.debug("Tar cmd: %s" % tar_cmd)
        subprocess.call(shlex.split(tar_cmd),
            stderr=subprocess.PIPE)
        self.delete_tree_tmp_dir()
        logger.debug("Tar File Size: %s", str(os.path.getsize(tar_file_name)))
        return tar_file_name

    def delete_tar_tmp_dir(self):
        """
        Delete the entire tar tmp dir
        """
        logger.debug("Deleting: " + self.tar_tmp_dir)
        shutil.rmtree(self.tar_tmp_dir, True)

    def delete_tree_tmp_dir(self):
        """
        Delete the entire tree tmp dir
        """
        logger.debug("Deleting: " + self.tree_tmp_dir)
        shutil.rmtree(self.tree_tmp_dir, True)

    def add_to_archive(self, spec):
        '''
        Add files and commands to archive
        Use InsightsSpec.get_output() to get data
        '''
        if spec.archive_path:
            archive_path = self.get_full_archive_path(spec.archive_path.lstrip('/'))
        else:
            # should never get here if the spec is correct
            if isinstance(spec, InsightsCommand):
                archive_path = os.path.join(self.cmd_dir, spec.mangled_command.lstrip('/'))
            if isinstance(spec, InsightsFile):
                archive_path = self.get_full_archive_path(spec.relative_path.lstrip('/'))
        output = spec.get_output()
        if output:
            write_data_to_file(output, archive_path)

    def add_metadata_to_archive(self, metadata, meta_path):
        '''
        Add metadata to archive
        '''
        archive_path = self.get_full_archive_path(meta_path.lstrip('/'))
        write_data_to_file(metadata, archive_path)


def _do_upload(pconn, tar_file, logging_name, collection_duration, result):
    # do the upload
    logger.info('Uploading Insights data for %s, this may take a few minutes', logging_name)
    for tries in range(InsightsClient.options.retries):
        upload = pconn.upload_archive(tar_file, collection_duration,
                                      cluster=generate_machine_id(
                                          docker_group=InsightsClient.options.container_mode))
        if upload.status_code == 201:
            machine_id = generate_machine_id()
            #logger.info("You successfully uploaded a report from %s to account %s." % (machine_id, InsightsClient.account_number))
            logger.info("You successfully uploaded a report from %s to account %s." % (machine_id, upload.json()['upload']['account_number']))
            logger.info("Upload completed successfully!")
            result['ansible_facts']['insights_upload_results'] = upload.json()
            return result
        elif upload.status_code == 412:
            pconn.handle_fail_rcs(upload)
            return dict(failed=True,
                        msg="Failed to upload %s, http status 412" % tar_file)
        else:
            logger.error("Upload attempt %d of %d failed! Status Code: %s",
                         tries + 1, InsightsClient.options.retries, upload.status_code)
            if tries + 1 != InsightsClient.options.retries:
                logger.info("Waiting %d seconds then retrying",
                            constants.sleep_time)
                time.sleep(constants.sleep_time)
            else:
                logger.error("All attempts to upload have failed!")
                return dict(failed=True,
                            msg="Failed to upload (%s times) %s" % (tries + 1, tar_file))
    return dict(failed=True,
                msg="Failed to upload (%s times) %s" % (tries + 1, tar_file))

def _delete_archive(archive):
    #archive.delete_tar_tmp_dir()
    archive.delete_tree_tmp_dir()

class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):

        self._supports_check_mode = True
        self._supports_async      = False

        result = super(ActionModule, self).run(tmp, task_vars)

        if result.get('skipped', False):
            return result

        result.update(self._execute_module(module_name="magpie", module_args=self._task.args, task_vars=task_vars))

        global SAVED_MACHINE_ID
        SAVED_MACHINE_ID = None
        if 'ansible_facts' in result:
            if 'magpie_etc/redhat-access-insights/machine-id' in result['ansible_facts']:
                SAVED_MACHINE_ID = result['ansible_facts']['magpie_etc/redhat-access-insights/machine-id']
        if not SAVED_MACHINE_ID:
            return dict(failed=True, msg="Not registered with Insights: no machine-id")

        InsightsClient.config = parse_config_file(constants.default_conf_file)

        username=task_vars.get('redhat_portal_username', DefaultArgument)
        password=task_vars.get('redhat_portal_password', DefaultArgument)


        hostname = "cato"
        logging_name = hostname
        collection_duration = "0.0000"

        if False:
            try:
                pconn = InsightsConnection(
                    username=username,
                    password=password
                    )
                rc = pconn.test_connection()
            except SystemExit, exc:
                if exc == 0:
                    logger.error("system exit called with non zero result")
                    logger.error(exc)
            return {}

        pconn = InsightsConnection(
            username=username,
            password=password,
        )

        try:
            branch_info = pconn.branch_info()
        except requests.ConnectionError:
            return dict(failed=True, msg="Could not connect to Insights")
        except LookupError:
            message = "Could not log into Insights"
            if 'redhat_portal_username' not in task_vars or 'redhat_portal_password' not in task_vars  :
                message += ", 'redhat_portal_username' and/or 'redhat_portal_password' not set."
            return dict(failed=True, msg=message)

        if 'ansible_facts' in result:
            if 'magpie_branch_info' in result['ansible_facts']:
                logger.debug('Incomming BRANCH %s' % result['ansible_facts']['magpie_branch_info'])
                del result['ansible_facts']['magpie_branch_info']

        archive = InsightsArchive(target_name=hostname)
        atexit.register(_delete_archive, archive)

        key_start_to_look_for = 'magpie_'
        if 'ansible_facts' in result:
            for (k,v) in result['ansible_facts'].items():
                if k.startswith(key_start_to_look_for):
                    write_data_to_file(v, archive.get_full_archive_path(k[len(key_start_to_look_for):]))
        write_data_to_file(json.dumps(branch_info), archive.get_full_archive_path("branch_info"))
        tar_file = archive.create_tar_file()

        return _do_upload(pconn, tar_file, logging_name, collection_duration, result)
