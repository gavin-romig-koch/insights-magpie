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
    default_ca_file = "auto" #os.path.join(default_conf_dir, 'cert-api.access.redhat.com.pem')
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

possible_CA_VERIFY_files = [
    "/etc/rhsm/ca/redhat-uep.pem",
    "/etc/redhat-access-insights/cert-api.access.redhat.com.pem",
    "/etc/insights-client/cert-api.access.redhat.com.pem",
]

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
        elif self.cert_verify.lower() == 'auto':
            # check the 'usual' places for a portal verify cert
            for filename in possible_CA_VERIFY_files:
                try:
                    open(filename)
                    self.cert_verify = filename
                    break
                except:
                    pass
            # if we are still 'auto' then none of the usual places worked, so don't verify
            if self.cert_verify.lower() == 'auto':
                self.cert_verify = False


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
        logger.debug("Session Verify Cert: %s" % session.verify)
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

        # module_args = self._task.args
        module_args = {
            'specs' : munge_specs(SPECS),
            }

        result.update(self._execute_module(module_name="magpie", module_args=module_args, task_vars=task_vars))

        if 'failed' in result and result['failed']:
            return result

        global SAVED_MACHINE_ID
        SAVED_MACHINE_ID = None
        if 'ansible_facts' in result:
            if 'magpie_etc/redhat-access-insights/machine-id' in result['ansible_facts']:
                SAVED_MACHINE_ID = result['ansible_facts']['magpie_etc/redhat-access-insights/machine-id']
            if 'magpie_etc/redhat_access_insights/machine_id' in result['ansible_facts']:
                SAVED_MACHINE_ID = result['ansible_facts']['magpie_etc/redhat_access_insights/machine_id']

        if not SAVED_MACHINE_ID:
            result['failed'] = True
            result['msg'] = "Not registered with Insights: no machine-id"
            return result

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

old_style = True

def munge_specs(specs):
    # So it looks like the server won't accept new style archives, which isn't too
    # supprizing
    #
    # But i still want to have the facts come back from magpie with short names,
    # rather than long names, and a reasonable choice for names is the spec names
    # in the new style specs,
    #
    # Rather than try to get new style specs working, we will add 'spec' names to
    # entries in files and commands
    # And produce a local dictionary mapping spec names to files for the archive
    #
    if old_style:
        del specs["specs"]
    else:
        del specs["files"]
        del specs["commands"]
    return specs

SPECS = {
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
