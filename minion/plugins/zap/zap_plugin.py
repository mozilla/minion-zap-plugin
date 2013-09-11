# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import logging
import os
import random
import time
import urlparse

import jinja2
from twisted.internet import reactor
from twisted.internet.threads import deferToThread
from zapv2 import ZAPv2

import reference
from minion.plugins.base import ExternalProcessPlugin

class ZAPPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "ZAP"
    PLUGIN_VERSION = "0.3"

    ZAP_NAME = "zap.sh"
    ZAP_COMPATIBLE_VERSIONS = ('2.2.0',)

    def config(self, data):
        """ Render and write ZAP's config.xml file. """
        curr = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(curr, 'config.xml.example'), 'r') as f:
            content = f.read()
        with open(os.path.join(self.work_directory, 'config.xml'), 'w+') as f:
            template = jinja2.Template(content)
            f.write(template.render(data))

    def exclude(self):
        """ Exclude a set of urls in regex from proxy, scanner and spider. """
        _excludes = {'proxy': self.zap.core.exclude_from_proxy,
            'spider': self.zap.spider.exclude_from_scan,
            'scanner': self.zap.ascan.exclude_from_scan}

        config = self.configuration.get('excludes')
        if config:
            for name, f in _excludes.iteritems():
                if config.get(name):
                    logging.info('%s exist' % name)
                    for url in config[name]:
                        f('\Q%s\E' % url)

    def do_session(self, auth):
        """ Adding session token and its value
        to ZAP session. """

        site_info = self.get_site_info()
        sessions = auth['sessions']

        # in ZAP the site will include both the hostname and port
        netloc = site_info['hostname'] + ':' + str(site_info['port'])
        self.zap.httpsessions.create_empty_session(netloc)
        self.zap.httpsessions.set_active_session(
            netloc,
            'Session 0')
        for session in sessions:
            self.zap.httpsessions.add_session_token(
                netloc,
                session['token'])
            self.zap.httpsessions.set_session_token_value(
                netloc,
                'Session 0',
                session['token'],
                session['value'])

    def _classify(self, alert):
        cwe_url = None
        cwe_id = alert.get('cweid')
        wasc_id = alert.get('wasc_id')
        # ZAP default return '0' for issues don't have a CWE/WASC reference
        if cwe_id == '0':
            cwe_id = None
        if wasc_id == '0':
            wasc_id = None
        if cwe_id:
            cwe_url = "http://cwe.mitre.org/data/definitions/%s.html" % cwe_id
        return {
            "cwe_id": cwe_id,
            "cwe_url": cwe_url,
            "wasc_id": wasc_id,
            "wasc_url": reference.WASC_MAP.get(wasc_id, None)
        }

    def _load_global_config(self):
        """
        Load a global config from either /etc/minion/zap-plugin.json
        or from ~/.minion/zap-plugin.json in that order.
        """
        if os.path.exists("/etc/minion/zap-plugin.json"):
            with open("/etc/minion/zap-plugin.json") as fp:
                return json.load(fp)
        if os.path.exists(os.path.expanduser("~/.minion/zap-plugin.json")):
            with open(os.path.expanduser("~/.minion/zap-plugin.json")) as fp:
                return json.load(fp)

    def do_configure(self):
        logging.debug("ZAPPlugin.do_configure")
        # Load the global configuration file to find the path to zap
        global_config = self._load_global_config()
        if global_config and global_config.get('zap-path'):
            zap_path = global_config.get('zap-path') + '/zap.sh'
            if not os.path.exists(zap_path):
                raise Exception("Cannot find %s" % zap_path)
            self.zap_path = zap_path
        else:
            self.zap_path = self.locate_program(self.ZAP_NAME)
            if self.zap_path is None:
                raise Exception("Cannot find %s in PATH" % self.ZAP_NAME)
        logging.debug("Using ZAP at %s" % self.zap_path)
        # Validate the configuration
        if self.configuration.get('target') is None or len(self.configuration['target']) == 0:
            raise Exception("Missing or invalid target in configuration")

    def do_process_ended(self, status):
        logging.debug("ZAPPlugin.do_process_ended")
        self.callbacks.report_finish()

    def do_start(self):
        logging.debug("ZAPPlugin.do_start")

        policies = self.configuration.get('policies')
        data = {}
        if policies:
            data['policies'] = policies
        # Configure config.xml before starting daemon if
        # user chooses basic auth.
        #TODO: Until I or psiinon add an API to ZAP to configure
        # the configuration file directly via Python API,
        # config.xml must be written BEFORE the server starts up.
        auth = self.configuration.get('auth', {})
        if auth and auth['type'] == 'basic':
                auth.update({'auth': True})
                # we don't expect user to specify hostname
                # or port; but if they do, we will honor user's
                # own value. By updating the return of
                # self.get_site_info() we will ONLY override
                # existing keys in the return by keys present
                # in auth already.
                site_info = self.get_site_info()
                site_info.update(auth)
                data.update(site_info)
        # write config.xml
        self.config(data)

        # Start ZAP in daemon mode
        self.zap_port = self._random_port()
        args = ['-daemon', '-port', str(self.zap_port), '-dir', self.work_directory]
        self.spawn(self.zap_path, args)
        self.report_artifacts("ZAP Output", ["zap.log"])

        # Start the main code in a thread
        return deferToThread(self._blocking_zap_main)

    def _random_port(self):
        return random.randint(8192, 16384)

    #
    # Convert a ZAP alert to a Minion issue.
    #
    #   Summary       alert
    #   Description:  description
    #   Further-Info: (URL:xxx,Title:"")
    #   Severity:     risk
    #   Confidence:   reliability
    #   Solution:     solution
    #   URLs:         (URL:url,Extra:other)*
    #

    def _minion_severity(self, severity):
        if severity == 'Informational':
            return 'Info'
        return severity

    def _minion_issue(self, alert):

        issue = { "_Alert": alert,
                  "Summary" : alert.get('alert'),
                  "Classification": self._classify(alert),
                  "Description" : alert.get('description'),
                  "Severity" : self._minion_severity(alert.get('risk')),
                  "Confidence" : alert.get('reliability'),
                  "Solution" : alert.get('solution'),
                  "URLs" : [{
                        'URL': alert.get('url'),
                        'Extra': alert.get('other'),
                        'Attack': alert.get('attack'),
                        'Evidence': alert.get('evidence'),
                        'Parameter': alert.get('param')
                  }]
        }

        if alert.get('reference', '') != '':
            issue["FurtherInfo"] = [{'URL': url, 'Title': None} for url in alert.get('reference').split("\n")]

        return issue

    def _blocking_zap_main(self):
        logging.debug("ZAPPlugin._blocking_zap_main")
        self.report_progress(15, 'Starting ZAP')

        try:
            self.zap = ZAPv2(proxies={'http': 'http://127.0.0.1:%d' % self.zap_port, 'https': 'http://127.0.0.1:%d' % self.zap_port})
            target = self.configuration['target']
            logging.info('Accessing target %s' % target)

            # ZAP start-up time can take a little while
            while (True):
                try:
                    self.zap.urlopen(target)
                    break
                except IOError as e:
                    time.sleep(2)

            version = self.zap.core.version
            if version not in self.ZAP_COMPATIBLE_VERSIONS:
                issue = { "Summary": "Incompatible version of ZAP found.",
                          "Description": "This version of the Minion ZAP Plugin is only compatible with ZAP versions %s. You have %s installed." % (str(self.ZAP_COMPATIBLE_VERSIONS), version),
                          "Severity": "Error" }
                self.report_issue(issue)
                zapbug783 = self.zap.core.shutdown
                self.report_finish()
                return


            # Once we know ZAP is fully started, we can
            # setup sessions if auth type == 'sessions'
            auth = self.configuration.get('auth')
            if auth and isinstance(auth, dict) and auth.get('type') == 'session':
                self.do_session(auth)

            self.exclude()

            # Give the sites tree a chance to get updated
            time.sleep(2)
            logging.info('Spidering target %s' % target)
            self.report_progress(34, 'Spidering target')

            self.zap.spider.scan(target)
            # Give the Spider a chance to start
            time.sleep(2)
            while True:
                spider_progress = int(self.zap.spider.status)
                logging.info('Spider progress %d' % spider_progress)
                progress = 34 + (spider_progress / 3)
                self.report_progress(progress, 'Spidering target')
                if spider_progress == 100:
                    break
                time.sleep(5)

            logging.info('Spider completed')

            self.report_progress(67, 'Scanning target')
            if self.configuration.get('scan'):
                # Give the passive scanner a chance to finish
                time.sleep(5)

                logging.info('Scanning target %s' % target)
                self.zap.ascan.scan(target, recurse=True)
                time.sleep(5)
                while True:
                    scan_progress = int(self.zap.ascan.status)
                    logging.info('Scan progress %d' % scan_progress)
                    progress = 67 + (scan_progress / 3)
                    self.report_progress(progress, 'Scanning target')
                    if scan_progress == 100:
                        break
                    time.sleep(5)

            self.report_progress(100, 'Completing scan')

            #
            # Report the found issues. We group them by Summary.
            #

            issues_by_summary = {}
            for alert in self.zap.core.alerts()['alerts']:
                issue = self._minion_issue(alert)
                if issue['Summary'] not in issues_by_summary:
                    issues_by_summary[issue['Summary']] = issue
                else:
                    issues_by_summary[issue['Summary']]['URLs'] += issue['URLs']

            for issue in issues_by_summary.values():
                self.report_issues([issue])

            logging.info('Scan completed, shutting down')
            try:
                self.zap.core.shutdown()
            except:
                # TODO shutdown() throws an error but seems to shut down ok
                pass
            self.report_finish()

        except Exception as e:

            logging.exception("Error while executing zap plugin")
