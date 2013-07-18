# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import random
import time
import urlparse

import jinja2
from twisted.internet import reactor
from twisted.internet.threads import deferToThread
from zapv2 import ZAPv2

from minion.plugins.base import ExternalProcessPlugin

class ZAPPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "ZAP"
    PLUGIN_VERSION = "0.3"

    ZAP_NAME = "zap.sh"
    
    def config(self, data):
        """ Render and write ZAP's config.xml file. """
        curr = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(curr, 'config.xml.example'), 'r') as f:
            content = f.read()
        with open(os.path.join(self.work_directory, 'config.xml'), 'w+') as f:
            template = jinja2.Template(content)
            f.write(template.render(data))

    def do_session(self, auth):
        """ Adding session token and its value
        to ZAP session. """

        site_info = self.get_site_info()
        sessions = auth['sessions']
        self.zap.httpsessions.set_active_session(
            site_info['netloc'],
            'Session 0')
        for session in sessions:                    
            self.zap.httpsessions.add_session_token(
                site_info['netloc'],
                session['token'])
            self.zap.httpsessions.set_session_token_value(
                site_info['netloc'],
                'Session 0',
                session['token'],
                session['value'])

    def do_configure(self):
        logging.debug("ZAPPlugin.do_configure")
        self.zap_path = self.locate_program(self.ZAP_NAME)
        if self.zap_path is None:
            raise Exception("Cannot find %s in PATH" % self.ZAP_NAME)
        # Validate the configuration
        if self.configuration.get('target') is None or len(self.configuration['target']) == 0:
            raise Exception("Missing or invalid target in configuration")

    def do_process_ended(self, status):
        logging.debug("ZAPPlugin.do_process_ended")
        self.callbacks.report_finish()

    def do_start(self):
        logging.debug("ZAPPlugin.do_start")

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
                # write config.xml
                self.config(site_info)

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
                  "Description" : alert.get('description'),
                  "Severity" : self._minion_severity(alert.get('risk')),
                  "Confidence" : alert.get('reliability'),
                  "Solution" : alert.get('solution'),
                  "URLs" : [{'URL': alert.get('url'), 'Extra': alert.get('other')}] }
        
        if alert.get('reference', '') != '':
            issue["FurtherInfo"] = [{'URL': url, 'Title': None} for url in alert.get('reference').split("\n")]

        return issue

    def _blocking_zap_main(self):
        logging.debug("ZAPPlugin._blocking_zap_main")
        self.report_progress(15, 'Starting ZAP')

        try:
            self.zap = ZAPv2(proxies={'http': 'http://127.0.0.1:%d' % self.zap_port, 'https': 'http://127.0.0.1:%d' % self.zap_port})
            target = self.configuration['target']
            time.sleep(5)
            logging.info('Accessing target %s' % target)

            
            while (True):
                try:
                    self.zap.urlopen(target)
                    break
                except IOError as e:
                    time.sleep(2)
            
            # Once we know ZAP is fully started, we can
            # setup sessions if auth type == 'sessions'
            auth = self.configuration.get('auth')
            if auth and isinstance(auth, dict) and auth.get('type') == 'session':
                self.do_session(auth)
            
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
                self.zap.ascan.scan(target,recurse=True)
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

