# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import logging
import os
import random
import tempfile
import time

from twisted.internet import reactor
from twisted.internet.threads import deferToThread
from minion.plugin_api import ExternalProcessPlugin
from zapv2 import ZAPv2


class ZAPPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "ZAP"
    PLUGIN_VERSION = "0.2"

    ZAP_NAME = "zap.sh"
    
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
        # Start ZAP in daemon mode
        self.zap_port = self._random_port()
        args = ['-daemon', '-port', str(self.zap_port), '-dir', self.work_directory]
        self.spawn(self.zap_path, args)
        self.report_artifacts("ZAP Output", ["zap.log"])
        
        # Start the main code in a thread
        return deferToThread(self._blocking_zap_main)
        
    def _random_port(self):
        return random.randint(8192, 16384)

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
            
            # Give the sites tree a chance to get updated
            time.sleep(2)

            logging.info('Spidering target %s' % target)
            self.report_progress(34, 'Spidering target')
            self.zap.spider.scan(target)
            # Give the Spider a chance to start
            time.sleep(2)
            while True:
                spider_progress = int(self.zap.spider.status['status'])
                logging.debug('Spider progress %d' % spider_progress)
                progress = 34 + (spider_progress / 3)
                self.report_progress(progress, 'Spidering target')
                if spider_progress == 100:
                    break
                time.sleep(5)

            logging.debug('Spider completed')

            self.report_progress(67, 'Scanning target')

            if self.configuration.get('scan'):
                # Give the passive scanner a chance to finish
                time.sleep(5)

                logging.debug('Scanning target %s' % target)
                self.zap.ascan.scan(target,recurse=True)
                time.sleep(5)
                while True:
                    scan_progress = int(self.zap.ascan.status['status'])
                    logging.debug('Scan progress %d' % scan_progress)
                    progress = 67 + (scan_progress / 3)
                    self.report_progress(progress, 'Scanning target')
                    if scan_progress == 100:
                        break
                    time.sleep(5)

            self.report_progress(100, 'Completing scan')
    
            self.report_issues(self.get_results())
            
            logging.info('Scan completed, shutting down')
            try:
                self.zap.core.shutdown()
            except:
                # TODO shutdown() throws an error but seems to shut down ok
                pass
            #self.report_finish()
            
        except Exception as e:
            logging.exception("Error while executing zap plugin")

    def get_results(self):
        alerts = self.zap.core.alerts()
        issues = [] 

        for alert in alerts['alerts']:
            found = False
            for issue in issues:
                # TODO should test other values here as well
                if alert.get('alert') == issue['Summary']:
                    if len(issue['URLs']) < 25:
                        issue['URLs'].append(alert.get('url'))
                    found = True
                    break
                if found:
                    break
            if not found:
                issues.append({
                    "Summary" : alert.get('alert'), 
                    "Description" : alert.get('description'), 
                    "Further-Info" : alert.get('other'), 
                    "Severity" : alert.get('risk'), 
                    "Confidence" : alert.get('reliability'), 
                    "Solution" : alert.get('solution'), 
                    "URLs" : [alert.get('url')]});

        return issues

