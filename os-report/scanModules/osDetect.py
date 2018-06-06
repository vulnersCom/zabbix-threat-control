# -*- coding: utf-8 -*-
__author__ = 'videns'
import subprocess
import uuid
import re
# import logging

try:
    from subprocess import DEVNULL # py3k
except ImportError:
    import os
    DEVNULL = open(os.devnull, 'wb')

# logger = logging.getLogger("main")

class ScannerInterface(object):
    def __init__(self, sshPrefix):
        self.osVersion = None
        self.osFamily = None
        self.osDetectionWeight = 0
        self.sshPrefix = sshPrefix
        osDetection = self.osDetect()
        if osDetection is not None:
            (self.osVersion, self.osFamily, self.osDetectionWeight) = osDetection

    def sshCommand(self, command):
        # logger.debug("Executing ssh command - '%s'" % command)
        if self.sshPrefix:
            command = "%s %s" % (self.sshPrefix, command)
        randPre = str(uuid.uuid4()).split('-')[0]
        randAfter = str(uuid.uuid4()).split('-')[0]
        randFail = str(uuid.uuid4()).split('-')[0]
        command = "echo %s; %s; echo %s || echo %s" % (randPre, command, randAfter, randFail)
        # logger.debug("Full ssh command - '%s'" % command)
        cmdResult = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=DEVNULL, shell=True).communicate()[0]

        if isinstance(cmdResult, bytes):
            cmdResult = cmdResult.decode('utf8')
        # logger.debug("SSH Command result - '%s'" % cmdResult)
        if randFail in cmdResult:
            return None
        else:
            resMatch = re.search(r"%s\n(.*)\n%s" % (randPre, randAfter), cmdResult, re.DOTALL)
            if resMatch:
                return resMatch.group(1)
            else:
                return ""

    def osDetect(self):
        return None

    def getPkg(self):
        return []