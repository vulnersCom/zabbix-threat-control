# -*- coding: utf-8 -*-
__author__ = 'videns'
from scanModules.osDetect import ScannerInterface


class nixDetect(ScannerInterface):
    def osDetect(self):
        osFamily = self.sshCommand("uname -s")
        osVersion = self.sshCommand("uname -r")
        if osFamily and osVersion:
            osDetectionWeight = 10
            return (osVersion, osFamily, osDetectionWeight)

    def getHostName(self):
        return self.sshCommand("hostname")

    def getIP(self):
        return self.sshCommand("ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1")
