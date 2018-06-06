# -*- coding: utf-8 -*-
__author__ = 'videns'
import re

from scanModules.nixDetect import nixDetect

class linuxDetect(nixDetect):
    def osDetect(self):
        version = self.sshCommand("cat /etc/os-release")
        if version:
            reFamily = re.search(r"^ID=(.*)", version, re.MULTILINE)
            if reFamily:
                osFamily = reFamily.group(1).lower().strip('"')
            else:
                return

            reVersion = re.search("^VERSION_ID=(.*)", version, re.MULTILINE)
            if reVersion:
                osVersion = reVersion.group(1).lower().strip('"')
            else:
                return

            osDetectionWeight = 50
            return (osVersion, osFamily, osDetectionWeight)
