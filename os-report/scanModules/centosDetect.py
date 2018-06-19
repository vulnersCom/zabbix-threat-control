# -*- coding: utf-8 -*-
__author__ = 'videns'
import re

from scanModules.linuxDetect import linuxDetect


class rpmBasedDetect(linuxDetect):
    def __init__(self,sshPrefix):
        self.supportedFamilies = ('redhat', 'centos', 'oraclelinux',
                                  'suse', 'fedora', 'ol', 'rhel')
        super(rpmBasedDetect, self).__init__(sshPrefix)

    def osDetect(self):
        osDetection = super(rpmBasedDetect, self).osDetect()
        if osDetection:
            (osVersion, osFamily, osDetectionWeight) = osDetection

            if osFamily in self.supportedFamilies:
                osDetectionWeight = 60
                return (osVersion, osFamily, osDetectionWeight)

        version = self.sshCommand("cat /etc/centos-release")
        if version:
            osVersion = re.search("\s+(\d+)\.",version).group(1)
            osFamily = "centos"
            osDetectionWeight = 70
            return (osVersion, osFamily, osDetectionWeight)

        version = self.sshCommand("cat /etc/redhat-release")
        if version:
            osVersion = re.search("\s+(\d+)\.",version).group(1)
            osFamily = "rhel"
            osDetectionWeight = 60
            return (osVersion, osFamily, osDetectionWeight)


    def getPkg(self):
        pkgList = self.sshCommand("rpm -qa | grep -v '^kernel-'")
        uname = self.sshCommand("uname -r")
        pkgList += self.sshCommand("rpm -qa |grep '^kernel.*" + uname + "'")
        return pkgList

