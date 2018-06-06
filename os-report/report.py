#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'videns'
import inspect
import pkgutil
import json
import os
import sys
import scanModules


class scannerEngine():
    def __init__(self, sshPrefix=None):
        self.osInstanceClasses = self.getInstanceClasses()
        self.instance = self.__getInstance(sshPrefix)

    def getInstanceClasses(self):
        self.detectors = None
        members = set()
        for modPath, modName, isPkg in pkgutil.iter_modules(scanModules.__path__):
            #find all classed inherited from scanner.osDetect.ScannerInterface in all files
            members = members.union(inspect.getmembers(__import__('%s.%s' % ('scanModules',modName), fromlist=['scanModules']),
                                         lambda member:inspect.isclass(member)
                                                       and issubclass(member, scanModules.osDetect.ScannerInterface)
                                                       and member.__module__ == '%s.%s' % ('scanModules',modName)
                                                       and member != scanModules.osDetect.ScannerInterface))
        return members

    def getInstance(self):
        return self.instance

    def __getInstance(self,sshPrefix):
        inited = [instance[1](sshPrefix) for instance in self.osInstanceClasses]
        if not inited:
            raise Exception("No OS Detection classes found")
        osInstance = max(inited, key=lambda x:x.osDetectionWeight)
        if osInstance.osDetectionWeight:
            return osInstance

    def auditSystem(self):
        instance = self.getInstance()

        if len(sys.argv) < 2:
            return instance
        elif sys.argv[1] == 'os':
            print(instance.osFamily)
        elif sys.argv[1] == 'version':
            print(instance.osVersion)
        elif sys.argv[1] == 'package':
            print(instance.getPkg())

        return instance

class agentEngine():
    def __init__(self):
        self.host = scannerEngine()

    def main(self):
        self.host.auditSystem()

if __name__ == "__main__":
    agent = agentEngine()
    agent.main()
