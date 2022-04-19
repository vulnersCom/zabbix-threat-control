#!/usr/bin/env python3

import sys
import inspect
import pkgutil
import scan_modules


class ScannerEngine:
    def __init__(self, ssh_prefix=None):
        self.os_instance_classes = self.get_instance_classes()
        self.instance = self.__get_instance(ssh_prefix)

    @staticmethod
    def get_instance_classes():
        members = set()
        for module_path, module_name, is_pkg in pkgutil.iter_modules(scan_modules.__path__):
            members = members.union(
                inspect.getmembers(
                    __import__('%s.%s' % ('scan_modules', module_name), fromlist=['scan_modules']),
                    lambda member: (
                            inspect.isclass(member) and
                            issubclass(member, scan_modules.os_detect.ScannerInterface) and
                            member.__module__ == '%s.%s' % ('scan_modules', module_name) and
                            member != scan_modules.os_detect.ScannerInterface
                    )
                )
            )

        return members

    def __get_instance(self, ssh_prefix):
        inited = [instance[1](ssh_prefix) for instance in self.os_instance_classes]
        if not inited:
            raise Exception("No OS Detection classes found")
        os_instance = max(inited, key=lambda x: x.os_detection_weight)
        if os_instance.os_detection_weight:
            return os_instance

    def audit_system(self):
        if len(sys.argv) < 2:
            return self.instance
        elif sys.argv[1] == 'os':
            print(self.instance.os_family)
        elif sys.argv[1] == 'version':
            print(self.instance.os_version)
        elif sys.argv[1] == 'package':
            print(self.instance.get_pkg())
        return self.instance


if __name__ == "__main__":
    ScannerEngine().audit_system()
