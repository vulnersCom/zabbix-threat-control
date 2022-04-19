import re
from scan_modules.nix_detect import NixDetect


class LinuxDetect(NixDetect):
    def os_detect(self):
        version = self.execute_cmd("cat /etc/os-release")
        if version:
            re_family = re.search(r"^ID=(.*)", version, re.MULTILINE)
            if re_family:
                os_family = re_family.group(1).lower().strip('"')
            else:
                return

            reVersion = re.search("^VERSION_ID=(.*)", version, re.MULTILINE)
            if reVersion:
                os_version = reVersion.group(1).lower().strip('"')
            else:
                return

            os_detection_weight = 50
            return os_version, os_family, os_detection_weight
