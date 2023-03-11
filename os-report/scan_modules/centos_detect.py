import re

from scan_modules.linux_detect import LinuxDetect


class RpmBasedDetect(LinuxDetect):
    supported_families = (
        "redhat",
        "centos",
        "oraclelinux",
        "suse",
        "fedora",
        "ol",
        "rhel",
        "opensuse",
        "sles",
    )

    def __init__(self, ssh_prefix):
        super(RpmBasedDetect, self).__init__(ssh_prefix)

    def os_detect(self):
        os_detection = super(RpmBasedDetect, self).os_detect()
        if os_detection:
            os_version, os_family, os_detection_weight = os_detection

            if os_family in self.supported_families:
                os_detection_weight = 60
                return os_version, os_family, os_detection_weight

        version = self.execute_cmd("cat /etc/centos-release")
        if version:
            os_version = re.search(r"\s+\(?(\d+)\.", version).group(1)
            os_family = "centos"
            os_detection_weight = 70
            return os_version, os_family, os_detection_weight

        version = self.execute_cmd("cat /etc/redhat-release")
        if version:
            os_version = re.search(r"\s+(\d+)\.", version).group(1)
            os_family = "rhel"
            os_detection_weight = 60
            return os_version, os_family, os_detection_weight

        version = self.execute_cmd("cat /etc/SuSE-release")
        if version:
            os_version = re.search(r"VERSION = (\d+)", version).group(1)
            os_family = "opensuse"
            os_detection_weight = 70
            return os_version, os_family, os_detection_weight

    def get_pkg(self):
        pkg_list = self.execute_cmd("rpm -qa | grep -v '^kernel-'")
        uname = self.execute_cmd("uname -r")
        pkg_list += self.execute_cmd("rpm -qa |grep '^kernel.*" + uname + "'")
        return pkg_list
