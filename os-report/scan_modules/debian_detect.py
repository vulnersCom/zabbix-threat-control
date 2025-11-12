import re

from scan_modules.linux_detect import LinuxDetect


class DebianBasedDetect(LinuxDetect):
    deb_code_map = {
        "forky": "14",
        "trixie": "13",
        "bookworm": "12",
        "bullseye": "11",
        "buster": "10",
        "stretch": "9",
        "jessie": "8",
        "wheezy": "7",
        "squeeze": "6",
        "lenny": "5",
        "etch": "4",
        "sarge": "3.1",
        "woody": "3.0",
        "potato": "2.2",
        "slink": "2.1",
        "hamm": "2.0",
    }
    supported_families = ("debian", "ubuntu", "kali")

    def __init__(self, ssh_prefix):
        super(DebianBasedDetect, self).__init__(ssh_prefix)

    def os_detect(self):
        os_detection = super(DebianBasedDetect, self).os_detect()
        if os_detection:
            os_version, os_family, os_detection_weight = os_detection

            if os_family in self.supported_families:
                os_detection_weight = 60
                return os_version, os_family, os_detection_weight

        version = self.execute_cmd("cat /etc/debian_version")
        if version and re.match(r"^[\d\.]+$", version):
            os_version = version
            os_family = "debian"
            os_detection_weight = 60
            return os_version, os_family, os_detection_weight
        elif version and re.match(r"^\w+/\w+", version):
            os_code = re.search(r"^(\w+)/", version).group(1).lower()
            if os_code in self.deb_code_map:
                os_version = self.deb_code_map[os_code]
                os_family = "debian"
                os_detection_weight = 60
                return os_version, os_family, os_detection_weight

        version = self.execute_cmd("cat /etc/lsb-release")
        if version:
            mID = re.search('^DISTRIB_ID="?(.*?)"?', version, re.MULTILINE)
            mVer = re.search('^DISTRIB_RELEASE="?(.*?)"?', version, re.MULTILINE)
            if mID and mVer:
                os_family = mID.group(1).lower()
                os_version = mVer.group(1).lower()
                os_detection_weight = 60
                return os_version, os_family, os_detection_weight

    def get_pkg(self):
        return self.execute_cmd(
            "dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\\n'| "
            'awk \'($1 == "install" || $1 == "hold") && ($2 == "ok") {print $4" "$5" "$6}\''
        )
