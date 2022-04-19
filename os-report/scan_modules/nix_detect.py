from scan_modules.os_detect import ScannerInterface


class NixDetect(ScannerInterface):
    def os_detect(self):
        os_family = self.execute_cmd("uname -s")
        os_version = self.execute_cmd("uname -r")
        if os_family and os_version:
            os_detection_weight = 10
            return os_version, os_family, os_detection_weight

    def get_host_name(self):
        return self.execute_cmd("hostname")

    def get_ip(self):
        return self.execute_cmd(
            "ifconfig | "
            "grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | "
            "grep -Eo '([0-9]*\.){3}[0-9]*' | "
            "grep -v '127.0.0.1' | "
            "head -1"
        )
