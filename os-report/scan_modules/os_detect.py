import re
import uuid
import subprocess


try:
    from subprocess import DEVNULL  # py3k
except ImportError:
    import os
    DEVNULL = open(os.devnull, 'wb')


class ScannerInterface:
    def __init__(self, ssh_prefix):
        self.os_version = None
        self.os_family = None
        self.os_detection_weight = 0
        self.ssh_prefix = ssh_prefix
        os_detection = self.os_detect()
        if os_detection is not None:
            self.os_version, self.os_family, self.os_detection_weight = os_detection

    def execute_cmd(self, command):
        if self.ssh_prefix:
            command = "%s %s" % (self.ssh_prefix, command)
        randPre = str(uuid.uuid4()).split('-')[0]
        randAfter = str(uuid.uuid4()).split('-')[0]
        randFail = str(uuid.uuid4()).split('-')[0]
        command = "echo %s; %s; echo %s || echo %s" % (randPre, command, randAfter, randFail)
        cmdResult = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=DEVNULL, shell=True).communicate()[0]

        if isinstance(cmdResult, bytes):
            cmdResult = cmdResult.decode('utf8')
        if randFail in cmdResult:
            return None
        else:
            resMatch = re.search(r"%s\n(.*)\n%s" % (randPre, randAfter), cmdResult, re.DOTALL)
            if resMatch:
                return resMatch.group(1)
            else:
                return ""

    def os_detect(self):
        raise NotImplementedError

    def get_pkg(self):
        raise NotImplementedError
