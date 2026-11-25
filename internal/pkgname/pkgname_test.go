package pkgname

import "testing"

func TestName(t *testing.T) {
	cases := map[string]string{
		"openssl 3.0.2-0ubuntu1 amd64":        "openssl",                      // deb
		"busybox-1.37.0-r31":                  "busybox",                      // apk
		"py3-foo-1.2-r0":                      "py3-foo",                      // apk, hyphenated name
		"bash-5.1.8-6.el8.x86_64":             "bash",                         // rpm
		"sudo-1.9.15p1-2.red80.x86_64":        "sudo",                         // rpm, RED OS
		"openssl-libs-1:3.5.7-1.red80.x86_64": "openssl-libs",                 // rpm with epoch
		"kernel-lt-6.1.190-1.el7.3.x86_64":    "kernel-lt",                    // dotted release
		"bcel-6.8.1-1.el7.noarch":             "bcel",                         // noarch
		"glibc-2.17-326.el7_9.i686":           "glibc",                        // i686
		"gpg-pubkey-f8ac18ee-591e99a0":        "gpg-pubkey-f8ac18ee-591e99a0", // no arch: untouched
		"openssl":                             "openssl",
		"":                                    "",
	}
	for in, want := range cases {
		if got := Name(in); got != want {
			t.Errorf("Name(%q) = %q, want %q", in, got, want)
		}
	}
}
