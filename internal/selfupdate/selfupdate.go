// Package selfupdate reports whether a newer ztc release exists and installs it
// by replacing the running binary with the matching asset from GitHub Releases.
// It uses only the standard library.
package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases are published to.
const Repo = "vulnersCom/zabbix-threat-control"

const maxDownload = 100 << 20 // 100 MiB

func client() *http.Client { return &http.Client{Timeout: 60 * time.Second} }

// LatestVersion returns the newest release tag (e.g. "v2.1.0").
func LatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+Repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github releases: status %d", resp.StatusCode)
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return "", err
	}
	if r.TagName == "" {
		return "", fmt.Errorf("no tag_name in latest release")
	}
	return r.TagName, nil
}

// IsNewer reports whether latest is a strictly higher semver than current. It
// returns false when current is a dev build or either version is unparseable,
// so nightly/dev binaries never nag.
func IsNewer(current, latest string) bool {
	c, ok1 := parseSemver(current)
	l, ok2 := parseSemver(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v = strings.SplitN(v, "-", 2)[0] // drop any -prerelease suffix
	parts := strings.Split(v, ".")
	var out [3]int
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i := range parts {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Upgrade downloads the release asset for this OS/arch, verifies its checksum,
// and atomically replaces the running executable. version="" resolves latest.
// It returns the version that was installed.
func Upgrade(ctx context.Context, version string) (string, error) {
	if version == "" {
		v, err := LatestVersion(ctx)
		if err != nil {
			return "", err
		}
		version = v
	}
	asset := fmt.Sprintf("ztc_%s_%s_%s.tar.gz", strings.TrimPrefix(version, "v"), runtime.GOOS, runtime.GOARCH)
	base := "https://github.com/" + Repo + "/releases/download/" + version

	tarball, err := download(ctx, base+"/"+asset)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", asset, err)
	}
	if sums, err := download(ctx, base+"/checksums.txt"); err == nil {
		if err := verifyChecksum(tarball, sums, asset); err != nil {
			return "", err
		}
	}
	bin, err := extractBinary(tarball)
	if err != nil {
		return "", err
	}
	if err := replaceSelf(bin); err != nil {
		return "", err
	}
	return version, nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

func verifyChecksum(tarball, sums []byte, asset string) error {
	sum := sha256.Sum256(tarball)
	want := hex.EncodeToString(sum[:])
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == asset {
			if f[0] != want {
				return fmt.Errorf("checksum mismatch for %s", asset)
			}
			return nil
		}
	}
	return fmt.Errorf("no checksum entry for %s", asset)
}

func extractBinary(tarball []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == "ztc" {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
	return nil, fmt.Errorf("ztc binary not found in archive")
}

// replaceSelf atomically swaps the running executable for newBin (write a temp
// file in the same directory, then rename over the original — works on Linux
// even while the old binary is executing).
func replaceSelf(newBin []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".ztc-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s (run as root/sudo to self-update): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(newBin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return fmt.Errorf("replace %s: %w", exe, err)
	}
	return nil
}
