package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxOut        = 4 << 20  // raw capture before filtering
	defOutBytes   = 8 << 10  // returned by default
	maxOutBytes   = 64 << 10 // returned at most
	defTimeout    = 60
	maxTimeout    = 600
	maxStdin      = 1 << 20
	minNoteLength = 10
)

// disruptive matches commands that can cut access, stop services or destroy data.
// This is a speed bump that forces an explicit allow_disruptive=true, not a security boundary:
// real privilege separation comes from the read-only credentials on the remote side.
var disruptive = regexp.MustCompile(`(?i)(\b(reboot|shutdown|poweroff|halt|mkfs\S*|wipefs|fdisk|parted|sgdisk|kexec)\b|\binit\s+[06]\b|systemctl\s+(reboot|poweroff|halt|stop|disable|mask|restart)\b|\bpct\s+(stop|shutdown|destroy|restore|reboot|migrate)\b|\bqm\s+(stop|shutdown|destroy|reset|restore|reboot|migrate)\b|\bzpool\s+(destroy|export|offline|detach|remove|labelclear)\b|\bzfs\s+(destroy|rollback)\b|\bdd\s+[^|;&]*of=/dev|rm\s+-[a-z]*r[a-z]*\s+(--\s+)?/(\s|\*|$)|\biptables\b|\bnft\b|\bip\s+(link|addr|address|route)\s+(set|del|delete|flush|add)|\bdocker\s+(rm|rmi|kill|stop|restart|system\s+prune|volume\s+(rm|prune)|compose\s+(down|rm|stop|restart))|/system\s+(reboot|shutdown|reset-configuration|package|upgrade|routerboard)|/user\b|/ip\s+(service|ssh|firewall|address|route|dhcp-server|dns)\b|/interface\b|/routing\b|/system\s+(script|scheduler|identity|clock)\b|\bpasswd\b|\bchpasswd\b|authorized_keys|sshd_config|/etc/pve|\bpvecm\b|\bpveum\b)`)

var safePath = regexp.MustCompile(`^[A-Za-z0-9_./@:+,=~ -]{1,512}$`)

type limitedBuf struct {
	buf   bytes.Buffer
	trunc bool
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	room := maxOut - l.buf.Len()
	if room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
			l.trunc = true
		} else {
			l.buf.Write(p)
		}
	} else {
		l.trunc = true
	}
	return len(p), nil
}

func (l *limitedBuf) String() string {
	s := strings.ToValidUTF8(l.buf.String(), "?")
	if l.trunc {
		s += "\n[raw output truncated at 4 MiB]"
	}
	return s
}

func (a *App) host(name string) (HostCfg, error) {
	h, ok := a.cfg.Hosts[name]
	if !ok {
		names := make([]string, 0, len(a.cfg.Hosts))
		for n := range a.cfg.Hosts {
			names = append(names, n)
		}
		return h, fmt.Errorf("unknown host %q (known: %s)", name, strings.Join(names, ", "))
	}
	return h, nil
}

func (a *App) creds(h HostCfg, write bool) (user, key string, err error) {
	if write {
		if h.RWUser == "" {
			return "", "", errors.New("this host has no write credentials configured (read-only)")
		}
		return h.RWUser, h.RWKey, nil
	}
	return h.ROUser, h.ROKey, nil
}

func (a *App) sshOpts(h HostCfg, key string) []string {
	return []string{
		"-F", "/dev/null",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + a.cfg.KnownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-i", key,
	}
}

func cleanEnv() []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8"}
}

func (a *App) hostLock(name string) *sync.Mutex {
	m, _ := a.hostLocks.LoadOrStore(name, &sync.Mutex{})
	return m.(*sync.Mutex)
}

type execArgs struct {
	Host           string `json:"host"`
	Command        string `json:"command"`
	Mode           string `json:"mode"` // "read" (default) or "write"
	TimeoutSec     int    `json:"timeout_sec"`
	Stdin          string `json:"stdin"`
	Reason         string `json:"reason"`
	BackupNote     string `json:"backup_note"`
	AllowDisruptiv bool   `json:"allow_disruptive"`
	Grep           string `json:"grep"`      // keep only stdout lines matching this regexp
	Head           int    `json:"head"`      // keep the first N lines (after grep)
	Tail           int    `json:"tail"`      // keep the last N lines (after grep)
	MaxBytes       int    `json:"max_bytes"` // cap of returned stdout, default 8 KiB, max 64 KiB
}

// shapeOutput applies grep/head/tail and the byte cap on the gateway side, so large outputs cost few tokens.
func shapeOutput(s string, x execArgs) (string, error) {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	total := len(lines)
	if s == "" {
		lines, total = nil, 0
	}
	if x.Grep != "" {
		re, err := regexp.Compile(x.Grep)
		if err != nil {
			return "", fmt.Errorf("grep: %v", err)
		}
		kept := lines[:0:0]
		for _, l := range lines {
			if re.MatchString(l) {
				kept = append(kept, l)
			}
		}
		lines = kept
	}
	if x.Head > 0 && len(lines) > x.Head {
		lines = lines[:x.Head]
	}
	if x.Tail > 0 && len(lines) > x.Tail {
		lines = lines[len(lines)-x.Tail:]
	}
	out := strings.Join(lines, "\n")
	limit := x.MaxBytes
	if limit <= 0 {
		limit = defOutBytes
	}
	if limit > maxOutBytes {
		limit = maxOutBytes
	}
	if len(out) > limit {
		cut := strings.ToValidUTF8(out[:limit], "")
		out = cut + fmt.Sprintf("\n[cut at %d bytes of %d; %d lines total — narrow with grep/head/tail or raise max_bytes]", limit, len(strings.Join(lines, "\n")), total)
	} else if len(lines) < total {
		out += fmt.Sprintf("\n[%d of %d lines shown]", len(lines), total)
	}
	return out, nil
}

// checkWrite enforces the guard-rails for state-changing operations.
func checkWrite(reason, backup string) error {
	if len(strings.TrimSpace(reason)) < minNoteLength || len(strings.TrimSpace(backup)) < minNoteLength {
		return errors.New("write mode requires 'reason' and 'backup_note' (what backup/rollback exists), at least 10 characters each")
	}
	return nil
}

func (a *App) sshExec(ctx context.Context, x execArgs) (string, error) {
	h, err := a.host(x.Host)
	if err != nil {
		return "", err
	}
	write := x.Mode == "write"
	if x.Mode != "" && x.Mode != "read" && x.Mode != "write" {
		return "", errors.New(`mode must be "read" or "write"`)
	}
	if strings.TrimSpace(x.Command) == "" || len(x.Command) > 8192 || strings.ContainsRune(x.Command, 0) {
		return "", errors.New("command empty, too long or contains NUL")
	}
	if len(x.Stdin) > maxStdin {
		return "", errors.New("stdin too large")
	}
	if x.Grep != "" {
		if _, err := regexp.Compile(x.Grep); err != nil {
			return "", fmt.Errorf("grep: %v", err)
		}
	}
	if write {
		if err := checkWrite(x.Reason, x.BackupNote); err != nil {
			return "", err
		}
		if disruptive.MatchString(x.Command) && !x.AllowDisruptiv {
			return "", errors.New("command looks disruptive (service/network/user/firewall/storage change); repeat with allow_disruptive=true only if the backup and rollback plan are in place")
		}
		l := a.hostLock(x.Host)
		l.Lock()
		defer l.Unlock()
	}
	user, key, err := a.creds(h, write)
	if err != nil {
		return "", err
	}
	to := x.TimeoutSec
	if to <= 0 {
		to = defTimeout
	}
	if to > maxTimeout {
		to = maxTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(to)*time.Second)
	defer cancel()
	args := append(a.sshOpts(h, key), "-p", strconv.Itoa(h.Port), user+"@"+h.Addr, x.Command)
	cmd := exec.CommandContext(cctx, a.cfg.SSHBin, args...)
	cmd.Env = cleanEnv()
	var so, se limitedBuf
	cmd.Stdout, cmd.Stderr = &so, &se
	if x.Stdin != "" {
		cmd.Stdin = strings.NewReader(x.Stdin)
	}
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if cctx.Err() == context.DeadlineExceeded {
		se.Write([]byte("\n[timeout after " + strconv.Itoa(to) + "s]"))
	}
	stdout, err := shapeOutput(so.String(), x)
	if err != nil {
		return "", err
	}
	res := fmt.Sprintf("exit %d\n%s", code, stdout)
	if e := strings.TrimSpace(se.String()); e != "" {
		if len(e) > 4096 {
			e = strings.ToValidUTF8(e[len(e)-4096:], "") // the end of stderr carries the error
		}
		res += "\n--- stderr ---\n" + e
	}
	return res, nil
}

type xferArgs struct {
	Host       string `json:"host"`
	RemotePath string `json:"remote_path"`
	TmpPath    string `json:"tmp_path"`
	Reason     string `json:"reason"`
	BackupNote string `json:"backup_note"`
}

func (a *App) scp(ctx context.Context, x xferArgs, upload bool) (string, error) {
	h, err := a.host(x.Host)
	if err != nil {
		return "", err
	}
	if !safePath.MatchString(x.RemotePath) || strings.HasPrefix(x.RemotePath, "-") || strings.Contains(x.RemotePath, "..") {
		return "", errors.New("remote_path contains unsupported characters")
	}
	local, err := a.fsys.tmpLocalPath(x.TmpPath)
	if err != nil {
		return "", err
	}
	if upload {
		if err := checkWrite(x.Reason, x.BackupNote); err != nil {
			return "", err
		}
		if _, err := os.Stat(local); err != nil {
			return "", errors.New("tmp_path does not exist (write the file to the tmp root first)")
		}
		l := a.hostLock(x.Host)
		l.Lock()
		defer l.Unlock()
	} else {
		rel, _ := cleanRel(x.TmpPath)
		r, _ := a.fsys.root("tmp")
		if err := mkdirAll(r, path.Dir(rel)); err != nil {
			return "", err
		}
	}
	user, key, err := a.creds(h, upload)
	if err != nil {
		return "", err
	}
	args := a.sshOpts(h, key)
	args = append(args, "-q", "-P", strconv.Itoa(h.Port))
	if h.SCPLegacy {
		args = append(args, "-O")
	}
	remote := user + "@" + h.Addr + ":" + x.RemotePath
	if upload {
		args = append(args, "--", local, remote)
	} else {
		args = append(args, "--", remote, local)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, a.cfg.SCPBin, args...)
	cmd.Env = cleanEnv()
	var se limitedBuf
	cmd.Stderr = &se
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("scp failed: %v: %s", err, se.String())
	}
	if upload {
		return fmt.Sprintf("uploaded tmp:%s -> %s:%s", x.TmpPath, x.Host, x.RemotePath), nil
	}
	st, _ := os.Stat(local)
	size := int64(0)
	if st != nil {
		size = st.Size()
	}
	return fmt.Sprintf("downloaded %s:%s -> tmp:%s (%d bytes)", x.Host, x.RemotePath, x.TmpPath, size), nil
}
