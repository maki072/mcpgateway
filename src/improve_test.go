package main

import (
	"strings"
	"testing"
)

func TestReadPipeline(t *testing.T) {
	in := "b 2\na 10\nc 1\na 10\nerror: x\n"
	cases := []struct{ cmd, remote, want string }{
		{"ls -la", "ls -la", in},
		{"cat f | grep a", "cat f", "a 10\na 10\n"},
		{`cat f | grep -v "a 10" | wc -l`, "cat f", "3\n"},
		{"cat f | sort -n | head -2", "cat f", "a 10\na 10\n"},
		{"cat f | sort | uniq -c | head -n 1", "cat f", "      2 a 10\n"},
		{"journalctl -u x | grep -iE 'ERROR|warn' | tail -1", "journalctl -u x", "error: x\n"},
		{`cat f | grep 'a\|c'`, "cat f", "a 10\nc 1\na 10\n"},
		{"cat f | grep -c a", "cat f", "2\n"},
		{"cat f | grep -F 'a 1' | head -1", "cat f", "a 10\n"},
	}
	for _, c := range cases {
		r, fs, err := readPipeline(c.cmd)
		if err != nil || r != c.remote {
			t.Fatalf("%q: remote %q err %v", c.cmd, r, err)
		}
		got, err := applyFilters(in, fs)
		if fs == nil {
			got = in
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %q want %q err %v", c.cmd, got, c.want, err)
		}
	}
	// unknown filters are not run on the gateway: the whole command goes to the host (its mcp-ro-shell decides)
	for _, other := range []string{"cat f | sh", "cat f | grep a /etc/shadow", "cat f | grep $(id)", "cat f | tee x", "cat f | awk '{print}'", "| grep a", "ls | cut -c1-9"} {
		if r, fs, err := readPipeline(other); err != nil || fs != nil || r != other {
			t.Errorf("%q: remote %q filters %v err %v", other, r, fs != nil, err)
		}
	}
	if r, fs, _ := readPipeline("a || b"); fs != nil || r != "a || b" {
		t.Error("|| treated as a pipe")
	}
	if r, fs, _ := readPipeline(`grep "x|y" f`); fs != nil || r != `grep "x|y" f` {
		t.Error("quoted | treated as a pipe")
	}
	// a command list goes to the host as it is: a trailing filter must not be applied to the last command only on the gateway
	for _, list := range []string{"uptime; df -h | head -3", "ls; ps | grep ssh", "ls && ps | wc -l", "ls & ps | head"} {
		if r, fs, err := readPipeline(list); err != nil || fs != nil || r != list {
			t.Errorf("%q: remote %q filters %v err %v", list, r, fs != nil, err)
		}
	}
	if r, fs, _ := readPipeline(`grep "a;b" f | head -2`); fs == nil || r != `grep "a;b" f` {
		t.Error("quoted ; broke the pipeline split")
	}
}

func TestMaskSecrets(t *testing.T) {
	cases := map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN=cfut_abcdefghijklmnopqrstuvwxyz0123":                 "CLOUDFLARE_DNS_API_TOKEN=cfut_***",
		"/user add name=mcp-ro password=Xy7pQw9zLm":                                    "/user add name=mcp-ro password=***",
		`{"password": "hunter2hunter2"}`:                                               `{"password": ***}`,
		"Authorization: Bearer abcdef0123456789":                                       "Authorization: Bearer ***",
		"token ghp_0123456789abcdefghijABCDEFGHIJ end":                                 "token ghp_*** end",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----": "-----BEGIN PRIVATE KEY----- *** (masked) -----END PRIVATE KEY-----",
		"TOKEN=$TOKEN curl":      "TOKEN=$TOKEN curl",
		"ls -la /etc/ssh":        "ls -la /etc/ssh",
		"secret_file=/etc/x.env": "secret_file=***",
	}
	for in, want := range cases {
		if got := maskSecrets(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestPatchAndSection(t *testing.T) {
	s := "# T\n## A\none\n\n## B\ntwo\n"
	if _, _, err := patchText(s, "zzz", "y", false); err == nil {
		t.Error("missing old accepted")
	}
	if _, _, err := patchText("x x", "x", "y", false); err == nil {
		t.Error("ambiguous old accepted")
	}
	if got, n, err := patchText("x x", "x", "y", true); err != nil || n != 2 || got != "y y" {
		t.Errorf("replace_all: %q %d %v", got, n, err)
	}
	got, err := appendToSection(s, "A", "added")
	if err != nil || got != "# T\n## A\none\nadded\n\n## B\ntwo\n" {
		t.Errorf("section A: %q %v", got, err)
	}
	got, err = appendToSection(s, "B", "end\n")
	if err != nil || got != "# T\n## A\none\n\n## B\ntwo\nend\n" {
		t.Errorf("section B: %q %v", got, err)
	}
}

func TestDisruptive(t *testing.T) {
	ok := []string{"iptables -S", "iptables -t nat -nvL", "nft list ruleset", "sysctl net.ipv4.ip_forward",
		"/ip firewall filter print stats", "/interface print", "/user print", "cat /etc/hosts", "/ip route print where dst-address~\"10.\""}
	bad := []string{"iptables -A INPUT -j DROP", "iptables -t mangle -I PREROUTING 1 -j MARK", "nft flush ruleset", "sysctl -w a=1", "sysctl net.ipv4.ip_forward=0",
		"/ip firewall filter add chain=input action=drop", "/interface set ether1 disabled=yes", "/user remove x", "systemctl restart nginx", "reboot", "/system reboot"}
	for _, c := range ok {
		if disruptive.MatchString(c) {
			t.Errorf("flagged: %q", c)
		}
	}
	for _, c := range bad {
		if !disruptive.MatchString(c) {
			t.Errorf("not flagged: %q", c)
		}
	}
}

func TestCompactEvent(t *testing.T) {
	e := map[string]any{"ev": "tool", "tool": "ssh", "op": "exec", "host": "zb", "mode": "read", "ok": false, "ms": 2500.0,
		"ts": "2026-10-30T13:00:06Z", "command": strings.Repeat("x", 300), "error": "boom"}
	got := compactEvent(e)
	if !strings.HasPrefix(got, "10-30T13:00 ssh/exec zb read FAIL 2s | xxx") || !strings.HasSuffix(got, "| err: boom") || len(got) > 200 {
		t.Errorf("got %q", got)
	}
}
