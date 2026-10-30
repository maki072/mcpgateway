package main

import (
	"strings"
	"testing"
	"time"
)

func testApp() *App {
	return &App{cfg: &Config{Hosts: map[string]HostCfg{
		"a": {Group: "web"}, "b": {Group: "web"}, "c": {Group: "db"}, "d": {},
	}}}
}

func TestResolveHosts(t *testing.T) {
	a := testApp()
	got, err := a.resolveHosts([]string{"@web", "c", "a"}, false)
	if err != nil || strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("group+alias: %v %v", got, err)
	}
	if got, _ := a.resolveHosts([]string{"*"}, false); len(got) != 4 {
		t.Errorf("star: %v", got)
	}
	if _, err := a.resolveHosts([]string{"*"}, true); err == nil {
		t.Error("star accepted in write mode")
	}
	for _, bad := range [][]string{{"@nope"}, {"zzz"}, {}, {" "}} {
		if _, err := a.resolveHosts(bad, false); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestFoldResults(t *testing.T) {
	rs := []hostResult{{"a", "exit 0\nok", false}, {"b", "exit 0\nok", false}, {"c", "error: boom", true}}
	out := foldResults(rs)
	if !strings.HasPrefix(out, "3 hosts: 2 ok, 1 failed") || !strings.Contains(out, "### a, b (2)\nexit 0\nok") || !strings.Contains(out, "### c (1)\nerror: boom") {
		t.Errorf("got %q", out)
	}
	same := foldResults(rs[:2])
	if !strings.Contains(same, "same result on all 2 hosts: a, b") {
		t.Errorf("got %q", same)
	}
	if !resultFailed("exit 2\nx") || resultFailed("exit 0\nx") || !resultFailed("error: x") {
		t.Error("resultFailed")
	}
}

func TestWindow(t *testing.T) {
	a := testApp()
	if _, err := a.openWindow("", "", nil, 5); err == nil {
		t.Fatal("window without reason/backup accepted")
	}
	msg, err := a.openWindow("update ro-shell", "copies *.bak on each host", []string{"@web"}, 500)
	if err != nil || !strings.Contains(msg, "(120 min)") {
		t.Fatalf("%q %v", msg, err)
	}
	id := strings.Fields(msg)[1]
	var r, b string
	if err := a.windowFill(id, []string{"a"}, &r, &b); err != nil || r == "" || b == "" {
		t.Fatalf("fill: %q %q %v", r, b, err)
	}
	if err := a.windowFill(id, []string{"c"}, &r, &b); err == nil {
		t.Error("host outside scope accepted")
	}
	if err := a.windowFill("w-none", []string{"a"}, &r, &b); err == nil {
		t.Error("unknown window accepted")
	}
	windows.Lock()
	windows.m[id].Exp = time.Now().Add(-time.Second)
	windows.Unlock()
	if err := a.windowFill(id, []string{"a"}, &r, &b); err == nil {
		t.Error("expired window accepted")
	}
	if _, err := closeWindow(id); err != nil {
		t.Error(err)
	}
}

func TestNewUploadName(t *testing.T) {
	a := testApp()
	for _, bad := range []string{"", "../x", "/etc/x", "dir/"} {
		if _, err := a.newUpload(bad, 1); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
