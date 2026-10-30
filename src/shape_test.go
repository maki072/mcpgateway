package main

import "testing"

func TestShapeOutput(t *testing.T) {
	in := "a1\nb2\na3\nb4\na5\n"
	cases := []struct {
		x    execArgs
		want string
	}{
		{execArgs{}, "a1\nb2\na3\nb4\na5"},
		{execArgs{Grep: "^a"}, "a1\na3\na5\n[3 of 5 lines shown]"},
		{execArgs{Grep: "^a", Head: 1}, "a1\n[1 of 5 lines shown]"},
		{execArgs{Tail: 2}, "b4\na5\n[2 of 5 lines shown]"},
		{execArgs{MaxBytes: 4}, "a1\nb\n[cut at 4 bytes of 14; 5 lines total — narrow with grep/head/tail or raise max_bytes]"},
	}
	for i, c := range cases {
		got, err := shapeOutput(in, c.x)
		if err != nil || got != c.want {
			t.Errorf("case %d: got %q want %q err %v", i, got, c.want, err)
		}
	}
	if _, err := shapeOutput(in, execArgs{Grep: "("}); err == nil {
		t.Error("bad regexp accepted")
	}
}

func TestSections(t *testing.T) {
	doc := "# T\nintro\n## A\na text\n```\n# not a heading\n```\n### A1\nx\n## B\nb text\n"
	toc := tocText("p", doc)
	if want := "L3 ## A"; !contains(toc, want) || contains(toc, "not a heading") {
		t.Errorf("toc: %s", toc)
	}
	s, err := sectionText(doc, "a")
	if err != nil || s != "## A\na text\n```\n# not a heading\n```\n### A1\nx\n" {
		t.Errorf("section A: %q %v", s, err)
	}
	s, err = sectionText(doc, "B")
	if err != nil || s != "## B\nb text\n" {
		t.Errorf("section B: %q %v", s, err)
	}
	if _, err := sectionText(doc, "zzz"); err == nil {
		t.Error("missing section accepted")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestDecodeCoercesStrings(t *testing.T) {
	var x execArgs
	if err := decode([]byte(`{"host":"h","command":"ls","max_bytes":"300","head":" 5 ","allow_disruptive":"true"}`), &x); err != nil {
		t.Fatal(err)
	}
	if x.MaxBytes != 300 || x.Head != 5 || !x.AllowDisruptiv || x.Command != "ls" {
		t.Errorf("got %+v", x)
	}
	if err := decode([]byte(`{"host":"h","command":"ls","max_bytes":"lots"}`), &x); err == nil {
		t.Error("non-numeric string accepted")
	}
	if err := decode([]byte(`{"host":"h","bogus":1}`), &x); err == nil {
		t.Error("unknown field accepted")
	}
}
