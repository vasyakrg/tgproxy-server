package main

import (
	"bytes"
	"strings"
	"testing"
)

func runRoot(t *testing.T, env map[string]string, args ...string) (string, error) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestAgentEnrollRequiresToken(t *testing.T) {
	t.Setenv(EnrollTokenEnv, "")
	_, err := runRoot(t, nil, "agent", "enroll", "--server", "https://h:8444", "--ca-fingerprint", "SHA256:x")
	if err == nil || !strings.Contains(err.Error(), EnrollTokenEnv) {
		t.Fatalf("err %v", err)
	}
}

func TestAgentEnrollRequiredFlags(t *testing.T) {
	if _, err := runRoot(t, nil, "agent", "enroll"); err == nil {
		t.Fatal("expected required flags error")
	}
}

func TestAgentEnrollTokenFromEnvReachesAgent(t *testing.T) {
	// Токен из окружения принят, дальше падаем на валидации отпечатка (без сети).
	_, err := runRoot(t, map[string]string{EnrollTokenEnv: "sekret"},
		"agent", "enroll", "--server", "https://h:8444", "--ca-fingerprint", "bad")
	if err == nil || !strings.Contains(err.Error(), "ca-fingerprint") || strings.Contains(err.Error(), "sekret") {
		t.Fatalf("err %v", err)
	}
}

func TestResolveEnrollToken(t *testing.T) {
	cases := []struct {
		name, flag, env string
		stdinFlag       bool
		in              string
		want            string
		wantErr         bool
	}{
		{"flag wins", "f", "e", false, "s\n", "f", false},
		{"env over stdin", "", "e", false, "s\n", "e", false},
		{"stdin default", "", "", false, " tok123 \nrest", "tok123", false},
		{"stdin explicit beats env", "", "e", true, "s", "s", false},
		{"stdin empty", "", "", false, "", "", true},
		{"stdin blank line", "", "", true, "\n", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveEnrollToken(c.flag, c.env, c.stdinFlag, strings.NewReader(c.in))
			if (err != nil) != c.wantErr || got != c.want {
				t.Fatalf("got %q err %v", got, err)
			}
		})
	}
}

func TestAgentEnrollTokenFromStdinReachesAgent(t *testing.T) {
	t.Setenv(EnrollTokenEnv, "")
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader("sekret\n"))
	root.SetArgs([]string{"agent", "enroll", "--server", "https://h:8444", "--ca-fingerprint", "bad"})
	err := root.Execute()
	if err == nil || strings.Contains(err.Error(), "токен не задан") || strings.Contains(err.Error()+out.String(), "sekret") {
		t.Fatalf("err %v out %q", err, out.String())
	}
}
