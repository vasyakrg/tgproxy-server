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
