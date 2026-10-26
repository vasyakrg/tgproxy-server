package main

import (
	"bytes"
	"testing"
)

func TestUpdateApplyRegistered(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	// Не root (тесты) либо отсутствует пользователь tgproxy/каталоги — команда обязана отказать.
	root.SetArgs([]string{"update", "apply", "--data-dir", t.TempDir(), "--work-dir", t.TempDir(), "--component", "agent"})
	if err := root.Execute(); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestReleaseVerifierRejectsGarbage(t *testing.T) {
	v, err := newReleaseVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if v.Verify([]byte("x"), []byte("y")) == nil {
		t.Fatal("мусорная подпись принята")
	}
	if v.CheckVersion("not-a-version") == nil {
		t.Fatal("невалидная версия принята")
	}
	if v.CheckFile([]byte("x"), "f", bytes.NewReader(nil)) == nil {
		t.Fatal("пустые checksums приняты")
	}
}
