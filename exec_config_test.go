package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadContainerConfigAddsWorkdir(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(configPath, []byte(`{
  "version": 1,
  "containers": {
    "app": {
      "enabled": true,
      "compatibility": "hard_requirement",
      "include_workdir": true,
      "workdir": "/work",
      "read_only_paths": ["/"],
      "read_write_paths": ["/tmp"]
    }
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}

	config, err := loadContainerConfig(configPath, "app")
	if err != nil {
		t.Fatal(err)
	}
	if !containsPath(config.ReadWritePaths, "/work") {
		t.Fatalf("expected /work in read_write_paths: %#v", config.ReadWritePaths)
	}
}

func TestLoadContainerConfigRejectsRootReadWrite(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(configPath, []byte(`{
  "version": 1,
  "containers": {
    "app": {
      "enabled": true,
      "compatibility": "hard_requirement",
      "read_only_paths": [],
      "read_write_paths": ["/"]
    }
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadContainerConfig(configPath, "app"); err == nil {
		t.Fatal("expected read_write_paths / to be rejected")
	}
}
