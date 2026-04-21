package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type runtimeConfig struct {
	Version    int                        `json:"version"`
	Containers map[string]containerConfig `json:"containers"`
}

type containerConfig struct {
	Enabled        bool     `json:"enabled"`
	Compatibility  string   `json:"compatibility"`
	IncludeWorkdir bool     `json:"include_workdir"`
	Workdir        string   `json:"workdir,omitempty"`
	ReadOnlyPaths  []string `json:"read_only_paths"`
	ReadWritePaths []string `json:"read_write_paths"`
}

func loadContainerConfig(path, containerName string) (containerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return containerConfig{}, err
	}

	var config runtimeConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return containerConfig{}, err
	}
	if config.Version != 1 {
		return containerConfig{}, fmt.Errorf("unsupported runtime config version %d", config.Version)
	}
	if containerName == "" {
		return containerConfig{}, fmt.Errorf("container name is required")
	}

	container, ok := config.Containers[containerName]
	if !ok {
		return containerConfig{}, fmt.Errorf("container %q is not in filesystem policy", containerName)
	}
	if !container.Enabled {
		return containerConfig{}, fmt.Errorf("container %q filesystem policy is disabled", containerName)
	}
	if container.Compatibility == "" {
		container.Compatibility = "hard_requirement"
	}
	if container.Compatibility != "hard_requirement" && container.Compatibility != "best_effort" {
		return containerConfig{}, fmt.Errorf("container %q has invalid compatibility %q", containerName, container.Compatibility)
	}

	if container.IncludeWorkdir {
		workdir := container.Workdir
		if workdir == "" {
			workdir, err = os.Getwd()
			if err != nil {
				return containerConfig{}, err
			}
		}
		if !containsPath(container.ReadWritePaths, workdir) {
			container.ReadWritePaths = append(container.ReadWritePaths, workdir)
		}
	}

	for _, path := range append(append([]string{}, container.ReadOnlyPaths...), container.ReadWritePaths...) {
		if err := validatePolicyPath(path); err != nil {
			return containerConfig{}, err
		}
	}
	for _, path := range container.ReadWritePaths {
		if cleanPolicyPath(path) == "/" {
			return containerConfig{}, fmt.Errorf("read_write_paths must not include /")
		}
	}
	if len(container.ReadOnlyPaths)+len(container.ReadWritePaths) == 0 {
		return containerConfig{}, fmt.Errorf("filesystem policy has no paths")
	}

	return container, nil
}

func validatePolicyPath(path string) error {
	if path == "" {
		return fmt.Errorf("policy path is empty")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("policy path %q must be absolute", path)
	}
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if part == ".." {
			return fmt.Errorf("policy path %q must not contain ..", path)
		}
	}
	return nil
}

func cleanPolicyPath(path string) string {
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func containsPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}
