package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

type indexFile struct {
	Version int           `yaml:"version"`
	Configs []policyEntry `yaml:"configs"`
}

type policyEntry struct {
	Name string `yaml:"name"`
	File string `yaml:"file"`
}

type runtimePolicy struct {
	Version       int               `yaml:"version"`
	Name          string            `yaml:"name"`
	Output        string            `yaml:"output"`
	RuntimeConfig runtimeConfigSpec `yaml:"runtime_config"`
	Target        target            `yaml:"target"`
	Pod           podPolicy         `yaml:"pod"`
}

type runtimeConfigSpec struct {
	Output        string `yaml:"output"`
	ConfigMapName string `yaml:"config_map_name"`
	MountPath     string `yaml:"mount_path"`
}

type target struct {
	APIVersion string `yaml:"api_version"`
	Kind       string `yaml:"kind"`
	Name       string `yaml:"name"`
	Namespace  string `yaml:"namespace"`
}

type podPolicy struct {
	Containers []containerPolicy `yaml:"containers"`
}

type containerPolicy struct {
	Name     string          `yaml:"name"`
	Landlock *landlockPolicy `yaml:"landlock,omitempty"`
}

type landlockPolicy struct {
	Enabled        bool     `yaml:"enabled"`
	InjectMode     string   `yaml:"inject_mode,omitempty"`
	Compatibility  string   `yaml:"compatibility,omitempty"`
	IncludeWorkdir bool     `yaml:"include_workdir,omitempty"`
	Workdir        string   `yaml:"workdir,omitempty"`
	Entrypoint     []string `yaml:"entrypoint,omitempty"`
	ReadOnlyPaths  []string `yaml:"read_only_paths,omitempty"`
	ReadWritePaths []string `yaml:"read_write_paths,omitempty"`
}

type deploymentPatch struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   metadata   `yaml:"metadata"`
	Spec       deploySpec `yaml:"spec"`
}

type metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace,omitempty"`
}

type deploySpec struct {
	Template podTemplate `yaml:"template"`
}

type podTemplate struct {
	Spec podSpec `yaml:"spec"`
}

type podSpec struct {
	Containers []containerPatch `yaml:"containers,omitempty"`
}

type containerPatch struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command,omitempty"`
	Args    []string `yaml:"args,omitempty"`
	Env     []envVar `yaml:"env,omitempty"`
}

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type configMapResource struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   metadata          `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
}

type genRuntimeConfig struct {
	Version    int                               `json:"version"`
	Containers map[string]genContainerConfig `json:"containers"`
}

type genContainerConfig struct {
	Enabled        bool     `json:"enabled"`
	Compatibility  string   `json:"compatibility"`
	IncludeWorkdir bool     `json:"include_workdir"`
	Workdir        string   `json:"workdir,omitempty"`
	ReadOnlyPaths  []string `json:"read_only_paths"`
	ReadWritePaths []string `json:"read_write_paths"`
}


func runGenerate(args []string) error {
	if len(args) == 0 {
		return errors.New("expected subcommand: generate or check")
	}

	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("generate", flag.ContinueOnError)
		root := fs.String("root", ".", "repository root")
		index := fs.String("index", "configs/filesystem-policy.yaml", "policy index path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return generate(*root, *index)
	case "check":
		fs := flag.NewFlagSet("check", flag.ContinueOnError)
		root := fs.String("root", ".", "repository root")
		index := fs.String("index", "configs/filesystem-policy.yaml", "policy index path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return check(*root, *index)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func generate(root, indexPath string) error {
	policies, err := loadPolicies(root, indexPath)
	if err != nil {
		return err
	}

	for _, policy := range policies {
		out, err := renderPolicy(policy)
		if err != nil {
			return fmt.Errorf("%s: %w", policy.Name, err)
		}
		outputPath := filepath.Join(root, policy.Output)
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(outputPath, out, 0o644); err != nil {
			return err
		}
		fmt.Printf("generated %s\n", policy.Output)

		if policy.RuntimeConfig.Output != "" {
			out, err := renderRuntimeConfigMap(policy)
			if err != nil {
				return fmt.Errorf("%s runtime config: %w", policy.Name, err)
			}
			outputPath := filepath.Join(root, policy.RuntimeConfig.Output)
			if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(outputPath, out, 0o644); err != nil {
				return err
			}
			fmt.Printf("generated %s\n", policy.RuntimeConfig.Output)
		}
	}

	return nil
}

func check(root, indexPath string) error {
	policies, err := loadPolicies(root, indexPath)
	if err != nil {
		return err
	}

	var stale []string
	for _, policy := range policies {
		want, err := renderPolicy(policy)
		if err != nil {
			return fmt.Errorf("%s: %w", policy.Name, err)
		}
		outputPath := filepath.Join(root, policy.Output)
		got, err := os.ReadFile(outputPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			stale = append(stale, policy.Output)
		}

		if policy.RuntimeConfig.Output != "" {
			want, err := renderRuntimeConfigMap(policy)
			if err != nil {
				return fmt.Errorf("%s runtime config: %w", policy.Name, err)
			}
			outputPath := filepath.Join(root, policy.RuntimeConfig.Output)
			got, err := os.ReadFile(outputPath)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				stale = append(stale, policy.RuntimeConfig.Output)
			}
		}
	}

	if len(stale) > 0 {
		return fmt.Errorf("generated filesystem policy patches are stale: %s; run make filesystem-policy-generate", strings.Join(stale, ", "))
	}

	fmt.Println("filesystem policy patches are up to date")
	return nil
}

func loadPolicies(root, indexPath string) ([]runtimePolicy, error) {
	var idx indexFile
	if err := readYAML(filepath.Join(root, indexPath), &idx); err != nil {
		return nil, err
	}
	if idx.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d", indexPath, idx.Version)
	}
	if len(idx.Configs) == 0 {
		return nil, fmt.Errorf("%s: configs must not be empty", indexPath)
	}

	names := map[string]bool{}
	policies := make([]runtimePolicy, 0, len(idx.Configs))
	for _, entry := range idx.Configs {
		if entry.Name == "" || entry.File == "" {
			return nil, fmt.Errorf("%s: each config needs name and file", indexPath)
		}
		if names[entry.Name] {
			return nil, fmt.Errorf("%s: duplicate config name %q", indexPath, entry.Name)
		}
		names[entry.Name] = true

		var policy runtimePolicy
		if err := readYAML(filepath.Join(root, entry.File), &policy); err != nil {
			return nil, err
		}
		if policy.Name != entry.Name {
			return nil, fmt.Errorf("%s: policy name %q does not match index name %q", entry.File, policy.Name, entry.Name)
		}
		if err := validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.File, err)
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func readYAML(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.UnmarshalStrict(data, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func validatePolicy(policy runtimePolicy) error {
	if policy.Version != 1 {
		return fmt.Errorf("unsupported version %d", policy.Version)
	}
	if policy.Name == "" || policy.Output == "" {
		return errors.New("name and output are required")
	}
	if policy.Target.APIVersion == "" || policy.Target.Kind == "" || policy.Target.Name == "" {
		return errors.New("target api_version, kind, and name are required")
	}
	if policy.Target.Kind != "Deployment" {
		return fmt.Errorf("unsupported target kind %q", policy.Target.Kind)
	}
	if policy.RuntimeConfig.Output != "" {
		if policy.RuntimeConfig.ConfigMapName == "" || policy.RuntimeConfig.MountPath == "" {
			return errors.New("runtime_config output requires config_map_name and mount_path")
		}
		if !strings.HasPrefix(policy.RuntimeConfig.MountPath, "/") {
			return fmt.Errorf("runtime_config mount_path %q must be absolute", policy.RuntimeConfig.MountPath)
		}
	}

	if err := validateContainers("containers", policy.Pod.Containers); err != nil {
		return err
	}
	if len(policy.Pod.Containers) == 0 {
		return errors.New("at least one container policy is required")
	}
	if policy.RuntimeConfig.Output == "" || policy.RuntimeConfig.ConfigMapName == "" || policy.RuntimeConfig.MountPath == "" {
		return errors.New("landlock containers require runtime_config output, config_map_name, and mount_path")
	}

	return nil
}

func validateContainers(field string, containers []containerPolicy) error {
	names := map[string]bool{}
	for _, container := range containers {
		if container.Name == "" {
			return fmt.Errorf("%s: container name is required", field)
		}
		if names[container.Name] {
			return fmt.Errorf("%s: duplicate container %q", field, container.Name)
		}
		names[container.Name] = true

		if container.Landlock == nil || !container.Landlock.Enabled {
			return fmt.Errorf("%s: container %q requires enabled landlock policy", field, container.Name)
		}
		if err := validateLandlock(container.Name, container.Landlock); err != nil {
			return err
		}
	}
	return nil
}

func validateLandlock(containerName string, policy *landlockPolicy) error {
	if !policy.Enabled {
		return nil
	}
	switch policy.InjectMode {
	case "", "entrypoint", "manual":
	default:
		return fmt.Errorf("container %q landlock inject_mode must be entrypoint or manual", containerName)
	}
	if policy.InjectMode != "manual" {
		if len(policy.Entrypoint) == 0 {
			return fmt.Errorf("container %q enabled landlock policy requires entrypoint", containerName)
		}
		for i, arg := range policy.Entrypoint {
			if arg == "" {
				return fmt.Errorf("container %q landlock entrypoint[%d] is empty", containerName, i)
			}
		}
	}
	switch policy.Compatibility {
	case "", "hard_requirement", "best_effort":
	default:
		return fmt.Errorf("container %q landlock compatibility must be hard_requirement or best_effort", containerName)
	}
	paths := map[string]string{}
	for _, path := range policy.ReadOnlyPaths {
		if err := validateLandlockPath(containerName, "read_only_paths", path); err != nil {
			return err
		}
		if previous, ok := paths[path]; ok {
			return fmt.Errorf("container %q landlock path %q appears in both %s and read_only_paths", containerName, path, previous)
		}
		paths[path] = "read_only_paths"
	}
	for _, path := range policy.ReadWritePaths {
		if err := validateLandlockPath(containerName, "read_write_paths", path); err != nil {
			return err
		}
		if cleanLandlockPath(path) == "/" {
			return fmt.Errorf("container %q landlock read_write_paths must not include /", containerName)
		}
		if previous, ok := paths[path]; ok {
			return fmt.Errorf("container %q landlock path %q appears in both %s and read_write_paths", containerName, path, previous)
		}
		paths[path] = "read_write_paths"
	}
	if len(policy.ReadOnlyPaths)+len(policy.ReadWritePaths) == 0 && !policy.IncludeWorkdir {
		return fmt.Errorf("container %q enabled landlock policy has no paths", containerName)
	}
	if policy.Workdir != "" {
		if err := validateLandlockPath(containerName, "workdir", policy.Workdir); err != nil {
			return err
		}
	}
	return nil
}

func validateLandlockPath(containerName, field, path string) error {
	if path == "" {
		return fmt.Errorf("container %q landlock %s contains an empty path", containerName, field)
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("container %q landlock %s path %q must be absolute", containerName, field, path)
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == ".." {
			return fmt.Errorf("container %q landlock %s path %q must not contain ..", containerName, field, path)
		}
	}
	if len(path) > 4096 {
		return fmt.Errorf("container %q landlock %s path %q is too long", containerName, field, path)
	}
	return nil
}

func cleanLandlockPath(path string) string {
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func renderPolicy(policy runtimePolicy) ([]byte, error) {
	patch := deploymentPatch{
		APIVersion: policy.Target.APIVersion,
		Kind:       policy.Target.Kind,
		Metadata: metadata{
			Name:      policy.Target.Name,
			Namespace: policy.Target.Namespace,
		},
		Spec: deploySpec{
			Template: podTemplate{
				Spec: podSpec{
					Containers: renderContainers(policy.Pod.Containers, policy.RuntimeConfig),
				},
			},
		},
	}

	out, err := yaml.Marshal(patch)
	if err != nil {
		return nil, err
	}
	return append([]byte("# Generated by landlock-helper generate; do not edit by hand.\n"), out...), nil
}

func renderContainers(containers []containerPolicy, runtimeConfig runtimeConfigSpec) []containerPatch {
	if len(containers) == 0 {
		return nil
	}
	out := make([]containerPatch, 0, len(containers))
	for _, container := range containers {
		out = append(out, containerPatch{
			Name:    container.Name,
			Command: renderCommand(container),
			Args:    renderArgs(container),
			Env:     renderRuntimeConfigEnv(container, runtimeConfig),
		})
	}
	return out
}

func renderCommand(container containerPolicy) []string {
	if container.Landlock == nil || !container.Landlock.Enabled {
		return nil
	}
	if container.Landlock.InjectMode == "manual" {
		return nil
	}
	return []string{"/usr/local/bin/landlock-helper", "exec"}
}

func renderArgs(container containerPolicy) []string {
	if container.Landlock == nil || !container.Landlock.Enabled {
		return nil
	}
	if container.Landlock.InjectMode == "manual" {
		return nil
	}
	return append([]string{"--"}, container.Landlock.Entrypoint...)
}

func renderRuntimeConfigEnv(container containerPolicy, runtimeConfig runtimeConfigSpec) []envVar {
	if container.Landlock == nil || !container.Landlock.Enabled {
		return nil
	}
	configPath := filepath.Join(runtimeConfig.MountPath, "runtime.json")
	return []envVar{
		{Name: "LANDLOCK_HELPER_CONTAINER", Value: container.Name},
		{Name: "LANDLOCK_HELPER_CONFIG", Value: configPath},
	}
}

func renderRuntimeConfigMap(policy runtimePolicy) ([]byte, error) {
	config := genRuntimeConfig{
		Version:    1,
		Containers: map[string]genContainerConfig{},
	}
	for _, container := range policy.Pod.Containers {
		if container.Landlock == nil || !container.Landlock.Enabled {
			continue
		}
		compatibility := container.Landlock.Compatibility
		if compatibility == "" {
			compatibility = "hard_requirement"
		}
		config.Containers[container.Name] = genContainerConfig{
			Enabled:        true,
			Compatibility:  compatibility,
			IncludeWorkdir: container.Landlock.IncludeWorkdir,
			Workdir:        container.Landlock.Workdir,
			ReadOnlyPaths:  sortedCopy(container.Landlock.ReadOnlyPaths),
			ReadWritePaths: sortedCopy(container.Landlock.ReadWritePaths),
		}
	}

	runtimeJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}

	resource := configMapResource{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: metadata{
			Name:      policy.RuntimeConfig.ConfigMapName,
			Namespace: policy.Target.Namespace,
		},
		Data: map[string]string{
			"runtime.json": string(runtimeJSON) + "\n",
		},
	}
	out, err := yaml.Marshal(resource)
	if err != nil {
		return nil, err
	}
	return append([]byte("# Generated by landlock-helper generate; do not edit by hand.\n"), out...), nil
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
