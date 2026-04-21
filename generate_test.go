package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderPolicyWrapsLandlockContainer(t *testing.T) {
	policy := runtimePolicy{
		Version: 1,
		Name:    "test",
		Output:  "generated.yaml",
		RuntimeConfig: runtimeConfigSpec{
			Output:        "generated/configmap.yaml",
			ConfigMapName: "filesystem-policy",
			MountPath:     "/etc/cloud-claw/filesystem-policy",
		},
		Target: target{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "example",
			Namespace:  "default",
		},
		Pod: podPolicy{
			Containers: []containerPolicy{
				{
					Name: "app",
					Landlock: &landlockPolicy{
						Enabled:        true,
						Compatibility:  "hard_requirement",
						IncludeWorkdir: false,
						Entrypoint:     []string{"/bin/app", "--serve"},
						ReadOnlyPaths:  []string{"/"},
						ReadWritePaths: []string{"/tmp"},
					},
				},
			},
		},
	}

	if err := validatePolicy(policy); err != nil {
		t.Fatalf("validatePolicy() error = %v", err)
	}
	out, err := renderPolicy(policy)
	if err != nil {
		t.Fatalf("renderPolicy() error = %v", err)
	}

	text := string(out)
	for _, want := range []string{
		"command:",
		"- /usr/local/bin/landlock-helper",
		"args:",
		"- --",
		"- /bin/app",
		"- --serve",
		"name: LANDLOCK_HELPER_CONTAINER",
		"value: app",
		"name: LANDLOCK_HELPER_CONFIG",
		"value: /etc/cloud-claw/filesystem-policy/runtime.json",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered patch missing %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"securityContext:", "volumeMounts:", "volumes:"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("rendered patch unexpectedly contains %q:\n%s", unwanted, text)
		}
	}
}

func TestValidatePolicyRejectsContainerWithoutLandlock(t *testing.T) {
	policy := runtimePolicy{
		Version: 1,
		Name:    "test",
		Output:  "generated.yaml",
		RuntimeConfig: runtimeConfigSpec{
			Output:        "generated/configmap.yaml",
			ConfigMapName: "filesystem-policy",
			MountPath:     "/etc/cloud-claw/filesystem-policy",
		},
		Target: target{APIVersion: "apps/v1", Kind: "Deployment", Name: "example"},
		Pod: podPolicy{
			Containers: []containerPolicy{{Name: "app"}},
		},
	}

	err := validatePolicy(policy)
	if err == nil || !strings.Contains(err.Error(), "requires enabled landlock policy") {
		t.Fatalf("validatePolicy() error = %v, want enabled landlock error", err)
	}
}

func TestValidatePolicyRejectsLandlockWithoutEntrypoint(t *testing.T) {
	policy := runtimePolicy{
		Version: 1,
		Name:    "test",
		Output:  "generated.yaml",
		RuntimeConfig: runtimeConfigSpec{
			Output:        "generated/configmap.yaml",
			ConfigMapName: "filesystem-policy",
			MountPath:     "/etc/cloud-claw/filesystem-policy",
		},
		Target: target{APIVersion: "apps/v1", Kind: "Deployment", Name: "example"},
		Pod: podPolicy{
			Containers: []containerPolicy{
				{
					Name: "app",
					Landlock: &landlockPolicy{
						Enabled:        true,
						ReadOnlyPaths:  []string{"/"},
						ReadWritePaths: []string{"/tmp"},
					},
				},
			},
		},
	}

	err := validatePolicy(policy)
	if err == nil || !strings.Contains(err.Error(), "requires entrypoint") {
		t.Fatalf("validatePolicy() error = %v, want entrypoint error", err)
	}
}

func TestValidatePolicyAllowsManualLandlockWithoutEntrypoint(t *testing.T) {
	policy := runtimePolicy{
		Version: 1,
		Name:    "test",
		Output:  "generated.yaml",
		RuntimeConfig: runtimeConfigSpec{
			Output:        "generated/configmap.yaml",
			ConfigMapName: "filesystem-policy",
			MountPath:     "/etc/cloud-claw/filesystem-policy",
		},
		Target: target{APIVersion: "apps/v1", Kind: "Deployment", Name: "example"},
		Pod: podPolicy{
			Containers: []containerPolicy{
				{
					Name: "app",
					Landlock: &landlockPolicy{
						Enabled:        true,
						InjectMode:     "manual",
						ReadOnlyPaths:  []string{"/"},
						ReadWritePaths: []string{"/tmp"},
					},
				},
			},
		},
	}

	if err := validatePolicy(policy); err != nil {
		t.Fatalf("validatePolicy() error = %v", err)
	}
}

func TestRenderPolicyKeepsManualLandlockContainerEntrypoint(t *testing.T) {
	policy := runtimePolicy{
		Version: 1,
		Name:    "test",
		Output:  "generated.yaml",
		RuntimeConfig: runtimeConfigSpec{
			Output:        "generated/configmap.yaml",
			ConfigMapName: "filesystem-policy",
			MountPath:     "/etc/cloud-claw/filesystem-policy",
		},
		Target: target{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "example",
			Namespace:  "default",
		},
		Pod: podPolicy{
			Containers: []containerPolicy{
				{
					Name: "app",
					Landlock: &landlockPolicy{
						Enabled:        true,
						InjectMode:     "manual",
						Compatibility:  "hard_requirement",
						ReadOnlyPaths:  []string{"/"},
						ReadWritePaths: []string{"/tmp"},
					},
				},
			},
		},
	}

	if err := validatePolicy(policy); err != nil {
		t.Fatalf("validatePolicy() error = %v", err)
	}
	out, err := renderPolicy(policy)
	if err != nil {
		t.Fatalf("renderPolicy() error = %v", err)
	}

	text := string(out)
	for _, want := range []string{
		"name: LANDLOCK_HELPER_CONTAINER",
		"value: app",
		"name: LANDLOCK_HELPER_CONFIG",
		"value: /etc/cloud-claw/filesystem-policy/runtime.json",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered patch missing %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"command:", "args:"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("rendered patch unexpectedly contains %q:\n%s", unwanted, text)
		}
	}
}

func TestCheckDetectsStaleGeneratedPatch(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "configs/filesystem-policy.yaml"), `version: 1
configs:
  - name: test
    file: configs/filesystem-policy/test.yaml
`)
	mustWrite(t, filepath.Join(root, "configs/filesystem-policy/test.yaml"), `version: 1
name: test
output: generated/test.yaml
runtime_config:
  output: generated/configmap.yaml
  config_map_name: filesystem-policy
  mount_path: /etc/cloud-claw/filesystem-policy
target:
  api_version: apps/v1
  kind: Deployment
  name: example
pod:
  containers:
    - name: app
      landlock:
        enabled: true
        entrypoint:
          - /bin/app
        read_only_paths:
          - /
`)
	mustWrite(t, filepath.Join(root, "generated/test.yaml"), "stale\n")
	mustWrite(t, filepath.Join(root, "generated/configmap.yaml"), "stale\n")

	err := check(root, "configs/filesystem-policy.yaml")
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("check() error = %v, want stale", err)
	}
}

func TestLoadPoliciesRejectsSecurityContextFields(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "configs/filesystem-policy.yaml"), `version: 1
configs:
  - name: test
    file: configs/filesystem-policy/test.yaml
`)
	mustWrite(t, filepath.Join(root, "configs/filesystem-policy/test.yaml"), `version: 1
name: test
output: generated/test.yaml
runtime_config:
  output: generated/configmap.yaml
  config_map_name: filesystem-policy
  mount_path: /etc/cloud-claw/filesystem-policy
target:
  api_version: apps/v1
  kind: Deployment
  name: example
pod:
  containers:
    - name: app
      run_as_user: 1000
      landlock:
        enabled: true
        entrypoint:
          - /bin/app
        read_only_paths:
          - /
`)

	_, err := loadPolicies(root, "configs/filesystem-policy.yaml")
	if err == nil || !strings.Contains(err.Error(), "field run_as_user not found") {
		t.Fatalf("loadPolicies() error = %v, want strict YAML field error", err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
