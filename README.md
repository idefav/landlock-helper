# landlock-helper

A CLI tool for generating Kubernetes patches and executing binaries with Landlock filesystem sandboxing.

## Installation

```bash
go install github.com/idefav/landlock-helper@latest
```

## Usage

### Generate Policy
```bash
landlock-helper generate -root . -index configs/filesystem-policy.yaml
```

### Exec Sandbox
```bash
landlock-helper exec -config /etc/landlock-helper/runtime.json -container my-container -- my-command
```
