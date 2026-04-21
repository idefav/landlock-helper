package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
)


func runExec(args []string) error {
	fs := flag.NewFlagSet("landlock-helper exec", flag.ContinueOnError)
	configPath := fs.String("config", getenvDefault("LANDLOCK_HELPER_CONFIG", "/etc/landlock-helper/runtime.json"), "runtime filesystem policy JSON")
	containerName := fs.String("container", os.Getenv("LANDLOCK_HELPER_CONTAINER"), "container policy name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("expected command after --")
	}

	config, err := loadContainerConfig(*configPath, *containerName)
	if err != nil {
		return err
	}
	if err := applyFilesystemPolicy(config); err != nil {
		if config.Compatibility == "best_effort" {
			fmt.Fprintf(os.Stderr, "landlock-helper exec: running without Landlock enforcement: %v\n", err)
		} else {
			return err
		}
	}

	return syscall.Exec(command[0], command, os.Environ())
}

func getenvDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
