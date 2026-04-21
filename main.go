package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "landlock-helper: expected subcommand (generate, check, exec)\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate", "check":
		if err := runGenerate(os.Args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "landlock-helper %s: %v\n", os.Args[1], err)
			os.Exit(1)
		}
	case "exec":
		if err := runExec(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "landlock-helper exec: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "landlock-helper: unknown subcommand %q\n", os.Args[1])
		os.Exit(1)
	}
}
