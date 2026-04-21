//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	landlockCreateRulesetVersion = 1 << 0
	landlockRulePathBeneath      = 1

	landlockAccessFSExecute    = 1 << 0
	landlockAccessFSWriteFile  = 1 << 1
	landlockAccessFSReadFile   = 1 << 2
	landlockAccessFSReadDir    = 1 << 3
	landlockAccessFSRemoveDir  = 1 << 4
	landlockAccessFSRemoveFile = 1 << 5
	landlockAccessFSMakeChar   = 1 << 6
	landlockAccessFSMakeDir    = 1 << 7
	landlockAccessFSMakeReg    = 1 << 8
	landlockAccessFSMakeSock   = 1 << 9
	landlockAccessFSMakeFifo   = 1 << 10
	landlockAccessFSMakeBlock  = 1 << 11
	landlockAccessFSMakeSym    = 1 << 12
	landlockAccessFSRefer      = 1 << 13
	landlockAccessFSTruncate   = 1 << 14
	landlockAccessFSIoctlDev   = 1 << 15
)

type landlockRulesetAttr struct {
	HandledAccessFS uint64
}

type landlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}

func applyFilesystemPolicy(config containerConfig) error {
	abi, err := landlockABI()
	if err != nil {
		return err
	}

	handledAccess := accessAll(abi)
	rulesetAttr := landlockRulesetAttr{HandledAccessFS: handledAccess}
	rulesetFD, err := landlockCreateRuleset(&rulesetAttr, unsafe.Sizeof(rulesetAttr), 0)
	if err != nil {
		return err
	}
	defer syscall.Close(rulesetFD)

	rulesApplied := 0
	for _, path := range config.ReadOnlyPaths {
		applied, err := addPathRule(rulesetFD, path, accessRead(abi), config.Compatibility)
		if err != nil {
			return err
		}
		if applied {
			rulesApplied++
		}
	}
	for _, path := range config.ReadWritePaths {
		applied, err := addPathRule(rulesetFD, path, handledAccess, config.Compatibility)
		if err != nil {
			return err
		}
		if applied {
			rulesApplied++
		}
	}
	if rulesApplied == 0 {
		return fmt.Errorf("Landlock ruleset has zero valid paths")
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := landlockRestrictSelf(rulesetFD); err != nil {
		return err
	}
	return nil
}

func landlockABI() (int, error) {
	abi, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 {
		switch errno {
		case syscall.ENOSYS:
			return 0, errors.New("Landlock is not implemented by this kernel")
		case syscall.EOPNOTSUPP:
			return 0, errors.New("Landlock is not enabled by this kernel")
		case syscall.EPERM:
			return 0, errors.New("Landlock syscall is blocked by seccomp or container policy")
		default:
			return 0, fmt.Errorf("probe Landlock ABI: %w", errno)
		}
	}
	return int(abi), nil
}

func landlockCreateRuleset(attr *landlockRulesetAttr, size uintptr, flags uintptr) (int, error) {
	fd, _, errno := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(attr)), size, flags)
	if errno != 0 {
		return -1, fmt.Errorf("create Landlock ruleset: %w", errno)
	}
	return int(fd), nil
}

func landlockAddRule(rulesetFD int, attr *landlockPathBeneathAttr) error {
	_, _, errno := syscall.Syscall6(
		sysLandlockAddRule,
		uintptr(rulesetFD),
		landlockRulePathBeneath,
		uintptr(unsafe.Pointer(attr)),
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("add Landlock rule: %w", errno)
	}
	return nil
}

func landlockRestrictSelf(rulesetFD int) error {
	_, _, errno := syscall.Syscall(sysLandlockRestrictSelf, uintptr(rulesetFD), 0, 0)
	if errno != 0 {
		return fmt.Errorf("restrict self with Landlock: %w", errno)
	}
	return nil
}

func addPathRule(rulesetFD int, path string, allowedAccess uint64, compatibility string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if compatibility == "best_effort" {
			fmt.Fprintf(os.Stderr, "cloud-claw-filesystem-policy-exec: skipping Landlock path %s: %v\n", path, err)
			return false, nil
		}
		return false, fmt.Errorf("open Landlock path %s: %w", path, err)
	}
	defer file.Close()

	attr := landlockPathBeneathAttr{
		AllowedAccess: allowedAccess,
		ParentFD:      int32(file.Fd()),
	}
	if err := landlockAddRule(rulesetFD, &attr); err != nil {
		return false, fmt.Errorf("path %s: %w", path, err)
	}
	return true, nil
}

func accessRead(abi int) uint64 {
	return accessAll(abi) &^ accessWrite(abi)
}

func accessWrite(abi int) uint64 {
	write := uint64(landlockAccessFSWriteFile |
		landlockAccessFSRemoveDir |
		landlockAccessFSRemoveFile |
		landlockAccessFSMakeChar |
		landlockAccessFSMakeDir |
		landlockAccessFSMakeReg |
		landlockAccessFSMakeSock |
		landlockAccessFSMakeFifo |
		landlockAccessFSMakeBlock |
		landlockAccessFSMakeSym)
	if abi >= 2 {
		write |= landlockAccessFSRefer
	}
	if abi >= 3 {
		write |= landlockAccessFSTruncate
	}
	if abi >= 5 {
		write |= landlockAccessFSIoctlDev
	}
	return write
}

func accessAll(abi int) uint64 {
	access := uint64(landlockAccessFSExecute |
		landlockAccessFSWriteFile |
		landlockAccessFSReadFile |
		landlockAccessFSReadDir |
		landlockAccessFSRemoveDir |
		landlockAccessFSRemoveFile |
		landlockAccessFSMakeChar |
		landlockAccessFSMakeDir |
		landlockAccessFSMakeReg |
		landlockAccessFSMakeSock |
		landlockAccessFSMakeFifo |
		landlockAccessFSMakeBlock |
		landlockAccessFSMakeSym)
	if abi >= 2 {
		access |= landlockAccessFSRefer
	}
	if abi >= 3 {
		access |= landlockAccessFSTruncate
	}
	if abi >= 5 {
		access |= landlockAccessFSIoctlDev
	}
	return access
}
