//go:build unix

package fakepython

import "syscall"

func killSelf() int {
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGKILL); err != nil {
		return 104
	}
	select {} // the signal ends the process
}
