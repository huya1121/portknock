package main

import (
	"fmt"
	"os"
	"os/exec"
)

// ctlPath is the fixed, hardcoded path to the installed management script. It is
// NEVER taken from a request or config — a caller can only trigger "run the
// upgrade", never choose what runs — so there is no path-injection surface.
const ctlPath = "/usr/local/bin/portknock-ctl"

// upgradeLog is where the detached upgrade's output goes (the service's own
// stdout/stderr would vanish when systemd restarts it mid-upgrade).
const upgradeLogPath = "/var/lib/portknock/upgrade.log"

// runSelfUpgrade launches `portknock-ctl update` and returns immediately.
//
// It must run OUTSIDE this service's systemd sandbox: the unit sets
// ProtectSystem=full, which makes /usr (hence /usr/local/bin/portknock) read-only
// for the service and every child it forks — so a plain exec of the updater
// could not replace the binary. When systemd-run is available we launch the
// updater as a transient unit in the system context (fresh namespace, no
// inherited sandbox); otherwise (non-systemd / manual deploy) we fall back to a
// detached exec, which is correct there since no sandbox applies.
//
// The command is always a fixed binary path plus fixed, literal arguments passed
// as a slice — never a shell string — so there is no command/argument injection
// surface regardless of which path is taken.
func runSelfUpgrade() error {
	fi, err := os.Stat(ctlPath)
	if err != nil {
		return fmt.Errorf("未找到管理命令 %s（可能是手动部署、未安装 portknock-ctl）", ctlPath)
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return fmt.Errorf("%s 不可执行", ctlPath)
	}

	// Preferred: escape the service sandbox via a transient systemd unit.
	if sr, lerr := exec.LookPath("systemd-run"); lerr == nil {
		cmd := exec.Command(sr,
			"--collect",                    // auto-clean the transient unit when done
			"--unit=portknock-upgrade",     // fixed unit name
			"--description=portknock self-upgrade",
			ctlPath, "update", // fixed path + literal arg
		)
		cmd.Env = append(os.Environ(), "PORTKNOCK_UPGRADE_DETACHED=1")
		out, rerr := cmd.CombinedOutput()
		if rerr != nil {
			return fmt.Errorf("启动升级失败（systemd-run）：%w: %s", rerr, string(out))
		}
		return nil
	}

	// Fallback: no systemd (manual deploy) — detached exec, no sandbox to escape.
	logf, err := os.OpenFile(upgradeLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		logf = nil
	}
	cmd := exec.Command(ctlPath, "update") // fixed path + literal arg, no shell
	cmd.Env = append(os.Environ(), "PORTKNOCK_UPGRADE_DETACHED=1")
	if logf != nil {
		cmd.Stdout = logf
		cmd.Stderr = logf
	}
	detachProcess(cmd) // new session so it survives the service restart
	if err := cmd.Start(); err != nil {
		if logf != nil {
			logf.Close()
		}
		return fmt.Errorf("启动升级失败：%w", err)
	}
	if logf != nil {
		logf.Close()
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
