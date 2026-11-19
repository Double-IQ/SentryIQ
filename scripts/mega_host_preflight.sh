#!/usr/bin/env bash
# Read-only capability check for a possible MEGAcmd backup runner.
# This script does not log in, contact MEGA, read SentryIQ data, or change host state.
set -u

report() {
    printf '%s=%s\n' "$1" "$2"
}

has_command() {
    command -v "$1" >/dev/null 2>&1
}

report "CHECK_MODE" "read-only"
report "OS" "$(uname -s 2>/dev/null || printf unknown)"
report "ARCH" "$(uname -m 2>/dev/null || printf unknown)"
report "HOME_SET" "$([ -n "${HOME:-}" ] && printf yes || printf no)"
report "HOME_WRITABLE" "$([ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ -w "$HOME" ] && printf yes || printf no)"

for command_name in php mega-put mega-backup mega-whoami mega-df mega-cmd-server pgrep crontab tar; do
    if has_command "$command_name"; then
        report "COMMAND_$command_name" "present"
    else
        report "COMMAND_$command_name" "missing"
    fi
done

if has_command php; then
    php -r '
        printf("PHP_VERSION=%s\n", PHP_VERSION);
        foreach (["sodium", "zip", "curl"] as $extension) {
            printf("PHP_EXTENSION_%s=%s\n", strtoupper($extension), extension_loaded($extension) ? "present" : "missing");
        }
        foreach (["proc_open", "exec", "shell_exec"] as $function) {
            printf("PHP_FUNCTION_%s=%s\n", strtoupper($function), function_exists($function) ? "available" : "unavailable");
        }
    ' 2>/dev/null || report "PHP_PROBE" "failed"
else
    report "PHP_PROBE" "skipped-no-php-cli"
fi

if has_command pgrep; then
    if pgrep -x mega-cmd-server >/dev/null 2>&1; then
        report "MEGACMD_SERVER_PROCESS" "running"
    else
        report "MEGACMD_SERVER_PROCESS" "not-running"
    fi
else
    report "MEGACMD_SERVER_PROCESS" "unknown-pgrep-missing"
fi

if [ -n "${HOME:-}" ] && [ -d "$HOME" ] && has_command df; then
    df -Pk "$HOME" 2>/dev/null | awk 'NR == 2 { printf "HOME_DISK_AVAILABLE_KB=%s\n", $4 }'
else
    report "HOME_DISK_AVAILABLE_KB" "unknown"
fi

report "NOTE" "No credentials, account identity, remote quota, application files, or secrets were accessed."
