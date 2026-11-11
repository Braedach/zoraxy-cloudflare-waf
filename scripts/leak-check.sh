#!/usr/bin/env bash
# leak-check.sh - stops private data reaching this PUBLIC repository.
#
#   scripts/leak-check.sh                  scan every tracked file, and the commits not yet on origin/main
#   scripts/leak-check.sh --range A..B     scan the tracked files and the identities of commits A..B (CI uses the pull request's range)
#   scripts/leak-check.sh --files-only     skip the commit identities
#
# What it looks for (generic patterns only; nothing owner-specific is stored in the repository):
#   - free-mail addresses (a real person's address), in files AND as a commit author or committer;
#   - private and internal network addresses (10/8, 172.16/12, 192.168/16) and global IPv6 addresses;
#   - secret-shaped strings: GitHub, Cloudflare and AWS tokens, bearer tokens, private-key blocks;
#   - 32-character hex strings that look like Cloudflare account or zone IDs (a string of one repeated character is a placeholder);
#   - your own names, if you list them: one extended regex per line in ~/.config/leakcheck/names, or in $LEAKCHECK_EXTRA
#     (for example your internal host names and domains). Those stay on your machine, never in git.
# Allowed exceptions go in .leakcheck-allow (one extended regex per line, matched against "path:line:text").
#
# The output NEVER prints the matched value, only file:line and the name of the rule, so a log can be shared safely.
# Exit status: 0 clean, 1 findings, 2 usage error.
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not in a git repository" >&2; exit 2; }

RANGE=""; FILES=1; IDENT=1
while [ $# -gt 0 ]; do
    case "$1" in
        --range) RANGE="${2:-}"; shift 2 ;;
        --files-only) IDENT=0; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

FREEMAIL='[A-Za-z0-9._%+-]+@(gmail|googlemail|outlook|hotmail|live|msn|yahoo|ymail|icloud|me|aol|proton|protonmail|gmx|zoho)\.[A-Za-z.]{2,}'
PRIVATE_V4='(^|[^0-9.])(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)'
GLOBAL_V6='(^|[^0-9A-Fa-f:])2[0-9a-fA-F]{3}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:'
TOKENS='gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|cf(ut|at)_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|[Bb]earer [A-Za-z0-9._~+/-]{30,}'
HEX32='(^|[^0-9a-fA-F])[0-9a-f]{32}([^0-9a-fA-F]|$)'
ALLOWED_IDENTITY='(@users\.noreply\.github\.com|^noreply@anthropic\.com|^noreply@github\.com|@github\.com)$'

ALLOW_FILE=".leakcheck-allow"
EXTRA=""
[ -f "$HOME/.config/leakcheck/names" ] && EXTRA="$(grep -v '^\s*\(#\|$\)' "$HOME/.config/leakcheck/names" | paste -sd'|' -)"
[ -n "${LEAKCHECK_EXTRA:-}" ] && EXTRA="${EXTRA:+$EXTRA|}$LEAKCHECK_EXTRA"

found=0
report() { echo "  $1: [$2]"; found=$((found + 1)); }

allowed() {   # allowed "path:line:text"
    [ -f "$ALLOW_FILE" ] || return 1
    grep -v '^\s*\(#\|$\)' "$ALLOW_FILE" | while IFS= read -r re; do
        if printf '%s' "$1" | grep -Eq -- "$re"; then echo yes; break; fi
    done | grep -q yes
}

scan_text() {   # scan_text <label> <text on stdin>; reports file:line and rule only
    local label="$1" n=0 line
    while IFS= read -r line; do
        n=$((n + 1))
        local rule=""
        if   printf '%s' "$line" | grep -Eq -- "$FREEMAIL";    then rule="free-mail address"
        elif printf '%s' "$line" | grep -Eq -- "$PRIVATE_V4";  then rule="private network address"
        elif printf '%s' "$line" | grep -Eq -- "$GLOBAL_V6";   then rule="global IPv6 address"
        elif printf '%s' "$line" | grep -Eq -- "$TOKENS";      then rule="secret-shaped string"
        elif [ -n "$EXTRA" ] && printf '%s' "$line" | grep -Eiq -- "$EXTRA"; then rule="your own name list"
        elif printf '%s' "$line" | grep -Eo -- "$HEX32" | tr -d '[:space:]' | awk '{ s=$0; gsub(/[^0-9a-f]/,"",s); d=""; for(i=1;i<=length(s);i++){c=substr(s,i,1); if(index(d,c)==0) d=d c}; if(length(d)>3) f=1 } END{exit f?0:1}'; then rule="32-character hex id"
        fi
        [ -n "$rule" ] || continue
        allowed "$label:$n:$line" && continue
        report "$label:$n" "$rule"
    done
}

echo "== tracked files"
while IFS= read -r f; do
    case "$f" in
        *.docx|*.xlsx|*.pptx) command -v unzip >/dev/null && unzip -p "$f" 'word/*.xml' 2>/dev/null | sed 's/<[^>]*>/ /g' | scan_text "$f" ;;
        *.png|*.jpg|*.jpeg|*.gif|*.ico|*.zip|*.gz|*.pdf) ;;
        *) grep -Iq . "$f" 2>/dev/null && scan_text "$f" < "$f" ;;
    esac
done < <(git ls-files)

if [ "$IDENT" -eq 1 ]; then
    if [ -z "$RANGE" ]; then
        if git rev-parse -q --verify origin/main >/dev/null; then RANGE="origin/main..HEAD"; fi
    fi
    echo "== commit identities ${RANGE:+($RANGE)}"
    if [ -n "$RANGE" ]; then
        while IFS='|' read -r sha ae ce; do
            for e in "$ae" "$ce"; do
                printf '%s' "$e" | grep -Eq -- "$ALLOWED_IDENTITY" || report "commit ${sha:0:7}" "author or committer address is not a noreply address"
            done
        done < <(git log --format='%H|%ae|%ce' "$RANGE")
    else
        echo "  (no range to check)"
    fi
fi

if [ "$found" -gt 0 ]; then
    echo "FAILED: $found finding(s). Values are not shown. Remove the data (or add a justified exception to $ALLOW_FILE)."
    exit 1
fi
echo "clean"
