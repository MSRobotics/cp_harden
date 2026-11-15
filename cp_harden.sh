#!/usr/bin/env bash
#==============================================================================
#  cp_harden.sh  v2.0  -  CyberPatriot Linux hardening, audit & forensics toolkit
#------------------------------------------------------------------------------
#  Targets the Ubuntu / Debian / Linux Mint images used in CyberPatriot
#  (other distros: partial support).  Run as root.
#
#  SAFE BY DEFAULT: with no flags it is a DRY RUN - it only reports what it
#  WOULD do.  Nothing changes until you pass --apply (or --auto), and risky
#  actions (deleting users, purging packages, PAM / firewall edits, ...) ask
#  first unless you pass --yes / --auto.
#
#  FASTEST PATH (one command, one confirmation):
#    sudo ./cp_harden.sh --auto
#       -> finds + parses the README, shows you the parsed users/admins/services
#          ONCE for a y/N check, then applies everything with no more prompts.
#          (forensics evidence is collected FIRST, before anything is changed)
#
#  CAREFUL PATH
#    sudo ./cp_harden.sh --init                        create ./config/ templates
#    sudo ./cp_harden.sh --readme auto --readme-only   parse README -> config/*.txt
#         (then OPEN config/*.txt and CORRECT them by hand - the parser is a
#          best-effort helper, YOU are the authority on what the README says)
#    sudo ./cp_harden.sh                               dry run / report
#    sudo ./cp_harden.sh --apply                       do it (asks on risky steps)
#    less /root/cp_harden_*/reports/review.txt         items a human must judge
#
#  Everything is logged, backed up and undoable:
#    /root/cp_harden_<time>/{run.log, undo.sh, backups/, quarantine/, reports/}
#    backups/etc_full.tgz = complete copy of /etc taken before the first change
#
#  Rules reminder: use only on your own competition/practice images, follow
#  your season's CyberPatriot rules about scripts, and never touch the scoring
#  engine (/opt/CyberPatriot is excluded from every scan/change on purpose).
#==============================================================================
export LC_ALL=C
umask 022

CPH_VERSION="2.0"
SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "$0")"
SELF_DIR="$(dirname "$SELF")"
CONFIG_DIR="${CP_CONFIG_DIR:-$SELF_DIR/config}"

# ---------- option defaults ----------
APPLY=0; ASSUME_YES=0; AGGRESSIVE=0; INSTALL_EXTRAS=0; INCLUDE_IMAGES=0; FAST=0; AUTO=0
README_SRC=""; README_ONLY=0; INIT_ONLY=0; LIST_MODS=0
ONLY=""; SKIP=""; WITH=""; PW_OVERRIDE="${CP_PASSWORD:-}"; ME_OVERRIDE=""
RUN_ID="$(date +%Y%m%d_%H%M%S)"
STATE_DIR="${CP_STATE_DIR:-/root/cp_harden_$RUN_ID}"
LOG=/dev/null; UNDO=/dev/null; BACKUP_DIR=/nonexistent; REPORT_DIR=/tmp; QUAR_DIR=/nonexistent
N_CHANGED=0; N_WOULD=0; N_REVIEW=0; N_WARN=0; N_SKIP=0; QUIET=0
NEWF=()

# ---------- policy knobs (edit to taste) ----------
PASS_MAX=90; PASS_MIN=7; PASS_WARN=14     # login.defs / chage
PW_MINLEN=12                              # pam_pwquality minimum length
LOCK_DENY=5; LOCK_TIME=900                # account lockout
README_ME=(); PROT_CFG=(); PROTECTED=(); AUTH_USERS=(); AUTH_ADMINS=()
REQ_RAW=(); REQ_TOKENS=(); REQ_PKGS=(); PROHIB_CFG=(); EXTRA_PORTS=()

# ---------- colours ----------
if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; N=$'\e[0m'; BO=$'\e[1m'
else R=; G=; Y=; B=; C=; N=; BO=; fi

# ---------- output / logging ----------
_log()    { printf '%s %s\n' "$(date +%T)" "$*" >>"$LOG" 2>/dev/null; }
say()     { printf '%s\n' "$*"; _log "$*"; }
info()    { printf '%s[i]%s %s\n' "$C" "$N" "$*"; _log "INFO $*"; }
good()    { printf '%s[ok]%s %s\n' "$G" "$N" "$*"; _log "OK $*"; }
warn()    { printf '%s[!]%s %s\n' "$Y" "$N" "$*" >&2; N_WARN=$((N_WARN+1)); _log "WARN $*"; }
err()     { printf '%s[x]%s %s\n' "$R" "$N" "$*" >&2; _log "ERR $*"; }
section() { printf '\n%s== %s ==%s\n' "$BO$B" "$*" "$N"; _log "=== $* ==="; }
_done()   { N_CHANGED=$((N_CHANGED+1)); _log "DONE $*"; (( QUIET )) || printf '%s[DONE]%s %s\n' "$G" "$N" "$*"; }
_would()  { N_WOULD=$((N_WOULD+1));   _log "WOULD $*"; (( QUIET )) || printf '%s[WOULD]%s %s\n' "$Y" "$N" "$*"; }

# review "title" "multi-line text"  -> shown + saved for a human to judge
review() {
  local title="$1" text="${2-}" n
  [[ -z "$text" ]] && return 0
  n=$(printf '%s\n' "$text" | wc -l)
  N_REVIEW=$((N_REVIEW+1))
  printf '%s[REVIEW]%s %s (%s lines)\n' "$Y" "$N" "$title" "$n"
  printf '%s\n' "$text" | head -n 12 | sed 's/^/      /'
  (( n > 12 )) && printf '      ... %s more -> %s/review.txt\n' "$((n-12))" "$REPORT_DIR"
  { printf '### %s\n%s\n\n' "$title" "$text"; } >>"$REPORT_DIR/review.txt"
  return 0
}

# ---------- generic helpers ----------
have()      { command -v "$1" >/dev/null 2>&1; }
in_list()   { local x="$1" i; shift; for i in "$@"; do [[ "$i" == "$x" ]] && return 0; done; return 1; }
in_csv()    { [[ ",$1," == *",$2,"* ]]; }
read_list() { [[ -r "$1" ]] || return 0; sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" | grep -vE '^(#|$)'; return 0; }
undo()      { printf '%s\n' "$*" >>"$UNDO"; }
newfile()   { NEWF+=("$1"); undo "rm -f '$1'"; }
osr()       { ( . /etc/os-release 2>/dev/null; printf '%s' "${!1}" ); }
gen_pass()  { local b; b="$(tr -dc 'A-HJ-NP-Za-km-z2-9' </dev/urandom | head -c 14)"; printf '%s#Cp7x' "$b"; }
ask_yes()   { (( ASSUME_YES )) && return 0; [[ -t 0 ]] || return 0; local a; read -r -p "$1 [Y/n] " a </dev/tty; [[ ! "$a" =~ ^[Nn] ]]; }
confirm()   { (( ASSUME_YES )) && return 0; [[ -t 0 ]] || return 1; local a; read -r -p "    ${Y}?${N} $1 [y/N] " a </dev/tty || return 1; [[ "$a" =~ ^[Yy] ]]; }
confirm_always() { [[ -t 0 ]] || return 1; local a; read -r -p "${Y}?${N} $1 [y/N] " a </dev/tty || return 1; [[ "$a" =~ ^[Yy] ]]; }  # ignores --yes
slow_ok()   { (( ! FAST )); }   # true unless --fast (guards the slow full-disk scans)

# change "description" cmd args...   (dry-run aware)
change() {
  local d="$1"; shift
  if (( APPLY )); then
    if "$@" >>"$LOG" 2>&1; then _done "$d"; return 0; else warn "FAILED: $d  (see $LOG)"; return 1; fi
  else _would "$d"; return 0; fi
}
# rchange = risky change: asks first when applying
rchange() {
  local d="$1"; shift
  if (( APPLY )); then
    if confirm "$d"; then change "$d" "$@"
    else N_SKIP=$((N_SKIP+1)); printf '%s[SKIP]%s %s\n' "$B" "$N" "$d"; return 1; fi
  else N_WOULD=$((N_WOULD+1)); _log "WOULD* $d"; printf '%s[WOULD*]%s %s %s(will ask first)%s\n' "$Y" "$N" "$d" "$B" "$N"; fi
}

backup() {   # backup file... (first copy only) + undo line
  local f d
  for f in "$@"; do
    [[ -e "$f" || -L "$f" ]] || continue
    d="$BACKUP_DIR$f"; [[ -e "$d" ]] && continue
    mkdir -p "$(dirname "$d")" && cp -a "$f" "$d" && undo "cp -a '$d' '$f'"
  done
  return 0
}
# one-time safety net before the first change: account DBs, firewall, package list, and ALL of /etc
backup_core() {
  local f
  for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/login.defs /etc/fstab /etc/hosts /etc/ssh/sshd_config; do backup "$f"; done
  tar czf "$BACKUP_DIR/etc_full.tgz" -C / etc 2>/dev/null && undo "# FULL /etc ROLLBACK (manual, last resort):  tar xzf '$BACKUP_DIR/etc_full.tgz' -C /"
  if [[ -d /etc/ufw ]]; then
    mkdir -p "$BACKUP_DIR/etc" && cp -a /etc/ufw "$BACKUP_DIR/etc/ufw" && undo "rm -rf /etc/ufw && cp -a '$BACKUP_DIR/etc/ufw' /etc/ufw && ufw reload   # restore firewall config"
  fi
  have ufw && ufw status verbose >"$BACKUP_DIR/ufw_status.txt" 2>&1
  have dpkg && dpkg --get-selections >"$BACKUP_DIR/dpkg_selections.txt" 2>/dev/null
  getent passwd >"$BACKUP_DIR/passwd.getent" 2>/dev/null
  return 0
}
cf() { local d="$1" f="$2"; shift 2; (( APPLY )) && backup "$f"; change "$d" "$@"; }   # backup file then change
sed_file() { # desc file grep-pattern sed-expr : apply "sed -E" only if pattern present
  local d="$1" f="$2" pat="$3" ex="$4"
  [[ -f "$f" ]] && grep -qE -- "$pat" "$f" || return 0
  cf "$d" "$f" sed -i -E -e "$ex" "$f"
}

write_file() { # path [mode]  (content on stdin) - creates/overwrites only if different
  local p="$1" m="${2:-644}" tmp; tmp="$(mktemp)"; cat >"$tmp"
  if [[ -f "$p" ]] && cmp -s "$tmp" "$p"; then rm -f "$tmp"; return 0; fi
  if (( APPLY )); then
    if [[ -e "$p" ]]; then backup "$p"; else newfile "$p"; mkdir -p "$(dirname "$p")"; fi
    cat "$tmp" >"$p" && chmod "$m" "$p" && _done "write $p" || warn "could not write $p"
  else _would "write $p"; fi
  rm -f "$tmp"
}

ensure_line() { # file line
  local f="$1" l="$2"
  [[ -f "$f" ]] && grep -qxF -- "$l" "$f" && return 0
  if (( APPLY )); then
    if [[ -e "$f" ]]; then backup "$f"; else newfile "$f"; mkdir -p "$(dirname "$f")"; fi
    [[ -s "$f" && -n "$(tail -c1 "$f")" ]] && echo >>"$f"
    printf '%s\n' "$l" >>"$f"; _done "add line to $f: $l"
  else _would "add line to $f: $l"; fi
}

# ----- "key value" / "key=value" style files -----
conf_get() { # file key -> last active value
  [[ -r "$1" ]] || return 0
  K="$2" awk 'BEGIN{k=ENVIRON["K"];kl=length(k)}
    { s=$0; sub(/^[ \t]+/,"",s); if (substr(s,1,1)=="#") next
      if (substr(s,1,kl)==k) { c=substr(s,kl+1,1)
        if (c==""||c==" "||c=="\t"||c=="=") { v=substr(s,kl+1); sub(/^[ \t=]+/,"",v); sub(/[ \t\r]+$/,"",v); last=v; f=1 } } }
    END{ if (f) print last }' "$1"
}
set_conf() { # file key value [space|eq|speq]
  local f="$1" k="$2" v="$3" st="${4:-space}" line cur tmp
  case "$st" in eq) line="$k=$v";; speq) line="$k = $v";; *) line="$k $v";; esac
  cur="$(conf_get "$f" "$k")"
  [[ -e "$f" && "$cur" == "$v" ]] && return 0
  if (( APPLY )); then
    if [[ -e "$f" ]]; then backup "$f"; else newfile "$f"; mkdir -p "$(dirname "$f")"; : >"$f"; fi
    tmp="$(mktemp)"
    K="$k" NL="$line" awk 'BEGIN{k=ENVIRON["K"];nl=ENVIRON["NL"];kl=length(k);done=0}
      { s=$0; sub(/^[ \t]+/,"",s)
        if (substr(s,1,1)!="#" && substr(s,1,kl)==k) { c=substr(s,kl+1,1)
          if (c==""||c==" "||c=="\t"||c=="=") { if(!done){print nl;done=1}; next } }
        print }
      END{ if(!done) print nl }' "$f" >"$tmp" && cat "$tmp" >"$f"
    rm -f "$tmp"; _done "set $k=$v in $f"
  else _would "set $k=$v in $f (now: ${cur:-unset})"; fi
}

# ----- INI style files ([section] key = value) -----
ini_get() { # file section key
  [[ -r "$1" ]] || return 0
  S="$2" K="$3" awk 'BEGIN{S=ENVIRON["S"];K=ENVIRON["K"];kl=length(K);ls=length(S)+2;insec=0}
    { s=$0; sub(/^[ \t]+/,"",s)
      if (substr(s,1,1)=="[") { insec=(tolower(substr(s,1,ls))==tolower("[" S "]")); next }
      if (!insec) next
      c1=substr(s,1,1); if (c1=="#"||c1==";") next
      if (tolower(substr(s,1,kl))==tolower(K)) { c=substr(s,kl+1,1)
        if (c==""||c==" "||c=="\t"||c=="=") { v=substr(s,kl+1); sub(/^[ \t=]+/,"",v); sub(/[ \t\r]+$/,"",v); last=v; f=1 } } }
    END{ if (f) print last }' "$1"
}
ini_set() { # file section key value
  local f="$1" s="$2" k="$3" v="$4" cur tmp
  cur="$(ini_get "$f" "$s" "$k")"
  [[ -e "$f" && "${cur,,}" == "${v,,}" ]] && return 0
  if (( APPLY )); then
    if [[ -e "$f" ]]; then backup "$f"; else newfile "$f"; mkdir -p "$(dirname "$f")"; : >"$f"; fi
    tmp="$(mktemp)"
    S="$s" K="$k" V="$v" awk 'BEGIN{S=ENVIRON["S"];K=ENVIRON["K"];V=ENVIRON["V"];kl=length(K);ls=length(S)+2;insec=0;done=0}
      { line=$0; s=line; sub(/^[ \t]+/,"",s)
        if (substr(s,1,1)=="[") { if (insec && !done) { print K " = " V; done=1 }
          insec=(tolower(substr(s,1,ls))==tolower("[" S "]")); print line; next }
        if (insec) { c1=substr(s,1,1)
          if (c1!="#" && c1!=";" && tolower(substr(s,1,kl))==tolower(K)) { c=substr(s,kl+1,1)
            if (c==""||c==" "||c=="\t"||c=="=") { if(!done){print K " = " V; done=1}; next } } }
        print line }
      END{ if(!done){ if(!insec) print "[" S "]"; print K " = " V } }' "$f" >"$tmp" && cat "$tmp" >"$f"
    rm -f "$tmp"; _done "set [$s] $k = $v in $f"
  else _would "set [$s] $k = $v in $f (now: ${cur:-unset})"; fi
}

# validate a service config after editing; restore backups on failure
validate_or_restore() { # "validator command" file...
  local v="$1" f d; shift
  (( APPLY )) || return 0
  if ! eval "$v" >>"$LOG" 2>&1; then
    for f in "$@"; do d="$BACKUP_DIR$f"
      if [[ -e "$d" ]]; then cp -a "$d" "$f"; elif in_list "$f" "${NEWF[@]}"; then rm -f "$f"; fi
    done
    warn "validation FAILED ($v) - edits to ${*} were rolled back"; return 1
  fi
  return 0
}

# ---------- OS / package / service helpers ----------
detect_os() {
  OS_ID="$(osr ID)"; OS_VER="$(osr VERSION_ID)"; OS_NAME="$(osr PRETTY_NAME)"
  : "${OS_ID:=unknown}" "${OS_VER:=0}" "${OS_NAME:=unknown}"
  if have apt-get; then PM=apt; elif have dnf; then PM=dnf; elif have yum; then PM=yum; else PM=none; fi
  DEBFAM=0; [[ $PM == apt ]] && DEBFAM=1
}
pkg_installed() { case $PM in apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed';; dnf|yum) rpm -q "$1" >/dev/null 2>&1;; *) return 1;; esac; }
pkg_list()      { { case $PM in apt) dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sed 's/:.*//';; dnf|yum) rpm -qa --qf '%{NAME}\n';; esac; } | sort -u; }
# DPkg::Lock::Timeout lets this wait for a background 'apt upgrade' (e.g. the --only updates tip) instead of failing
pkg_install()   { case $PM in apt) DEBIAN_FRONTEND=noninteractive apt-get -y -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confold -o Acquire::Retries=1 -o Acquire::http::Timeout=20 install "$@";; dnf|yum) $PM -y install "$@";; *) return 1;; esac; }
pkg_purge()     { local p; for p in "$@"; do undo "apt-get install -y $p   # (re-install purged package)"; done
                  case $PM in apt) DEBIAN_FRONTEND=noninteractive apt-get -y -o DPkg::Lock::Timeout=600 purge "$@";; dnf|yum) $PM -y remove "$@";; *) return 1;; esac; }
svc_has()       { [[ -z "${SVC_UNITS+x}" ]] && SVC_UNITS=" $(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}' | tr '\n' ' ')"; [[ "$SVC_UNITS" == *" $1 "* ]]; }
svc_active()    { systemctl is-active --quiet "$1" 2>/dev/null; }
svc_enabled()   { [[ "$(systemctl is-enabled "$1" 2>/dev/null)" == enabled ]]; }
svc_disable()   { local s="$1" u; for u in "$s.service" "$s.socket" "$s.path"; do systemctl disable --now "$u" 2>/dev/null; done
                  undo "systemctl enable --now '$s'   # (re-enable service)"; return 0; }
svc_reload()    { svc_active "$1" && { systemctl reload "$1" 2>/dev/null || systemctl restart "$1" 2>/dev/null; }; return 0; }

# ---------- required-service / package matching ----------
expand_req() { local t="${1,,}"; t="${t%.service}"
  case "$t" in
    ssh|sshd|openssh*) echo ssh sshd openssh;;
    apache|apache2|httpd) echo apache2 httpd apache;;
    mysql|mysqld|mariadb|mariadb-server|mysql-server) echo mysql mariadb;;
    samba|smb|smbd|nmbd) echo samba smbd nmbd;;
    postgres|postgresql) echo postgres;;
    bind|bind9|named|dns) echo bind9 named;;
    ftp|vsftpd|ftpd) echo vsftpd proftpd pure-ftpd;;
    nfs|nfs-server|nfs-kernel-server) echo nfs;;
    smtp|mail|postfix) echo postfix;;
    *) echo "$t";;
  esac; }
req_match() { local n="${1,,}" t; n="${n%.service}"
  for t in "${REQ_TOKENS[@]}"; do
    [[ "$n" == "$t" || "$n" == "$t"* ]] && return 0
    (( ${#t} >= 4 )) && [[ "$n" == *"$t"* ]] && return 0
  done; return 1; }
pkg_is_required() { local p="$1" pat; for pat in "${REQ_PKGS[@]}"; do [[ "$p" == $pat ]] && return 0; done; req_match "$p"; }
req_units() { case "$1" in
    ssh|sshd|openssh*) echo "ssh sshd";; apache|apache2|httpd) echo "apache2 httpd";;
    mysql|mysqld|mariadb*|mysql-server) echo "mysql mariadb";; samba|smb|smbd|nmbd) echo "smbd nmbd";;
    postgres|postgresql) echo postgresql;; bind|bind9|named|dns) echo "bind9 named";;
    ftp|vsftpd|ftpd) echo "vsftpd proftpd pure-ftpd";; nfs|nfs-server) echo "nfs-server nfs-kernel-server";;
    smtp|mail|postfix) echo postfix;; *) echo "$1";; esac; }

# ---------- config / state ----------
init_state() {
  mkdir -p "$STATE_DIR"/{backups,reports,before,after,quarantine} && chmod 700 "$STATE_DIR"
  LOG="$STATE_DIR/run.log"; UNDO="$STATE_DIR/undo.sh"; BACKUP_DIR="$STATE_DIR/backups"
  REPORT_DIR="$STATE_DIR/reports"; QUAR_DIR="$STATE_DIR/quarantine"
  { echo '#!/usr/bin/env bash'; echo "# UNDO script for run $RUN_ID - REVIEW before running (restores backups, re-enables services...)"; } >"$UNDO"
  chmod 700 "$UNDO"; : >"$REPORT_DIR/review.txt"
}

init_config() {
  mkdir -p "$CONFIG_DIR"
  local f h
  for f in authorized_users authorized_admins required_services required_packages prohibited_packages protected_users allow_ports; do
    [[ -e "$CONFIG_DIR/$f.txt" ]] && continue
    case $f in
      authorized_users)    h="ALL authorized accounts from the README (admins AND standard users). One username per line.";;
      authorized_admins)   h="Accounts that are allowed to be administrators (sudo). One per line.";;
      required_services)   h="Services the README says must keep running (ssh, apache2, mysql, samba, vsftpd, ...). Never disabled.";;
      required_packages)   h="Packages that must NOT be removed (globs ok: nmap, wireshark*). Use for 'allowed' software.";;
      prohibited_packages) h="Packages to remove (globs ok). The built-in list of hacking tools/games/p2p is used in addition.";;
      protected_users)     h="Accounts this script must never delete or change passwords for (you are protected automatically).";;
      allow_ports)         h="Extra firewall ports to allow, e.g. 8080/tcp  or  53/udp";;
    esac
    printf '# %s\n# %s\n# One entry per line. Lines starting with # are ignored.\n' "$f.txt" "$h" >"$CONFIG_DIR/$f.txt"
  done
}

detect_me() {
  if [[ "$ME_OVERRIDE" == none ]]; then ME=""; return; fi
  ME="${ME_OVERRIDE:-${SUDO_USER:-}}"
  [[ -z "$ME" ]] && ME="$(logname 2>/dev/null)"
  [[ -z "$ME" ]] && ME="$(who am i 2>/dev/null | awk '{print $1}')"
  [[ -z "$ME" || "$ME" == root ]] && ME=""
}

load_config() {
  local t
  mapfile -t AUTH_USERS  < <(read_list "$CONFIG_DIR/authorized_users.txt")
  mapfile -t AUTH_ADMINS < <(read_list "$CONFIG_DIR/authorized_admins.txt")
  mapfile -t REQ_RAW     < <(read_list "$CONFIG_DIR/required_services.txt")
  mapfile -t REQ_PKGS    < <(read_list "$CONFIG_DIR/required_packages.txt")
  mapfile -t PROHIB_CFG  < <(read_list "$CONFIG_DIR/prohibited_packages.txt")
  mapfile -t PROT_CFG    < <(read_list "$CONFIG_DIR/protected_users.txt")
  mapfile -t EXTRA_PORTS < <(read_list "$CONFIG_DIR/allow_ports.txt")
  REQ_TOKENS=(); for t in "${REQ_RAW[@]}"; do REQ_TOKENS+=($(expand_req "$t")); done
  detect_me
  PROTECTED=(root); [[ -n "$ME" ]] && PROTECTED+=("$ME")
  PROTECTED+=("${PROT_CFG[@]}" "${README_ME[@]}")
  UID_MIN="$(awk '$1=="UID_MIN"{print $2}' /etc/login.defs 2>/dev/null)"; UID_MIN="${UID_MIN:-1000}"
  UID_MAX="$(awk '$1=="UID_MAX"{print $2}' /etc/login.defs 2>/dev/null)"; UID_MAX="${UID_MAX:-60000}"
}

# =============================================================================
#  README ingestion  (--readme FILE | - | auto)
#  Converts the README (html/txt) to text, extracts authorized admins/users,
#  critical services, "(you)" account and key rules, then writes config/*.txt
# =============================================================================
find_readme() {
  local c url
  for c in /opt/CyberPatriot/README* /opt/CyberPatriot/*.html /home/*/Desktop/README* /root/Desktop/README* \
           /home/*/Desktop/*readme*.html /usr/share/CyberPatriot/README*; do
    [[ -f "$c" ]] || continue
    if [[ "$c" == *.desktop ]]; then   # launcher: pull the file it opens
      url="$(grep -m1 -E '^URL=' "$c" | sed -e 's/^URL=//' -e 's#^file://##')"
      [[ -f "$url" ]] && { echo "$url"; return 0; }
      continue
    fi
    echo "$c"; return 0
  done
  find / -xdev \( -path /proc -o -path /sys -o -path /usr -o -path /var/lib \) -prune -o -type f -iname '*readme*' \
       \( -iname '*.html' -o -iname '*.htm' -o -iname '*.txt' -o -iname '*.desktop' \) -print 2>/dev/null | head -5 | while read -r c; do
    if [[ "$c" == *.desktop ]]; then url="$(grep -m1 -E '^URL=' "$c" | sed -e 's/^URL=//' -e 's#^file://##')"; [[ -f "$url" ]] && { echo "$url"; break; }; else echo "$c"; break; fi
  done
}

readme_to_text() {  # file -> plain text on stdout
  if have python3; then
    python3 - "$1" <<'PY'
import sys
from html.parser import HTMLParser
BLOCK={'br','p','div','li','ul','ol','tr','td','th','table','h1','h2','h3','h4','h5','h6','pre','hr','section','article','blockquote'}
class P(HTMLParser):
    def __init__(s): super().__init__(); s.o=[]; s.skip=0
    def handle_starttag(s,t,a):
        if t in('script','style'): s.skip+=1
        elif t in BLOCK: s.o.append('\n')
    def handle_endtag(s,t):
        if t in('script','style'): s.skip=max(0,s.skip-1)
        elif t in BLOCK: s.o.append('\n')
    def handle_data(s,d):
        if not s.skip: s.o.append(d)
p=P(); p.feed(open(sys.argv[1],'rb').read().decode('utf-8','replace'))
print(''.join(p.o).replace('\xa0',' '))
PY
  else
    sed -e 's/<[Bb][Rr][^>]*>/\n/g' -e 's/<\/\?\(p\|div\|li\|ul\|ol\|tr\|td\|th\|table\|h[1-6]\|pre\)[^>]*>/\n/Ig' \
        -e 's/<[^>]*>//g' -e 's/&nbsp;/ /g;s/&amp;/\&/g;s/&lt;/</g;s/&gt;/>/g;s/&quot;/"/g' "$1"
  fi
}

# service keyword table:  regex-of-words : service tokens
SVC_MAP=(
 'openssh|ssh|sshd:ssh'            'apache|apache2|httpd|web server:apache2'   'nginx:nginx'
 'mysql:mysql'                     'mariadb:mariadb'                           'postgres|postgresql:postgresql'
 'samba|smb|smbd|nmbd:samba'       'vsftpd|ftp|proftpd:ftp'                    'bind9|named|dns:bind9'
 'postfix|smtp|mail server:postfix' 'dovecot|imap|pop3:dovecot'               'cups|printing:cups'
 'docker:docker'                   'tomcat:tomcat'                             'redis:redis-server'
 'mongo|mongodb:mongod'            'nfs:nfs'                                   'snmp:snmpd'
 'squid:squid'                     'dhcp:isc-dhcp-server'                      'ldap|slapd:slapd'
 'memcached:memcached'             'php:php'                                   'cron:cron'
)
svc_from_text() { # text -> service tokens (one per line)
  local e pats names
  for e in "${SVC_MAP[@]}"; do
    pats="${e%%:*}"; names="${e##*:}"
    printf '%s\n' "$1" | grep -Eiqw "($pats)" && printf '%s\n' "$names"
  done
}

readme_parse() { # textfile outdir
  local txt="$1" d="$2" line ctx
  : >"$d/admins.txt"; : >"$d/users.txt"; : >"$d/me.txt"; : >"$d/svc_raw.txt"
  awk -v A="$d/admins.txt" -v U="$d/users.txt" -v M="$d/me.txt" -v S="$d/svc_raw.txt" '
    function trim(s){ sub(/^[ \t\r]+/,"",s); sub(/[ \t\r]+$/,"",s); return s }
    function adduser(tok, full){
      if (tok ~ /^[a-z_][a-z0-9_.-]*$/) {
        if (sec=="admin") print tok > A; else print tok > U
        if (tolower(full) ~ /\(you\)/ || tolower(full) ~ /\([^)]*you[^)]*\)/) print tok > M
      } }
    function inline(rest,   n,i,w,prev,it){ rest=trim(rest); if (rest=="") return
      if (sec=="svc") { n=split(rest,w,/[,;]/); for(i=1;i<=n;i++){ it=trim(w[i]); if (it!="") print it > S }; return }
      gsub(/[,;]/," ",rest); n=split(rest,w,/[ \t]+/); prev=""
      for(i=1;i<=n;i++){ if (w[i]=="") continue
        if (substr(w[i],1,1)=="(") { if (tolower(w[i]) ~ /you/ && prev!="") print prev > M; continue }
        if (w[i] ~ /^[a-z_][a-z0-9_.-]*$/) { if (sec=="admin") print w[i] > A; else print w[i] > U; prev=w[i] } } }
    BEGIN{sec=""}
    { line=trim($0); low=tolower(line); if (line=="") next
      if (low ~ /^authorized (administrators|admins)/) {
        if (low ~ /and users/ && index(line,":")==0) { sec=""; next }
        sec="admin"; if (index(line,":")>0) inline(substr(line,index(line,":")+1)); next }
      if (low ~ /^authorized (standard )?users/) { sec="user"; if (index(line,":")>0) inline(substr(line,index(line,":")+1)); next }
      if (low ~ /(critical|required|essential|necessary) services?/ && length(line)<80) {
        sec="svc"; if (index(line,":")>0) inline(substr(line,index(line,":")+1)); next }
      if (sec=="admin" || sec=="user") {
        if (low ~ /^password/) next
        tok=line; sub(/[ \t]*\(.*$/,"",tok)
        if (tok ~ /^[a-z_][a-z0-9_.-]*$/) { adduser(tok, line); next } else sec=""
      }
      if (sec=="svc") { n=split(line,w,/[ \t]+/); if (n<=5 && line !~ /\.$/) { print line > S; next } else sec="" }
    }' "$txt"
  # normalise
  for line in admins users me; do sort -u "$d/$line.txt" -o "$d/$line.txt"; done
  cat "$d/admins.txt" "$d/users.txt" | sort -u >"$d/all_users.txt"
  # services: explicit "critical services" lines + sentences with critical words
  : >"$d/services.txt"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    ctx="$(svc_from_text "$line")"
    if [[ -n "$ctx" ]]; then printf '%s\n' "$ctx" >>"$d/services.txt"; else printf '%s\n' "${line,,}" | awk '{print $1}' >>"$d/services.txt"; fi
  done <"$d/svc_raw.txt"
  grep -iE '(critical|required|must (remain|stay|keep|be (running|available))|need(s|ed)? (to|for)|essential|necessary|do not (remove|disable|stop|delete)|should (remain|stay|keep))' "$txt" |
    while IFS= read -r line; do svc_from_text "$line"; done >>"$d/services.txt"
  sort -u "$d/services.txt" -o "$d/services.txt"
  # protected software: a tool the README explicitly says is needed/allowed
  : >"$d/protect_pkgs.txt"
  local tool
  for tool in "${DEFAULT_PROHIBITED[@]}"; do
    [[ "$tool" == *'*'* ]] && continue
    grep -iw -- "$tool" "$txt" 2>/dev/null | grep -qiE '(authori[sz]ed|allowed|required|critical|need|must|permitted|used for|necessary|do not (remove|delete|uninstall))' && echo "$tool" >>"$d/protect_pkgs.txt"
  done
  sort -u "$d/protect_pkgs.txt" -o "$d/protect_pkgs.txt"
  # ports the README mentions (a human decides: put them in config/allow_ports.txt)
  grep -oiE '\bports?[: ]+[0-9]{2,5}(/(tcp|udp))?' "$txt" 2>/dev/null | sort -u >"$d/ports.txt"
  # key sentences for the humans
  grep -iE '(do not|don.t|must|should|never|only|required|critical|prohibit|forbid|not allowed|authori[sz]ed|policy|ensure|make sure|please)' "$txt" |
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | awk 'length>25 && length<400' | head -60 >"$d/key_lines.txt"
}

readme_ingest() { # src (file | - | auto)
  local src="$1" raw="$STATE_DIR/readme_raw" txt="$STATE_DIR/readme.txt" d="$STATE_DIR/readme_parsed" f bak
  mkdir -p "$d"
  if [[ "$src" == auto ]]; then
    src="$(find_readme)"; [[ -n "$src" ]] || { err "could not auto-locate the README; pass --readme /path/to/README.html"; return 1; }
    info "README located: $src"
  fi
  if [[ "$src" == - ]]; then cat >"$raw"; else
    [[ -r "$src" ]] || { err "README not readable: $src"; return 1; }
    cp -- "$src" "$raw"
  fi
  readme_to_text "$raw" >"$txt"
  [[ -s "$txt" ]] || { err "README produced no text"; return 1; }
  readme_parse "$txt" "$d"
  section "README parse results (best-effort: VERIFY against the real README!)"
  say "Authorized administrators : $(tr '\n' ' ' <"$d/admins.txt")"
  say "Authorized standard users : $(comm -13 "$d/admins.txt" "$d/users.txt" | tr '\n' ' ')"
  say "Account marked '(you)'     : $(tr '\n' ' ' <"$d/me.txt")"
  say "Critical services (guess) : $(tr '\n' ' ' <"$d/services.txt")"
  say "Software README protects  : $(tr '\n' ' ' <"$d/protect_pkgs.txt")"
  [[ -s "$d/ports.txt" ]] && say "Ports mentioned in README: $(tr '\n' ' ' <"$d/ports.txt")  (add real ones to config/allow_ports.txt)"
  [[ -s "$d/all_users.txt" ]] || warn "No 'Authorized Administrators/Users' lists were recognised. Fill config/authorized_*.txt by hand."
  if [[ -s "$d/key_lines.txt" ]]; then
    printf '\n%sREADME sentences that look like rules - READ THESE YOURSELF:%s\n' "$BO" "$N"; sed 's/^/   | /' "$d/key_lines.txt" | head -25
    cp "$d/key_lines.txt" "$REPORT_DIR/readme_key_lines.txt"
  fi
  echo
  if ask_yes "Write these lists into $CONFIG_DIR (existing files are backed up as *.bak)?"; then
    mkdir -p "$CONFIG_DIR"
    for f in authorized_users authorized_admins required_services required_packages; do
      [[ -f "$CONFIG_DIR/$f.txt" ]] && cp -a "$CONFIG_DIR/$f.txt" "$CONFIG_DIR/$f.txt.bak.$RUN_ID"
    done
    { echo "# generated from README $RUN_ID - REVIEW"; cat "$d/all_users.txt"; }  >"$CONFIG_DIR/authorized_users.txt"
    { echo "# generated from README $RUN_ID - REVIEW"; cat "$d/admins.txt"; }     >"$CONFIG_DIR/authorized_admins.txt"
    { echo "# generated from README $RUN_ID - heuristic, REVIEW"; cat "$d/services.txt"; } >"$CONFIG_DIR/required_services.txt"
    { echo "# software the README says is allowed/needed - REVIEW"; cat "$d/protect_pkgs.txt"; } >"$CONFIG_DIR/required_packages.txt"
    if [[ -s "$d/me.txt" ]]; then   # remember the '(you)' account so later runs protect it
      [[ -f "$CONFIG_DIR/protected_users.txt" ]] || : >"$CONFIG_DIR/protected_users.txt"
      while read -r f; do grep -qxF "$f" "$CONFIG_DIR/protected_users.txt" || echo "$f" >>"$CONFIG_DIR/protected_users.txt"; done <"$d/me.txt"
    fi
    good "config written to $CONFIG_DIR  -> open and correct the files before --apply"
  else warn "config not written"; fi
  mapfile -t README_ME <"$d/me.txt"
}

# =============================================================================
#  MODULE policy : login.defs, pwquality, PAM, lockout, password aging
# =============================================================================
human_users() { awk -F: -v mn="$UID_MIN" -v mx="$UID_MAX" '$3>=mn && $3<=mx && $1!="nobody"{print $1}' /etc/passwd | sort; }

pam_arg() { # file type module-regex key=value|token   (replace key=* or append)
  local f="$1" t="$2" m="$3" kv="$4" k="${4%%=*}" line
  [[ -f "$f" ]] || return 0
  line="$(grep -E "^[[:space:]]*$t[[:space:]].*$m" "$f" | head -1)"; [[ -n "$line" ]] || return 0
  grep -qE "(^|[[:space:]])$kv([[:space:]]|\$)" <<<"$line" && return 0
  if [[ "$kv" == *=* ]]; then
    cf "pam: set $kv on ${m//\\/} ($f)" "$f" sed -i -E -e "/^[[:space:]]*$t[[:space:]].*$m/{" -e "s/([[:space:]])$k=[^[:space:]]*/\1$kv/" -e "t" -e "s/\$/ $kv/" -e "}" "$f"
  else
    cf "pam: add '$kv' to ${m//\\/} ($f)" "$f" sed -i -E -e "/^[[:space:]]*$t[[:space:]].*$m/ s/\$/ $kv/" "$f"
  fi
}
_lock_tally2() {
  local f=/etc/pam.d/common-auth
  backup $f /etc/pam.d/common-account
  sed -i -E "0,/^auth[[:space:]]/s//auth required pam_tally2.so deny=$LOCK_DENY onerr=fail unlock_time=$LOCK_TIME\nauth /" $f || return 1
  grep -q pam_tally2 /etc/pam.d/common-account || echo 'account required pam_tally2.so' >>/etc/pam.d/common-account
}
_lock_faillock() {
  local f=/etc/pam.d/common-auth a="deny=$LOCK_DENY unlock_time=$LOCK_TIME fail_interval=$LOCK_TIME" t
  backup $f /etc/pam.d/common-account; t="$(mktemp)"
  awk -v a="$a" '/^[ \t]*auth[ \t].*pam_unix\.so/ && !d { print "auth required pam_faillock.so preauth silent " a; print
        print "auth [default=die] pam_faillock.so authfail " a; print "auth sufficient pam_faillock.so authsucc " a; d=1; next } {print}' $f >"$t" \
    && grep -q pam_faillock "$t" && cat "$t" >$f; rm -f "$t"
  grep -q pam_faillock $f || return 1
  grep -q pam_faillock /etc/pam.d/common-account || echo 'account required pam_faillock.so' >>/etc/pam.d/common-account
}
_su_wheel() { local g=sudo; getent group sudo >/dev/null || g=wheel; backup /etc/pam.d/su; echo "auth required pam_wheel.so use_uid group=$g" >>/etc/pam.d/su; }
_pam_permit_off() { backup "$1"; sed -i -E '/^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit\.so/ s/^/# cp_disabled: /' "$1"; }

mod_policy() {
  section "Password policy, PAM, lockout, aging"
  local L=/etc/login.defs PWQ=/etc/security/pwquality.conf CP=/etc/pam.d/common-password CA=/etc/pam.d/common-auth cur want u f today_days today_date mn mx wn lc
  set_conf $L PASS_MAX_DAYS "$PASS_MAX"; set_conf $L PASS_MIN_DAYS "$PASS_MIN"; set_conf $L PASS_WARN_AGE "$PASS_WARN"
  set_conf $L PASS_MIN_LEN "$PW_MINLEN"
  set_conf $L LOGIN_RETRIES 5; set_conf $L LOGIN_TIMEOUT 60; set_conf $L UMASK 027
  set_conf $L FAILLOG_ENAB yes; set_conf $L LOG_OK_LOGINS yes; set_conf $L SYSLOG_SU_ENAB yes; set_conf $L SYSLOG_SG_ENAB yes
  set_conf $L USERGROUPS_ENAB yes
  case "$(conf_get $L ENCRYPT_METHOD)" in SHA512|YESCRYPT) ;; *) set_conf $L ENCRYPT_METHOD SHA512;; esac
  [[ -e /etc/default/useradd ]] && set_conf /etc/default/useradd INACTIVE 30 eq
  [[ -e /etc/adduser.conf ]]    && set_conf /etc/adduser.conf DIR_MODE 0750 eq
  ensure_line /etc/security/limits.conf '* hard core 0'

  # --- complexity ---
  if (( DEBFAM )) && ! pkg_installed libpam-pwquality && ! find /lib /usr/lib -name 'pam_cracklib.so' 2>/dev/null | grep -q .; then
    change "install libpam-pwquality" pkg_install libpam-pwquality
  fi
  set_conf $PWQ minlen "$PW_MINLEN" speq; set_conf $PWQ difok 3 speq
  set_conf $PWQ dcredit -1 speq; set_conf $PWQ ucredit -1 speq; set_conf $PWQ lcredit -1 speq; set_conf $PWQ ocredit -1 speq
  set_conf $PWQ maxrepeat 3 speq; set_conf $PWQ usercheck 1 speq; set_conf $PWQ enforcing 1 speq; set_conf $PWQ retry 3 speq
  if [[ -f $CP ]]; then
    want="password requisite pam_pwquality.so retry=3 minlen=$PW_MINLEN difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 reject_username enforce_for_root"
    if grep -qE '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' $CP; then
      cur="$(grep -E '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' $CP | head -1 | tr -s ' \t' '  ')"
      [[ "$cur" == "$want" ]] || cf "common-password: set pam_pwquality complexity rules" $CP sed -i -E "s|^[[:space:]]*password[[:space:]].*pam_pwquality\.so.*|$want|" $CP
    elif grep -qE 'pam_cracklib\.so' $CP; then
      cf "common-password: set pam_cracklib complexity rules" $CP sed -i -E "s|^[[:space:]]*password[[:space:]].*pam_cracklib\.so.*|password requisite pam_cracklib.so retry=3 minlen=$PW_MINLEN difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root|" $CP
    elif find /lib /usr/lib -name pam_pwquality.so 2>/dev/null | grep -q . || (( ! APPLY )); then
      cf "common-password: add pam_pwquality" $CP sed -i -E "0,/^[[:space:]]*password[[:space:]].*pam_unix\.so/s||$want\n&|" $CP
    fi
    pam_arg $CP password 'pam_unix\.so' remember=5
    grep -E '^[[:space:]]*password[[:space:]].*pam_unix\.so' $CP | grep -qE 'sha512|yescrypt|blowfish' || pam_arg $CP password 'pam_unix\.so' sha512
    sed_file "common-password: remove nullok" $CP 'pam_unix.*nullok' '/pam_unix/ s/[[:space:]]+nullok(_secure)?//'
  fi
  # --- lockout ---
  if [[ -f $CA ]]; then
    sed_file "common-auth: remove nullok (blank passwords)" $CA 'pam_unix.*nullok' '/pam_unix/ s/[[:space:]]+nullok(_secure)?//'
    if grep -qE 'pam_(tally2|faillock)\.so' $CA; then good "account lockout already present in common-auth"
    elif find /lib /usr/lib -name 'pam_tally2.so' 2>/dev/null | grep -q .; then
      rchange "enable account lockout (pam_tally2 deny=$LOCK_DENY) - test a login in a 2nd terminal afterwards!" _lock_tally2
    elif find /lib /usr/lib -name 'pam_faillock.so' 2>/dev/null | grep -q .; then
      rchange "enable account lockout (pam_faillock deny=$LOCK_DENY) - test a login in a 2nd terminal afterwards!" _lock_faillock
    else warn "no pam_tally2/pam_faillock module found - lockout not configured"; fi
  fi
  if [[ -f /etc/security/faillock.conf ]]; then
    set_conf /etc/security/faillock.conf deny "$LOCK_DENY" speq; set_conf /etc/security/faillock.conf unlock_time "$LOCK_TIME" speq
    set_conf /etc/security/faillock.conf fail_interval "$LOCK_TIME" speq
  fi
  # --- every other PAM file: blank-password (nullok) and 'auth sufficient pam_permit' bypasses ---
  for f in /etc/pam.d/*; do
    [[ -f "$f" && "$f" != "$CP" && "$f" != "$CA" ]] || continue
    sed_file "pam: remove nullok in $f" "$f" 'pam_unix.*nullok' '/pam_unix/ s/[[:space:]]+nullok(_secure)?//'
  done
  for f in /etc/pam.d/*; do
    [[ -f "$f" ]] && grep -qE '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit\.so' "$f" && rchange "pam: disable 'auth sufficient pam_permit.so' (login bypass) in $f" _pam_permit_off "$f"
  done
  if (( AGGRESSIVE )) && [[ -f /etc/pam.d/su ]] && ! grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' /etc/pam.d/su; then
    rchange "restrict 'su' to the admin group (pam_wheel)" _su_wheel
  fi
  review "PAM lines that can bypass authentication (verify!)" "$(grep -nE '(sufficient|optional|\[success=(done|ok)).*pam_permit\.so|pam_exec\.so|pam_succeed_if\.so.*sufficient' /etc/pam.d/* 2>/dev/null)"
  review "polkit rules granting actions without authentication (verify)" "$(grep -rnE 'ResultAny=yes|ResultActive=yes|ResultInactive=yes|polkit\.Result\.YES' /etc/polkit-1 /var/lib/polkit-1 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*(//|#)' | head -15)"
  # --- aging for existing users ---
  today_days=$(( $(date +%s)/86400 )); today_date="$(date +%F)"
  while read -r u; do
    cur="$(awk -F: -v u="$u" '$1==u{print $4":"$5":"$6":"$3}' /etc/shadow)"; [[ -z "$cur" ]] && continue
    IFS=: read -r mn mx wn lc <<<"$cur"
    [[ "$mn:$mx:$wn" == "$PASS_MIN:$PASS_MAX:$PASS_WARN" ]] || change "chage aging for $u ($PASS_MIN/$PASS_MAX/$PASS_WARN)" chage -m "$PASS_MIN" -M "$PASS_MAX" -W "$PASS_WARN" "$u"
    if in_list "$u" "${PROTECTED[@]}" && [[ -n "$lc" ]] && (( lc + PASS_MAX < today_days )); then
      change "reset last-change date of protected user $u (prevents sudo 'password expired' lockout)" chage -d "$today_date" "$u"
    fi
  done < <(human_users)
}

# =============================================================================
#  MODULE accounts : users, admins, groups, passwords
# =============================================================================
remove_user() { local u="$1" h uid shared rm_home=0
  [[ "$u" == root ]] && return 1                       # never
  uid="$(id -u "$u" 2>/dev/null)"; h="$(getent passwd "$u" | cut -d: -f6)"
  # Home is only removed if it is /home/<name> and no other account shares it (a planted UID-0 account may share /root!)
  shared="$(getent passwd | awk -F: -v h="$h" -v u="$u" '$6==h && $1!=u' | wc -l)"
  [[ "$h" =~ ^/home/[^/]+/?$ && "$shared" == 0 ]] && rm_home=1
  (( rm_home )) && [[ -d "$h" ]] && tar czf "$BACKUP_DIR/home_${u}.tgz" -C "$(dirname "$h")" "$(basename "$h")" 2>/dev/null
  # NEVER pkill by UID 0: that would kill every root process (including this script)
  [[ -n "$uid" && "$uid" != 0 ]] && pkill -KILL -U "$uid" 2>/dev/null
  crontab -r -u "$u" 2>/dev/null
  if (( rm_home )); then userdel -r -f "$u" || userdel -f "$u"; else userdel -f "$u"; fi
  undo "# user '$u' was deleted. Home archive (if any): $BACKUP_DIR/home_${u}.tgz  (recreate: useradd -m $u && tar xzf ... -C /home)"
}
add_user()  { useradd -m -s /bin/bash "$1" && undo "userdel -r '$1'   # created by script"; }
next_uid()  { awk -F: -v m="$UID_MIN" -v x="$UID_MAX" '$3>=m && $3<x && $3>mx{mx=$3} END{print (mx<m?m:mx+1)}' /etc/passwd; }
pw_apply()  {
  local pass="${PW_OVERRIDE:-$(gen_pass)}" u pf="$STATE_DIR/new_password.txt"
  ( umask 077; printf '# run %s - password applied to: %s\n%s\n' "$RUN_ID" "${PW_USERS[*]}" "$pass" >"$pf" )
  for u in "${PW_USERS[@]}"; do printf '%s:%s\n' "$u" "$pass" | chpasswd || return 1; done
}

mod_accounts() {
  section "User accounts, groups, passwords"
  local u g m ag admgrp="" nologin=/usr/sbin/nologin rs uid sh ex
  local -a cur
  [[ -x $nologin ]] || nologin=/sbin/nologin
  mapfile -t cur < <(human_users)
  info "Human accounts (UID $UID_MIN-$UID_MAX): ${cur[*]:-none}"
  info "Protected (never deleted / password-changed): ${PROTECTED[*]}"
  [[ -z "$ME" ]] && warn "could not detect which account is YOURS - pass --me USERNAME or list it in config/protected_users.txt"

  # 1) unauthorized / missing users
  if (( ${#AUTH_USERS[@]} == 0 )); then
    warn "authorized_users.txt is empty -> skipping unauthorized/missing user checks (fill it from the README)"
  else
    for u in "${cur[@]}"; do
      in_list "$u" "${AUTH_USERS[@]}" && continue
      in_list "$u" "${PROTECTED[@]}" && continue
      rchange "DELETE unauthorized user '$u' (home archived first)" remove_user "$u"
    done
    for u in "${AUTH_USERS[@]}"; do
      id "$u" >/dev/null 2>&1 && continue
      rchange "CREATE missing authorized user '$u'" add_user "$u"
    done
  fi

  # 2) admin group membership
  for ag in sudo admin wheel; do getent group "$ag" >/dev/null && { admgrp="$ag"; break; }; done
  if (( ${#AUTH_ADMINS[@]} == 0 )); then
    warn "authorized_admins.txt is empty -> skipping admin group sync"
  else
    for ag in sudo admin wheel; do
      getent group "$ag" >/dev/null || continue
      while read -r m; do
        [[ -z "$m" ]] && continue
        in_list "$m" "${AUTH_ADMINS[@]}" && continue; in_list "$m" "${PROTECTED[@]}" && continue
        rchange "remove '$m' from admin group '$ag' (not an authorized admin)" gpasswd -d "$m" "$ag"
      done < <(getent group "$ag" | cut -d: -f4 | tr ',' '\n')
    done
    for u in "${AUTH_ADMINS[@]}"; do
      id "$u" >/dev/null 2>&1 || continue
      id -nG "$u" | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel' || [[ -z "$admgrp" ]] || change "make authorized admin '$u' a member of '$admgrp'" usermod -aG "$admgrp" "$u"
    done
    for g in shadow disk docker lxd root staff libvirt kvm; do   # privilege-equivalent groups
      getent group "$g" >/dev/null || continue
      while read -r m; do
        [[ -z "$m" ]] && continue
        in_list "$m" "${AUTH_ADMINS[@]}" && continue; in_list "$m" "${PROTECTED[@]}" && continue
        rchange "remove '$m' from privileged group '$g'" gpasswd -d "$m" "$g"
      done < <(getent group "$g" | cut -d: -f4 | tr ',' '\n')
    done
  fi
  # passwordless-login group (Linux Mint / lightdm): nobody should be in it
  if getent group nopasswdlogin >/dev/null; then
    while read -r m; do
      [[ -z "$m" ]] && continue
      rchange "remove '$m' from 'nopasswdlogin' (log in WITHOUT a password)" gpasswd -d "$m" nopasswdlogin
    done < <(getent group nopasswdlogin | cut -d: -f4 | tr ',' '\n')
  fi
  review "Members of group 'adm' (can read logs) - verify" "$(getent group adm | cut -d: -f4)"
  review "Accounts whose primary group is GID 0 (root)" "$(awk -F: '$4==0 && $1!="root"{print $1}' /etc/passwd)"

  # 3) UID 0 backdoors
  while IFS=: read -r u _ uid _; do
    [[ "$uid" == 0 && "$u" != root ]] || continue
    if in_list "$u" "${AUTH_USERS[@]}"; then rchange "UID-0 account '$u' is authorized: give it a normal UID" usermod -u "$(next_uid)" "$u"
    else rchange "REMOVE extra UID-0 (root-equivalent) account '$u'" remove_user "$u"; fi
  done </etc/passwd
  # 3b) normal accounts whose primary group is root's group
  while read -r u; do
    [[ -z "$u" ]] && continue; in_list "$u" "${PROTECTED[@]}" && continue
    g="$u"; getent group "$g" >/dev/null || g=users
    rchange "set primary group of '$u' to '$g' (was GID 0 = root)" usermod -g "$g" "$u"
  done < <(awk -F: '$4==0 && $1!="root"{print $1}' /etc/passwd)
  # 3c) authorized accounts must be usable: real shell, no account expiry
  if (( ${#AUTH_USERS[@]} )); then
    for u in "${AUTH_USERS[@]}"; do
      id "$u" >/dev/null 2>&1 || continue
      uid="$(id -u "$u")"; sh="$(getent passwd "$u" | cut -d: -f7)"
      if (( uid >= UID_MIN )) && [[ "$sh" =~ (nologin|/false)$ ]]; then
        rchange "authorized user '$u' has shell '$sh': give it /bin/bash" usermod -s /bin/bash "$u"
      fi
      ex="$(chage -l "$u" 2>/dev/null | awk -F': ' '/^Account expires/{print $2}')"
      [[ -n "$ex" && "$ex" != never ]] && rchange "authorized user '$u' has an account expiry ($ex): remove it" chage -E -1 "$u"
    done
  fi
  review "Human accounts with a home directory outside /home" "$(awk -F: -v mn="$UID_MIN" -v mx="$UID_MAX" '$3>=mn && $3<=mx && $6!~/^\/home\//{print $1":"$6}' /etc/passwd)"
  have pdbedit && review "Samba user database (pdbedit) - every entry must be an authorized user" "$(pdbedit -L 2>/dev/null)"

  # 4) system accounts with login shells, empty passwords, duplicates
  review "System accounts (UID<$UID_MIN) with a login shell" "$(awk -F: -v mn="$UID_MIN" '$3<mn && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $7!~/(nologin|false)$/ && $7!=""{print $1" -> "$7}' /etc/passwd)"
  while read -r u; do
    in_list "$u" "${PROTECTED[@]}" && continue
    rchange "set nologin shell for system account '$u'" usermod -s "$nologin" "$u"
  done < <(awk -F: -v mn="$UID_MIN" '$3<mn && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $7!~/(nologin|false)$/ && $7!=""{print $1}' /etc/passwd)
  while read -r u; do
    [[ -z "$u" ]] && continue; in_list "$u" "${PROTECTED[@]}" && continue
    uid="$(id -u "$u" 2>/dev/null)"
    if [[ -n "$uid" ]] && (( uid >= UID_MIN )); then info "'$u' has an EMPTY password (fixed by the password step below)"
    else rchange "lock system account '$u' (empty password)" passwd -l "$u"; fi
  done < <(awk -F: '$2==""{print $1}' /etc/shadow)
  review "passwd entries whose password field is not 'x'" "$(awk -F: '$2!="x"{print $1":"$2}' /etc/passwd)"
  review "Duplicate UIDs"  "$(cut -d: -f3 /etc/passwd | sort | uniq -d)"
  review "Duplicate usernames" "$(cut -d: -f1 /etc/passwd | sort | uniq -d)"
  review "Duplicate GIDs / group names" "$( { cut -d: -f3 /etc/group | sort | uniq -d; cut -d: -f1 /etc/group | sort | uniq -d; } )"
  have pwck && review "pwck consistency problems" "$(pwck -r 2>&1 | head -15)"
  have grpck && review "grpck consistency problems" "$(grpck -r 2>&1 | head -15)"

  # 5) passwords
  PW_USERS=()
  while read -r u; do
    in_list "$u" "${PROTECTED[@]}" && continue
    (( ${#AUTH_USERS[@]} )) && ! in_list "$u" "${AUTH_USERS[@]}" && continue
    PW_USERS+=("$u")
  done < <(human_users)
  if (( ${#PW_USERS[@]} )); then
    rchange "set a NEW strong password for ${#PW_USERS[@]} user(s): ${PW_USERS[*]}" pw_apply && (( APPLY )) && info "new password saved (root-only) in $STATE_DIR/new_password.txt"
  fi
  [[ -n "$ME" ]] && info "Your own account '$ME' is never auto-changed: set a strong password for it yourself (passwd $ME) once everything else is done."
  # 6) root account
  rs="$(passwd -S root 2>/dev/null | awk '{print $2}')"
  if [[ "$rs" == P && -n "$(getent group sudo admin wheel | cut -d: -f4 | tr -d ',\n')" ]]; then
    rchange "lock the root password (sudo admins exist; 'sudo -i' still works)" passwd -l root
  fi
}

# =============================================================================
#  MODULE sudoers
# =============================================================================
sudo_edit_safe() { # file sed-expr   (edit a temp copy, validate with visudo, then install)
  local f="$1" ex="$2" t; t="$(mktemp)"; backup "$f"
  sed -E -e "$ex" "$f" >"$t" || { rm -f "$t"; return 1; }
  if visudo -cf "$t" >/dev/null 2>&1; then cat "$t" >"$f"; rm -f "$t"; else rm -f "$t"; return 1; fi
}
sudo_extra_lines() {
  local f
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" && "$f" != */README ]] || continue
    ADM=" ${AUTH_ADMINS[*]} ${PROTECTED[*]} " awk -v F="$f" '
      { s=$0; sub(/^[ \t]+/,"",s) }
      s=="" || substr(s,1,1)=="#" || s ~ /^(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias)/ || s ~ /^@/ {next}
      { split(s,w,/[ \t]+/); t=w[1]
        if (substr(t,1,1)=="%") { g=substr(t,2); if (g=="sudo"||g=="admin"||g=="wheel"||g=="root") next; print F ":" NR ":" s; next }
        if (index(ENVIRON["ADM"]," " t " ")==0) print F ":" NR ":" s }' "$f"
  done
}
mod_sudoers() {
  section "sudo configuration"
  [[ -f /etc/sudoers ]] || { info "sudo not installed"; return; }
  local f n rest t
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" && "$f" != */README ]] || continue
    grep -qE '^[^#]*(NOPASSWD|!authenticate)' "$f" && rchange "sudoers: remove NOPASSWD / !authenticate in $f" sudo_edit_safe "$f" '/^[[:space:]]*Defaults.*!authenticate/d; s/NOPASSWD:[[:space:]]*//g'
  done
  if (( ${#AUTH_ADMINS[@]} )); then
    while IFS=: read -r f n rest; do
      [[ -n "$f" ]] || continue
      rchange "sudoers: comment out entry for non-admin  $f:$n  [$rest]" sudo_edit_safe "$f" "${n}s/^/# cp_disabled: /"
    done < <(sudo_extra_lines)
  else warn "authorized_admins.txt empty -> not checking sudoers entries against it"; fi
  t="$(mktemp)"
  printf '%s\n' 'Defaults use_pty' 'Defaults logfile="/var/log/sudo.log"' 'Defaults !visiblepw' 'Defaults passwd_tries=3' 'Defaults timestamp_timeout=15' >"$t"
  if visudo -cf "$t" >/dev/null 2>&1; then write_file /etc/sudoers.d/99-cp-hardening 440 <"$t"; else warn "sudo Defaults not supported here; skipped"; fi
  rm -f "$t"
  have visudo && review "visudo syntax check problems" "$(visudo -c 2>&1 | grep -viE 'parsed OK|^$')"
}

# =============================================================================
#  MODULE ssh
# =============================================================================
ssh_literal() { K="$1" awk 'BEGIN{k=tolower(ENVIRON["K"])} {s=$0; sub(/^[ \t]+/,"",s); if (substr(s,1,1)=="#") next; split(s,w,/[ \t=]+/)
  if (tolower(w[1])==k) { v=s; sub(/^[^ \t=]+[ \t=]+/,"",v); sub(/[ \t\r]+$/,"",v); print v; exit } }' /etc/ssh/sshd_config; }
_ssh_build() { # outfile
  local keys; keys="$(printf '%s\n' "${SSH_NEED[@]}" | awk '{print tolower($1)}' | paste -sd'|')"
  { echo "# --- cp_harden: enforced settings (sshd uses the FIRST value it sees) ---"; printf '%s\n' "${SSH_NEED[@]}"; echo "# --- end cp_harden ---"
    K="$keys" awk 'BEGIN{n=split(ENVIRON["K"],a,"|"); for(i=1;i<=n;i++) bad[a[i]]=1}
      /^# --- (end )?cp_harden/ {next}
      { s=$0; sub(/^[ \t]+/,"",s); split(s,w,/[ \t=]+/); if (substr(s,1,1)!="#" && (tolower(w[1]) in bad)) next; print }' /etc/ssh/sshd_config
  } >"$1"
}
_ssh_apply() {
  local f=/etc/ssh/sshd_config t attempt x; local -a tmp
  mkdir -p /run/sshd; t="$(mktemp)"
  for attempt in all noproto; do
    if [[ $attempt == noproto ]]; then tmp=(); for x in "${SSH_NEED[@]}"; do [[ $x == Protocol* ]] || tmp+=("$x"); done; SSH_NEED=("${tmp[@]}"); fi
    _ssh_build "$t"
    if "$SSHD" -t -f "$t" >>"$LOG" 2>&1; then
      backup $f; cat "$t" >$f; rm -f "$t"
      svc_active ssh && systemctl reload ssh 2>/dev/null; svc_active sshd && systemctl reload sshd 2>/dev/null
      return 0
    fi
  done
  rm -f "$t"; return 1
}
ssh_verify() { # compare EFFECTIVE config (sshd -T: includes drop-ins and defaults) with WANT (dynamic scope: set in mod_ssh)
  local out w k v e
  out="$("$SSHD" -T 2>/dev/null)" || return 0
  [[ -n "$out" ]] || return 0
  for w in "${WANT[@]}"; do
    k="${w%% *}"; v="${w#* }"; k="${k,,}"
    case "$k" in banner|protocol|ciphers|macs|kexalgorithms) continue;; esac
    e="$(awk -v k="$k" '$1==k{$1="";sub(/^ /,"");print;exit}' <<<"$out")"
    [[ -z "$e" ]] && continue
    [[ "${e,,}" == "${v,,}" ]] && continue
    warn "sshd EFFECTIVE value of $k is '$e' (wanted '$v'): a Match block or drop-in overrides it"
  done
}
mod_ssh() {
  section "SSH server (sshd_config)"
  SSHD="$(command -v sshd || echo /usr/sbin/sshd)"
  [[ -x "$SSHD" && -f /etc/ssh/sshd_config ]] || { info "openssh-server not installed - nothing to harden"; return; }
  local w k v cur
  local -a WANT=( "PermitRootLogin no" "PermitEmptyPasswords no" "Protocol 2" "X11Forwarding no" "MaxAuthTries 4"
    "LoginGraceTime 60" "IgnoreRhosts yes" "HostbasedAuthentication no" "PermitUserEnvironment no"
    "ClientAliveInterval 300" "ClientAliveCountMax 2" "LogLevel VERBOSE" "UsePAM yes" "StrictModes yes"
    "MaxSessions 4" "MaxStartups 10:30:60" "PermitTunnel no" "GatewayPorts no" "Banner /etc/issue.net" "PrintLastLog yes" "UseDNS no" )
  (( AGGRESSIVE )) && WANT+=( "AllowTcpForwarding no" "AllowAgentForwarding no" "Compression no" "TCPKeepAlive no"
    "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256" )
  SSH_NEED=()
  for w in "${WANT[@]}"; do k="${w%% *}"; v="${w#* }"; cur="$(ssh_literal "$k")"; [[ "${cur,,}" == "${v,,}" ]] || SSH_NEED+=("$w"); done
  if (( ${#SSH_NEED[@]} )); then
    info "sshd_config needs ${#SSH_NEED[@]} setting(s): $(printf '%s\n' "${SSH_NEED[@]}" | awk '{print $1}' | paste -sd' ')"
    change "sshd_config: enforce ${#SSH_NEED[@]} hardening setting(s) (validated with sshd -t, then reloaded)" _ssh_apply
  else good "sshd_config already has all enforced settings"; fi
  (( APPLY )) && ssh_verify
  review "sshd_config.d drop-ins that set the same keys (verify they do not weaken the config)" "$(grep -HiE '^[[:space:]]*(PermitRootLogin|PermitEmptyPasswords|PasswordAuthentication|X11Forwarding|UsePAM|AllowUsers|AuthorizedKeysFile)[[:space:]]' /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
  review "sshd: non-default AuthorizedKeysFile / AuthorizedKeysCommand (possible backdoor)" "$(grep -iE '^[[:space:]]*(AuthorizedKeysFile|AuthorizedKeysCommand|ForceCommand|Subsystem)' /etc/ssh/sshd_config | grep -viE 'AuthorizedKeysFile[[:space:]]+(\.ssh/authorized_keys|%h/\.ssh/authorized_keys)([[:space:]]+\.ssh/authorized_keys2)?$|Subsystem[[:space:]]+sftp[[:space:]]+(/usr/lib/openssh/sftp-server|/usr/libexec/openssh/sftp-server)')"
  svc_active ssh || svc_active sshd || info "sshd is not running (fine unless the README requires SSH)"
}

# =============================================================================
#  MODULE services : disable what is not required, keep what is
# =============================================================================
BAD_SVCS=(telnet telnetd inetd xinetd openbsd-inetd vsftpd proftpd pure-ftpd tftpd-hpa smbd nmbd samba samba-ad-dc
  nfs-server nfs-kernel-server rpcbind rpc-statd avahi-daemon cups cups-browsed snmpd isc-dhcp-server isc-dhcp-server6
  slapd bind9 named apache2 nginx lighttpd mysql mariadb postgresql dovecot postfix sendmail exim4 rsh rlogin rexec
  ntalk talk ypserv ypbind xrdp xrdp-sesman x11vnc vncserver tightvncserver vino-server bluetooth squid minidlna
  rsync tor webmin mongod redis-server memcached couchdb elasticsearch tomcat9 tomcat8 jenkins iscsid kerneloops
  ssh sshd teamviewerd anydesk rustdesk saned autofs)

mod_services() {
  section "Services"
  local s t u any report_only=0
  local -a found=()
  if (( ${#REQ_TOKENS[@]} == 0 )); then
    warn "required_services.txt is empty -> unnecessary services are only REPORTED (fill the file from the README to allow disabling)"
    report_only=1
  else info "Required services (never disabled): ${REQ_RAW[*]}"; fi
  for s in "${BAD_SVCS[@]}"; do
    svc_has "$s" || continue
    req_match "$s" && continue
    { svc_active "$s" || svc_enabled "$s"; } && found+=("$s")
  done
  review "Active/enabled services that are not in required_services.txt" "$(printf '%s\n' "${found[@]}")"
  if (( ! report_only )); then
    for s in "${found[@]}"; do rchange "stop + disable service '$s' (+ its socket/path units)" svc_disable "$s"; done
  fi
  for t in "${REQ_RAW[@]}"; do
    any=0
    for u in $(req_units "$t"); do
      svc_has "$u" || continue; any=1
      svc_active "$u"  || change "START required service '$u'" systemctl start "$u"
      svc_enabled "$u" || change "ENABLE required service '$u' at boot" systemctl enable "$u"
    done
    (( any )) || warn "required service '$t' has no systemd unit here (not installed, or different name?)"
  done
  review "Listening sockets (check every unexpected port)" "$(ss -tulpn 2>/dev/null | tail -n +2)"
  review "All enabled service unit files (look for anything odd)" "$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | grep -vE '^(systemd-|getty@|apt-|e2scrub|snap|dbus|console-|keyboard-|multipath|networkd|plymouth|pollinate|ua-|ubuntu-|unattended|grub-|finalrd|cloud-|ssh\.service|cron|rsyslog|ufw|apparmor|NetworkManager|gdm|lightdm|accounts|irqbalance|polkit|udisks|upower|rtkit|wpa_|thermald|power-prof)')"
}

# =============================================================================
#  MODULE svchard : service-specific hardening (only for installed services)
# =============================================================================
apache_noindex() { # rewrite "Options ... Indexes" lines so ALL options carry +/-  (Apache forbids mixing)
  local f="$1" t; t="$(mktemp)"; backup "$f"
  awk '/^[ \t]*Options[ \t]/ && /[ \t+]Indexes([ \t]|$)/ && !/#/ {
         match($0,/^[ \t]*/); out=substr($0,1,RLENGTH) "Options"; n=split($0,w,/[ \t]+/)
         for(i=1;i<=n;i++){ t=w[i]; if(t==""||t=="Options") continue
           if(t=="Indexes"||t=="+Indexes") t="-Indexes"; else if(substr(t,1,1)!="+"&&substr(t,1,1)!="-") t="+" t
           out=out " " t } print out; next } {print}' "$f" >"$t" && cat "$t" >"$f"; rm -f "$t"
}
hard_apache() {
  pkg_installed apache2 || return 0
  info "Apache2 found"
  local cf=/etc/apache2/conf-available/cp-hardening.conf f m
  write_file $cf 644 <<'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
<IfModule mod_headers.c>
  Header always set X-Frame-Options SAMEORIGIN
  Header always set X-Content-Type-Options nosniff
</IfModule>
EOF
  [[ -e /etc/apache2/conf-enabled/cp-hardening.conf ]] || { have a2enconf && change "apache: enable cp-hardening conf" a2enconf cp-hardening; }
  for f in /etc/apache2/apache2.conf /etc/apache2/sites-available/*.conf /etc/apache2/conf-available/*.conf; do
    [[ -f "$f" && "$f" != "$cf" ]] || continue
    grep -qE '^[[:space:]]*Options[[:space:]].*[[:space:]+]Indexes([[:space:]]|$)' "$f" && change "apache: disable directory listing in $f" apache_noindex "$f"
  done
  for m in status info userdir autoindex dav dav_fs; do
    [[ -e /etc/apache2/mods-enabled/$m.load ]] && have a2dismod && change "apache: disable module $m" a2dismod -f "$m"
  done
  if [[ -f /etc/apache2/mods-available/ssl.conf ]]; then
    sed_file "apache: SSLProtocol modern only" /etc/apache2/mods-available/ssl.conf '^[[:space:]]*SSLProtocol' 's/^[[:space:]]*SSLProtocol.*/\tSSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1/'
  fi
  review "Apache: AllowOverride All / world-wide grants (verify)" "$(grep -rnE 'AllowOverride[[:space:]]+All|Require[[:space:]]+all[[:space:]]+granted' /etc/apache2/apache2.conf /etc/apache2/sites-enabled 2>/dev/null | head -10)"
  grep -qE '^[[:space:]]*export APACHE_RUN_USER=root' /etc/apache2/envvars 2>/dev/null && warn "Apache runs as root! fix APACHE_RUN_USER in /etc/apache2/envvars"
  (( APPLY )) && { validate_or_restore "apache2ctl configtest" $cf /etc/apache2/apache2.conf /etc/apache2/mods-available/ssl.conf /etc/apache2/sites-available/*.conf && svc_reload apache2; }
}
hard_nginx() {
  pkg_installed nginx || pkg_installed nginx-core || pkg_installed nginx-light || return 0
  info "nginx found"
  local f=/etc/nginx/nginx.conf s
  [[ -f $f ]] || return 0
  if grep -qE '^[[:space:]]*server_tokens[[:space:]]+on' $f; then sed_file "nginx: server_tokens off" $f 'server_tokens[[:space:]]+on' 's/server_tokens[[:space:]]+on/server_tokens off/'
  elif ! grep -qE '^[[:space:]]*server_tokens[[:space:]]+off' $f; then
    if grep -qE '^[[:space:]]*#[[:space:]]*server_tokens' $f; then sed_file "nginx: enable server_tokens off" $f '^[[:space:]]*#[[:space:]]*server_tokens' 's/^[[:space:]]*#[[:space:]]*server_tokens.*/\tserver_tokens off;/'
    else cf "nginx: add server_tokens off" $f sed -i -e '/^[[:space:]]*http[[:space:]]*{/a\' -e '    server_tokens off;' $f; fi
  fi
  sed_file "nginx: ssl_protocols TLS1.2+" $f '^[[:space:]]*ssl_protocols' 's/^([[:space:]]*)ssl_protocols.*/\1ssl_protocols TLSv1.2 TLSv1.3;/'
  for s in /etc/nginx/sites-available/* /etc/nginx/conf.d/*.conf; do
    [[ -f "$s" ]] && sed_file "nginx: autoindex off in $s" "$s" '^[[:space:]]*autoindex[[:space:]]+on' 's/^([[:space:]]*autoindex)[[:space:]]+on/\1 off/'
  done
  (( APPLY )) && { validate_or_restore "nginx -t" $f /etc/nginx/sites-available/* /etc/nginx/conf.d/*.conf && svc_reload nginx; }
}
hard_php() {
  local ini any=0
  for ini in /etc/php/*/*/php.ini /etc/php.ini; do
    [[ -f "$ini" ]] || continue; any=1
    set_conf "$ini" expose_php Off speq; set_conf "$ini" display_errors Off speq; set_conf "$ini" display_startup_errors Off speq
    set_conf "$ini" log_errors On speq; set_conf "$ini" allow_url_include Off speq; set_conf "$ini" allow_url_fopen Off speq
    set_conf "$ini" cgi.fix_pathinfo 0 speq; set_conf "$ini" session.cookie_httponly 1 speq; set_conf "$ini" session.use_strict_mode 1 speq
    set_conf "$ini" max_execution_time 30 speq
    (( AGGRESSIVE )) && set_conf "$ini" disable_functions "exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source" speq
  done
  (( any )) && { svc_reload apache2; for ini in /etc/php/*/fpm; do [[ -d $ini ]] && svc_reload "php$(basename "$(dirname "$ini")")-fpm"; done; }
  local roots=(/var/www /srv /usr/share/nginx/html) r; local -a rr=()
  for r in "${roots[@]}"; do [[ -d $r ]] && rr+=("$r"); done
  if (( ${#rr[@]} )); then
    review "Possible web shells / backdoors in web roots" "$(grep -rIlE '(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|(shell_exec|passthru|system|exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|c99shell|r57shell|b374k|FilesMan|WSO [0-9]' "${rr[@]}" 2>/dev/null | head -30)"
    review "Risky files in web roots (phpinfo, backups, dumps, .env, .git)" "$(find "${rr[@]}" \( -iname 'phpinfo.php' -o -iname 'info.php' -o -iname 'test.php' -o -iname '*.bak' -o -iname '*.old' -o -iname '*.sql' -o -iname '*.zip' -o -iname '*.tar*' -o -iname '.env' -o -iname '.git' -o -iname '.htpasswd' \) 2>/dev/null | head -30)"
    review "PHP files inside upload directories" "$(find "${rr[@]}" -ipath '*upload*' -iname '*.php' 2>/dev/null | head -20)"
    review "World-writable files/dirs in web roots" "$(find "${rr[@]}" -perm -0002 ! -type l 2>/dev/null | head -20)"
    find "${rr[@]}" -name wp-config.php 2>/dev/null | while read -r f; do
      [[ "$(stat -c %a "$f")" =~ ^(640|600|440|400)$ ]] || change "WordPress: chmod 640 $f" chmod 640 "$f"; done
  fi
}
hard_mysql() {
  { have mysqld || have mariadbd || [[ -d /etc/mysql ]]; } || return 0
  info "MySQL/MariaDB found"
  write_file /etc/mysql/conf.d/zz-cp-hardening.cnf 644 <<'EOF'
[mysqld]
local-infile=0
symbolic-links=0
skip-name-resolve
EOF
  local f
  for f in $(grep -rlE '^[[:space:]]*bind-address' /etc/mysql 2>/dev/null); do
    [[ "$(conf_get "$f" bind-address)" == 127.0.0.1 ]] || { rask "MySQL: bind-address=127.0.0.1 in $f (breaks REMOTE db clients!)" && set_conf "$f" bind-address 127.0.0.1 speq; }
  done
  for f in $(grep -rlE '^[[:space:]]*skip[-_]grant[-_]tables' /etc/mysql 2>/dev/null); do   # starts MySQL with NO authentication
    sed_file "MySQL: disable skip-grant-tables in $f" "$f" '^[[:space:]]*skip[-_]grant[-_]tables' 's/^([[:space:]]*skip[-_]grant[-_]tables.*)$/# cp_disabled: \1/'
  done
  if have mysql && mysql -NBe 'select 1' >/dev/null 2>&1; then
    local u h
    while IFS=$'\t' read -r u h; do
      rchange "MySQL: DROP USER '$u'@'$h' (anonymous / remote root)" mysql -e "DROP USER '$u'@'$h'"
    done < <(mysql -NBe "select user,host from mysql.user where user='' or (user='root' and host not in ('localhost','127.0.0.1','::1'))" 2>/dev/null)
    mysql -NBe "show databases like 'test'" 2>/dev/null | grep -q test && rchange "MySQL: drop sample 'test' database" mysql -e 'DROP DATABASE test'
    review "MySQL accounts with empty password" "$(mysql -NBe "select user,host from mysql.user where (authentication_string='' or authentication_string is null) and plugin not in ('auth_socket','unix_socket')" 2>/dev/null)"
  fi
}
hard_postgres() {
  local f
  for f in /etc/postgresql/*/main/pg_hba.conf; do
    [[ -f "$f" ]] || continue
    review "PostgreSQL 'trust' authentication in $f" "$(grep -nE '^[[:space:]]*(local|host|hostssl|hostnossl)[[:space:]].*[[:space:]]trust' "$f")"
    grep -qE '^[[:space:]]*(local|host).*[[:space:]]trust' "$f" && rchange "PostgreSQL: replace 'trust' with peer/md5 in $f" _pg_fix "$f"
  done
  for f in /etc/postgresql/*/main/postgresql.conf; do
    [[ -f "$f" ]] || continue
    case "$(conf_get "$f" listen_addresses)" in
      *\**|*0.0.0.0*) rask "PostgreSQL: listen_addresses='localhost' in $f (breaks REMOTE db clients!)" && set_conf "$f" listen_addresses "'localhost'" speq;;
    esac
  done
}
_pg_fix() { backup "$1"; sed -i -E -e '/^[[:space:]]*local[[:space:]]/ s/[[:space:]]trust/ peer/' -e '/^[[:space:]]*host/ s/[[:space:]]trust/ md5/' "$1"; svc_reload postgresql; }
hard_ftp() {
  if [[ -f /etc/vsftpd.conf ]]; then
    local k v f=/etc/vsftpd.conf
    for kv in anonymous_enable=NO anon_upload_enable=NO anon_mkdir_write_enable=NO anon_other_write_enable=NO chroot_local_user=YES allow_writeable_chroot=YES xferlog_enable=YES; do
      set_conf $f "${kv%%=*}" "${kv#*=}" eq
    done
    (( APPLY )) && svc_reload vsftpd
  fi
  if [[ -f /etc/proftpd/proftpd.conf ]]; then
    set_conf /etc/proftpd/proftpd.conf RootLogin off; set_conf /etc/proftpd/proftpd.conf UseReverseDNS off
    set_conf /etc/proftpd/proftpd.conf ServerIdent off; set_conf /etc/proftpd/proftpd.conf DefaultRoot '~'
    review "ProFTPD <Anonymous> blocks" "$(grep -n '<Anonymous' /etc/proftpd/proftpd.conf)"
  fi
}
hard_samba() {
  local f=/etc/samba/smb.conf
  [[ -f $f ]] || return 0
  info "Samba found"
  ini_set $f global "restrict anonymous" 2; ini_set $f global "map to guest" Never
  ini_set $f global "min protocol" SMB2; ini_set $f global "null passwords" no; ini_set $f global "usershare allow guests" no
  (( AGGRESSIVE )) && { ini_set $f global "server signing" mandatory; ini_set $f global "client signing" mandatory; }
  sed_file "samba: shares must not allow guests" $f '^[[:space:]]*(guest ok|public|guest only)[[:space:]]*=[[:space:]]*(yes|true|1)' 's/^([[:space:]]*(guest ok|public|guest only))[[:space:]]*=[[:space:]]*(yes|true|1)/\1 = no/I'
  review "Samba share definitions (check paths + permissions)" "$(testparm -s 2>/dev/null | grep -E '^\[|path|writ|read only|guest|valid users' | head -30)"
  (( APPLY )) && { validate_or_restore "testparm -s" $f && svc_reload smbd; }
}
hard_misc_services() {
  local f
  if [[ -f /etc/exports ]]; then
    sed_file "NFS: root_squash instead of no_root_squash" /etc/exports 'no_root_squash' 's/no_root_squash/root_squash/g'
    review "NFS exports open to the world" "$(grep -nE '\*|0\.0\.0\.0|rw' /etc/exports | grep -v '^[0-9]*:#')"
  fi
  if have postconf; then
    local kv
    for kv in disable_vrfy_command=yes smtpd_helo_required=yes 'smtpd_banner=$myhostname ESMTP'; do
      [[ "$(postconf -h "${kv%%=*}" 2>/dev/null)" == "${kv#*=}" ]] || change "postfix: $kv" postconf -e "$kv"
    done
    review "Postfix relay settings (open relay?)" "$(postconf mynetworks smtpd_relay_restrictions inet_interfaces 2>/dev/null)"
  fi
  [[ -f /etc/dovecot/conf.d/10-auth.conf ]] && set_conf /etc/dovecot/conf.d/10-auth.conf disable_plaintext_auth yes speq
  if [[ -f /etc/bind/named.conf.options ]] && ! grep -q 'allow-transfer' /etc/bind/named.conf.options; then
    cf "bind: deny zone transfers" /etc/bind/named.conf.options sed -i -e '/^[[:space:]]*options[[:space:]]*{/a\' -e '\tallow-transfer { none; };' /etc/bind/named.conf.options
    (( APPLY )) && validate_or_restore "named-checkconf" /etc/bind/named.conf.options
  fi
  [[ -f /etc/snmp/snmpd.conf ]] && review "SNMP community strings" "$(grep -nE '^[[:space:]]*(ro|rw)?community|public|private' /etc/snmp/snmpd.conf | grep -v ':#')"
  if [[ -f /etc/cups/cupsd.conf ]]; then
    sed_file "cups: Browsing Off" /etc/cups/cupsd.conf '^Browsing[[:space:]]+(On|Yes)' 's/^Browsing.*/Browsing Off/'
    sed_file "cups: listen on localhost only" /etc/cups/cupsd.conf '^Port[[:space:]]+631' 's/^Port[[:space:]]+631/Listen localhost:631/'
  fi
  [[ -f /etc/redis/redis.conf ]] && { set_conf /etc/redis/redis.conf bind 127.0.0.1; set_conf /etc/redis/redis.conf protected-mode yes; }
  [[ -f /etc/memcached.conf ]]   && set_conf /etc/memcached.conf -l 127.0.0.1
  [[ -f /etc/mongod.conf ]]      && sed_file "mongod: bind to localhost" /etc/mongod.conf 'bindIp:[[:space:]]*0\.0\.0\.0' 's/bindIp:[[:space:]]*0\.0\.0\.0/bindIp: 127.0.0.1/'
  if have docker; then
    review "Docker group members" "$(getent group docker | cut -d: -f4)"
    review "Privileged / host-network containers" "$(docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} priv={{.HostConfig.Privileged}} net={{.HostConfig.NetworkMode}}' 2>/dev/null | grep -E 'priv=true|net=host')"
    review "Docker daemon exposed on TCP" "$(ss -tlnp 2>/dev/null | grep -E ':(2375|2376)\b')"
  fi
}
mod_svchard() {
  section "Service-specific hardening (only for software that is installed)"
  hard_apache; hard_nginx; hard_php; hard_mysql; hard_postgres; hard_ftp; hard_samba; hard_misc_services
}

# =============================================================================
#  MODULE firewall (UFW)
# =============================================================================
# NOTE: databases (mysql/postgres/redis/mongo) are deliberately NOT opened: local clients use loopback,
#       which ufw always allows. If the README needs REMOTE access, add it to config/allow_ports.txt.
ports_for() { case "$1" in
    ssh|sshd|openssh) echo 22/tcp;; apache2|httpd|apache|nginx|lighttpd) echo "80/tcp 443/tcp";;
    vsftpd|proftpd|pure-ftpd|ftp|ftpd) echo "21/tcp";; samba|smbd|nmbd|smb) echo "137/udp 138/udp 139/tcp 445/tcp";;
    bind9|named|dns|bind) echo "53/tcp 53/udp";; postfix|smtp|mail|exim4|sendmail) echo "25/tcp 587/tcp";;
    dovecot|imap|pop3) echo "110/tcp 143/tcp 993/tcp 995/tcp";;
    nfs|nfs-server|nfs-kernel-server) echo "2049/tcp 111/tcp";; tomcat|tomcat8|tomcat9) echo "8080/tcp";;
    ldap|slapd) echo "389/tcp 636/tcp";; xrdp|rdp) echo "3389/tcp";; snmp|snmpd) echo "161/udp";;
    dhcp|isc-dhcp-server) echo "67/udp";; cups) echo "631/tcp";; esac; }
_ufw_rebuild() {
  local p
  ufw --force reset || return 1
  ufw default deny incoming; ufw default allow outgoing; ufw default deny routed 2>/dev/null
  for p in "${FW_PORTS[@]}"; do ufw allow "$p"; done
  ufw logging medium; ufw --force enable; systemctl enable ufw 2>/dev/null; return 0
}
mod_firewall() {
  section "Firewall (UFW)"
  local t p st unexpected defaults_ok=0
  FW_PORTS=()
  for t in "${REQ_RAW[@]}"; do for p in $(ports_for "${t,,}"); do in_list "$p" "${FW_PORTS[@]}" || FW_PORTS+=("$p"); done; done
  (( ${#REQ_RAW[@]} == 0 )) && { svc_active ssh || svc_active sshd; } && FW_PORTS+=(22/tcp)
  for p in "${EXTRA_PORTS[@]}"; do FW_PORTS+=("$p"); done
  info "Ports that will be allowed: ${FW_PORTS[*]:-none}"
  if ! have ufw; then
    (( DEBFAM )) && change "install ufw" pkg_install ufw
    have ufw || { (( APPLY )) && warn "ufw not available"; return; }
  fi
  set_conf /etc/default/ufw IPV6 yes eq
  if have ufw; then
    st="$(ufw status verbose 2>/dev/null)"
    grep -qi 'Default: deny (incoming)' <<<"$st" && defaults_ok=1
    unexpected="$(ufw status 2>/dev/null | awk '/ALLOW|LIMIT/{print $1}' | sed 's#/\(tcp\|udp\)$##' | sort -u | while read -r x; do
        ok=0; for p in "${FW_PORTS[@]}"; do [[ "${p%%/*}" == "$x" ]] && ok=1; done; [[ "$x" == "Anywhere" || $ok == 0 ]] && echo "$x"; done)"
    if grep -q '^Status: active' <<<"$st" && (( defaults_ok )) && [[ -z "$unexpected" ]]; then good "ufw active, default deny incoming, rules match requirements"
    else
      review "ufw rules that do not match required services" "$unexpected"
      rchange "REBUILD firewall: reset, deny incoming, allow outgoing, allow only [${FW_PORTS[*]}], enable" _ufw_rebuild
    fi
  else rchange "REBUILD firewall (ufw) allowing [${FW_PORTS[*]}]" _ufw_rebuild; fi
  have iptables && review "Raw iptables rules not managed by ufw (verify)" "$(iptables -S 2>/dev/null | grep -vE '^-P|^-N|ufw|f2b-|DOCKER' | head -15)"
  review "/etc/hosts.allow, hosts.deny active lines" "$(grep -vhE '^[[:space:]]*(#|$)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null)"
}

# =============================================================================
#  MODULE software : prohibited packages, held packages, snaps, odd binaries
# =============================================================================
DEFAULT_PROHIBITED=(
  john john-data hydra hydra-gtk thc-hydra medusa ophcrack ophcrack-cli crack crack-common hashcat fcrackzip pdfcrack rarcrack lcrack cewl crunch
  ncrack rainbowcrack chntpw cmospwd patator wfuzz gobuster dirb dirbuster wapiti skipfish w3af weevely sslscan
  aircrack-ng wifite reaver pixiewps kismet nikto sqlmap 'metasploit*' beef-xss burpsuite zaproxy
  nmap zenmap ncat netcat netcat-openbsd netcat-traditional ettercap-common ettercap-graphical ettercap-text-only dsniff driftnet
  arp-scan nbtscan netdiscover proxychains proxychains4 bettercap yersinia tcpflow cryptcat
  macchanger wireshark wireshark-common wireshark-qt tshark hping3 masscan zmap logkeys
  transmission-gtk transmission-common transmission-cli transmission-qt deluge deluge-gtk qbittorrent vuze frostwire amule ktorrent rtorrent nicotine gtk-gnutella
  aisleriot gnome-mahjongg gnome-mines gnome-sudoku gnome-nibbles gnome-robots gnome-tetravex gnome-taquin gnome-klotski gnome-chess
  gnome-2048 quadrapassel iagno lightsoff swell-foop five-or-more four-in-a-row hitori tali atomix kmahjongg kmines 'freeciv*' 'wesnoth*'
  'supertux*' frozen-bubble 'minetest*' 'nethack*' 'openarena*' warzone2100 0ad 'xonotic*' 'tuxracer*' gnuchess xboard pingus bsdgames
  'steam*' lutris playonlinux neverball neverputt armagetronad hedgewars widelands sauerbraten extremetuxracer kpat ksudoku
  telnet telnetd inetutils-telnetd rsh-client rsh-server rsh-redone-client rsh-redone-server talk talkd ntalk tftp tftpd tftpd-hpa
  xinetd openbsd-inetd inetutils-inetd nis ypserv ypbind x11vnc tightvncserver vino xrdp tor pumpa teamviewer anydesk rustdesk
)
SERVER_PKGS=(vsftpd proftpd-basic proftpd-core pure-ftpd samba apache2 nginx bind9 isc-dhcp-server snmpd slapd dovecot-core postfix exim4-base sendmail squid nfs-kernel-server)
HACK_BINS=(nc ncat netcat nmap john hydra hashcat medusa ophcrack aircrack-ng sqlmap nikto msfconsole msfvenom ettercap dsniff wifite reaver cewl crunch hping3 masscan zmap socat logkeys keylogger)
PROTECTED_PKG_RE='^(ubuntu-desktop.*|ubuntu-minimal|ubuntu-standard|ubuntu-server|linuxmint.*|mint-meta.*|cinnamon.*|mate-desktop.*|gnome-shell|gdm3|lightdm.*|xorg|xserver-xorg.*|sudo|systemd.*|libpam.*|login|passwd|apt|dpkg|bash|coreutils|network-manager|openssh-server|openssh-client|ufw|linux-image.*|linux-generic.*|grub.*|firefox|libc6|python3|python3-minimal|snapd|ubuntu-session|gnome-session.*)$'
INSTALLED_PKGS=()

match_pkgs() { local p pat; for p in "${INSTALLED_PKGS[@]}"; do for pat in "$@"; do [[ "$p" == $pat ]] && { echo "$p"; break; }; done; done; }
purge_ok() {  # simulate; refuse if it would drag out a protected/required package
  local p="$1" r x
  [[ $PM == apt ]] || return 0
  r="$(apt-get -s purge "$p" 2>/dev/null | awk '/^(Remv|Purg) /{print $2}')"
  [[ -n "$r" ]] || return 1
  while read -r x; do [[ "$x" =~ $PROTECTED_PKG_RE ]] && return 1; pkg_is_required "$x" && return 1; done <<<"$r"
  return 0
}
purge_flow() { # title pkgs...
  local title="$1" p; shift
  local -a ok=()
  (( $# )) || return 0
  review "$title" "$(printf '%s\n' "$@")"
  for p in "$@"; do
    if purge_ok "$p"; then ok+=("$p"); else warn "NOT purging '$p': it is required, or removing it would also remove protected packages"; fi
  done
  (( ${#ok[@]} )) && rchange "PURGE ${#ok[@]} package(s): ${ok[*]}" pkg_purge "${ok[@]}"
}
rask() { # risky prompt without a command (apply mode only)
  local d="$1"
  if (( APPLY )); then confirm "$d" && return 0; N_SKIP=$((N_SKIP+1)); printf '%s[SKIP]%s %s\n' "$B" "$N" "$d"; return 1
  else N_WOULD=$((N_WOULD+1)); printf '%s[WOULD*]%s %s %s(will ask first)%s\n' "$Y" "$N" "$d" "$B" "$N"; return 1; fi
}

mod_software() {
  section "Software: prohibited / unauthorized / held / odd binaries"
  [[ $PM == none ]] && { warn "no supported package manager"; return; }
  local p s f
  local -a hits1 hits2 hits3
  mapfile -t INSTALLED_PKGS < <(pkg_list)
  info "${#INSTALLED_PKGS[@]} packages installed"
  # 1) from config (README-derived) - strongest signal
  if (( ${#PROHIB_CFG[@]} )); then
    mapfile -t hits1 < <(match_pkgs "${PROHIB_CFG[@]}" | while read -r p; do pkg_is_required "$p" || echo "$p"; done)
    purge_flow "Packages from config/prohibited_packages.txt" "${hits1[@]}"
  fi
  # 2) built-in hacking tools / games / p2p / legacy network daemons
  mapfile -t hits2 < <(match_pkgs "${DEFAULT_PROHIBITED[@]}" | while read -r p; do pkg_is_required "$p" || in_list "$p" "${hits1[@]}" || echo "$p"; done)
  purge_flow "Built-in list: hacking tools, games, p2p, legacy daemons (verify README does not allow them)" "${hits2[@]}"
  # 3) unneeded servers (only when we know the required list)
  if (( AGGRESSIVE && ${#REQ_TOKENS[@]} )); then
    mapfile -t hits3 < <(match_pkgs "${SERVER_PKGS[@]}" | while read -r p; do pkg_is_required "$p" || echo "$p"; done)
    purge_flow "Server packages NOT in required_services.txt" "${hits3[@]}"
  fi
  # snaps / flatpaks / pip
  if have snap; then
    s="$(snap list 2>/dev/null | awk 'NR>1{print $1}' | grep -iE '^(nmap|wireshark|john.*|hashcat|netcat|hydra|sqlmap|metasploit.*|aircrack.*|zaproxy|burp.*|ettercap.*|nikto|steam.*|transmission|deluge|qbittorrent)$')"
    for p in $s; do pkg_is_required "$p" || rchange "snap remove $p" snap remove "$p"; done
  fi
  have flatpak && review "Flatpak apps installed" "$(flatpak list --app 2>/dev/null)"
  have pip3 && review "pip packages that look like attack tools" "$(pip3 list 2>/dev/null | grep -iE 'impacket|sqlmap|scapy|pwntools|paramiko|crackmapexec|hashcat|mitmproxy')"
  # held packages (a classic planted vulnerability) / unauthenticated apt
  if have apt-mark; then
    s="$(apt-mark showhold 2>/dev/null)"; review "Packages on HOLD (blocks security updates)" "$s"
    for p in $s; do rchange "unhold package $p" apt-mark unhold "$p"; done
    review "Manually installed packages (apt-mark showmanual, last 60) - look for odd names" "$(apt-mark showmanual 2>/dev/null | tail -60)"
  fi
  review "APT: unauthenticated/insecure repository options" "$(grep -rnEi 'AllowUnauthenticated[[:space:]]+"?true|AllowInsecureRepositories|AllowDowngradeToInsecure|Verify-Peer[[:space:]]+"?false|trusted=yes' /etc/apt 2>/dev/null)"
  for f in $(grep -rlEi 'AllowUnauthenticated[[:space:]]+"?true|AllowInsecureRepositories|AllowDowngradeToInsecure|Verify-Peer[[:space:]]+"?false' /etc/apt/apt.conf /etc/apt/apt.conf.d 2>/dev/null); do
    cf "apt: turn insecure option off in $f" "$f" sed -i -E -e '/(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|Verify-Peer)/ s/"?(true|1)"?/"false"/I' "$f"
  done
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
    [[ -f "$f" ]] && grep -qE 'trusted=yes' "$f" && sed_file "apt: drop [trusted=yes] in $f" "$f" 'trusted=yes' 's/[[:space:]]*trusted=yes//g'
  done
  review "APT sources that are not official mirrors (PPAs / odd hosts)" "$(grep -rhE '^(deb|URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -vE '(archive|security|ports|[a-z]{2}\.archive)\.ubuntu\.com|deb\.debian\.org|security\.debian\.org|packages\.linuxmint\.com|mirrors\.|\.edu|download\.docker\.com|packages\.microsoft')"
  review "APT proxy / odd config" "$(grep -rnE 'Acquire::.*(Proxy|proxy)|Pre-Invoke|Post-Invoke' /etc/apt/apt.conf /etc/apt/apt.conf.d 2>/dev/null | grep -vE 'update-notifier|packagekit|docker-clean')"
  # manually installed attack tools
  local -a ne=(); local first=1 b
  for b in "${HACK_BINS[@]}"; do (( first )) || ne+=(-o); ne+=(-iname "$b"); first=0; done
  find /usr/local /opt /home /root /srv /tmp /var/tmp /usr/games /mnt /media -xdev \( -path /opt/CyberPatriot -o -path "$STATE_DIR" -o -path "$SELF_DIR" -o -path '/root/cp_harden_*' -o -path '*/.cache' -o -path '*/snap' \) -prune -o -type f \( "${ne[@]}" \) -print 2>/dev/null >"$REPORT_DIR/hack_bins.txt"
  if [[ -s "$REPORT_DIR/hack_bins.txt" ]]; then
    review "Manually installed attack-tool binaries" "$(cat "$REPORT_DIR/hack_bins.txt")"
    rchange "quarantine $(wc -l <"$REPORT_DIR/hack_bins.txt") attack-tool binaries" quarantine_list "$REPORT_DIR/hack_bins.txt"
  fi
}

# =============================================================================
#  MODULE files : media, suspicious files, credentials, hidden files
# =============================================================================
MEDIA_EXT=(mp3 mp4 m4a m4v mkv avi mov wmv flv ogg ogv oga opus wav flac aac wma webm mpg mpeg 3gp aiff aif mid midi swf)
IMG_EXT=(jpg jpeg png gif bmp tif tiff webp)
SCAN_ROOTS=(/home /root /opt /srv /tmp /var/tmp /var/www /var/backups /var/ftp /usr/local /mnt /media /usr/games)
quarantine() { local f="$1" d; [[ -e "$f" ]] || return 0; [[ "$f" =~ ^/opt/CyberPatriot ]] && return 0
  d="$QUAR_DIR$f"; mkdir -p "$(dirname "$d")" && mv -- "$f" "$d" && undo "mv '$d' '$f'"; }
quarantine_list() { local f; while IFS= read -r f; do quarantine "$f"; done <"$1"; }
build_iname() { IEXPR=(); local e; for e in "$@"; do (( ${#IEXPR[@]} )) && IEXPR+=(-o); IEXPR+=(-iname "*.$e"); done; }
find_files() { # find expression pieces...   (never descends into libs, caches, this toolkit or its state dir)
  local -a roots=() pr=(); local r
  for r in "${SCAN_ROOTS[@]}"; do [[ -d $r ]] && roots+=("$r"); done
  (( ${#roots[@]} )) || return 0
  pr=( -path /opt/CyberPatriot -o -path "$STATE_DIR" -o -path "$SELF_DIR" -o -path "$CONFIG_DIR" -o -path '/root/cp_harden_*'
       -o -path '*/.cache' -o -path '*/.mozilla' -o -path '*/snap' -o -path '*/node_modules' -o -path '*/site-packages' -o -path '*/dist-packages'
       -o -path '/usr/local/lib' -o -path '/usr/local/share' -o -path '/usr/local/include' -o -path '/opt/pipx' -o -path '*/.local/lib'
       -o -path '*/.config/google-chrome' -o -path '*/.config/chromium' -o -path '*/.local/share/gvfs-metadata' )
  find "${roots[@]}" \( "${pr[@]}" \) -prune -o -type f \( "$@" \) -print 2>/dev/null
}
mod_files() {
  section "Files: prohibited media, suspicious files, credentials"
  local list="$REPORT_DIR/media_files.txt" n
  build_iname "${MEDIA_EXT[@]}"; (( INCLUDE_IMAGES )) && { IEXPR+=(-o); local -a keep=("${IEXPR[@]}"); build_iname "${IMG_EXT[@]}"; IEXPR=("${keep[@]}" "${IEXPR[@]}"); }
  find_files "${IEXPR[@]}" | sort >"$list"
  # media hidden behind other extensions (detect by content)
  if have file && slow_ok; then
    find_files -size +100k ! -iname '*.so*' ! -iname '*.deb' ! -iname '*.iso' ! -iname '*.img' ! -iname '*.json' ! -iname '*.db' 2>/dev/null |
      grep -viE '\.(mp3|mp4|m4a|m4v|mkv|avi|mov|wmv|flv|ogg|ogv|oga|opus|wav|flac|aac|wma|webm|mpg|mpeg|3gp|aiff|aif|mid|midi|swf)$' |
      head -2000 | xargs -d '\n' -r file --mime-type 2>/dev/null | grep -E ': (audio|video)/' | sed 's/: [a-z]*\/.*$//' >>"$list"
    sort -u "$list" -o "$list"
  fi
  n=$(wc -l <"$list")
  if (( n )); then
    review "Media files found ($n) - audio/video are prohibited in most rounds (check README!)" "$(cat "$list")"
    rask "move $n media files to quarantine ($QUAR_DIR, reversible)" && change "quarantine $n media files" quarantine_list "$list"
  else good "no audio/video files found"; fi

  build_iname torrent pcap pcapng cap hccap hccapx pot lst dic
  review "Hash/capture/wordlist/torrent files" "$(find_files "${IEXPR[@]}")"
  review "Files with suspicious names (passwords, cracking, exploits, backdoors)" "$(find_files -iname '*password*' -o -iname '*passwd*' -o -iname '*credential*' -o -iname '*rockyou*' -o -iname '*crack*' -o -iname '*exploit*' -o -iname '*backdoor*' -o -iname '*keylog*' -o -iname '*shadow*' -o -iname '*.kdbx' -o -iname 'id_rsa*' | grep -v '/\.ssh/.*\.pub$' | head -40)"
  build_iname zip tar gz tgz bz2 xz rar 7z
  review "Archives in user/tmp areas (may hide tools or loot)" "$(find_files "${IEXPR[@]}" | head -30)"
  build_iname sh py pl rb php exe bat deb appimage run jar
  review "Scripts / executables / installers in home dirs and temp (look for backdoors)" "$(find_files "${IEXPR[@]}" | grep -E '^/(home|root|tmp|var/tmp|opt|srv)/' | head -40)"
  slow_ok && review "Files containing plaintext passwords (home, www, srv)" "$(grep -rIlEi '(password|passwd|pwd|secret)[[:space:]]*[:=][[:space:]]*[^[:space:]]+' /home /root /var/www /srv 2>/dev/null | grep -vE "/\.(cache|mozilla|config|local)/|^$SELF_DIR|^$STATE_DIR|^/root/cp_harden_" | head -25)"
  review "Hidden executables in home/tmp" "$(find /home /root /tmp /var/tmp /dev/shm -type f -name '.*' -perm /111 2>/dev/null | grep -v '/\.\(cache\|config\|local\|mozilla\)/' | grep -v "^$STATE_DIR\|^/root/cp_harden_" | head -20)"
  review "Hidden dirs/files in / and /tmp" "$(find / -maxdepth 1 -name '.*' ! -name '.' 2>/dev/null; find /tmp /var/tmp /dev/shm -maxdepth 2 -name '.*' ! -name '.' ! -name '..' 2>/dev/null | grep -vE '/\.(X11-unix|ICE-unix|font-unix|XIM-unix|Test-unix|X0-lock|X1-lock)$')"
  slow_ok && review "Files with no owner/group (-nouser/-nogroup)" "$(find / -xdev \( -path /proc -o -path /sys \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -20)"
  slow_ok && review "Very large files (>200MB)" "$(find / -xdev \( -path /proc -o -path /sys -o -path /var/lib/snapd -o -path /snap \) -prune -o -type f -size +200M -print 2>/dev/null | head -10)"
  review "User dotfiles that should not exist (.rhosts .netrc .forward hosts.equiv)" "$(find /home /root -maxdepth 2 \( -name .rhosts -o -name .netrc -o -name .forward -o -name .shosts \) 2>/dev/null; ls /etc/hosts.equiv /etc/shosts.equiv 2>/dev/null)"
  local rl="$REPORT_DIR/rhosts.txt"
  { find /home /root -maxdepth 2 \( -name .rhosts -o -name .shosts -o -name .netrc \) 2>/dev/null; ls /etc/hosts.equiv /etc/shosts.equiv 2>/dev/null; } >"$rl"
  [[ -s "$rl" ]] && rchange "quarantine $(wc -l <"$rl") r-command/credential dotfiles" quarantine_list "$rl"
}

# =============================================================================
#  MODULE perms : critical file permissions, SUID/SGID, world-writable, caps, ACLs
# =============================================================================
fix_mode() { # file mode [owner:group]
  local f="$1" m="$2" og="${3:-}" cur co
  [[ -e "$f" && ! -L "$f" ]] || return 0
  cur="$(stat -c %a "$f")"; co="$(stat -c %U:%G "$f")"
  if [[ "$cur" != "$m" && "${cur#0}" != "${m#0}" ]]; then
    (( APPLY )) && undo "chmod $cur '$f'"
    change "chmod $m $f (was $cur)" chmod "$m" "$f"
  fi
  if [[ -n "$og" && "$co" != "$og" ]] && getent group "${og#*:}" >/dev/null; then
    (( APPLY )) && undo "chown $co '$f'"
    change "chown $og $f (was $co)" chown "$og" "$f"
  fi
}
DANGEROUS_SUID=(find vim vi vim.basic vim.tiny nano nmap bash sh dash zsh python python2 python3 perl ruby awk gawk mawk less more cp mv env nice nohup ionice tar zip unzip strace gdb php node lua tclsh docker date base64 xxd cat head tail dd tee wget curl nc ncat netcat socat openssl systemctl rsync tcpdump)
mod_perms() {
  section "Permissions, SUID/SGID, world-writable, capabilities, ACLs"
  local f u h m sg=shadow d b cap l
  getent group shadow >/dev/null || sg=root
  fix_mode /etc/passwd 644 root:root; fix_mode /etc/group 644 root:root; fix_mode "/etc/passwd-" 600; fix_mode "/etc/group-" 600
  fix_mode /etc/shadow 640 "root:$sg"; fix_mode "/etc/shadow-" 640 "root:$sg"; fix_mode /etc/gshadow 640 "root:$sg"; fix_mode "/etc/gshadow-" 640 "root:$sg"
  fix_mode /etc/sudoers 440 root:root; [[ -d /etc/sudoers.d ]] && { fix_mode /etc/sudoers.d 750 root:root; for f in /etc/sudoers.d/*; do fix_mode "$f" 440 root:root; done; }
  fix_mode /etc/ssh/sshd_config 600 root:root
  for f in /etc/ssh/ssh_host_*_key; do fix_mode "$f" 600 root:root; done; for f in /etc/ssh/ssh_host_*_key.pub; do fix_mode "$f" 644 root:root; done
  fix_mode /etc/crontab 600 root:root; for f in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do fix_mode $f 700 root:root; done
  for f in /etc/hosts /etc/hosts.allow /etc/hosts.deny /etc/fstab /etc/issue /etc/issue.net /etc/motd; do fix_mode $f 644 root:root; done
  fix_mode /boot/grub/grub.cfg 400 root:root; fix_mode /boot/grub2/grub.cfg 400 root:root; fix_mode /root 700
  fix_mode /tmp 1777; fix_mode /var/tmp 1777
  [[ -d /var/log ]] && { local wl; wl="$(find /var/log -type f -perm -0002 2>/dev/null)"; [[ -n "$wl" ]] && rchange "remove world-write from $(echo "$wl" | wc -l) log files" xargs -d '\n' chmod o-w <<<"$wl"; }
  # home directories + ssh dirs
  while IFS=: read -r u _ uid _ _ h _; do
    (( uid >= UID_MIN && uid <= UID_MAX )) && [[ -d "$h" && "$h" != / ]] || continue
    m="$(stat -c %a "$h")"; [[ "$m" =~ ^(700|750|710|550|500)$ ]] || rchange "chmod 750 $h (was $m)" chmod 750 "$h"
    [[ -d "$h/.ssh" ]] && { fix_mode "$h/.ssh" 700; for f in "$h"/.ssh/id_* ; do [[ "$f" == *.pub ]] || fix_mode "$f" 600; done; fix_mode "$h/.ssh/authorized_keys" 600; }
  done </etc/passwd
  # world-writable files / dirs without sticky bit, on local disk filesystems
  local mp wf="$REPORT_DIR/world_writable_files.txt" wd="$REPORT_DIR/world_writable_dirs.txt"; : >"$wf"; : >"$wd"
  while read -r mp; do
    find "$mp" -xdev \( -path /proc -o -path /sys -o -path /opt/CyberPatriot -o -path /var/lib/docker -o -path /snap \) -prune -o -type f -perm -0002 -print 2>/dev/null >>"$wf"
    find "$mp" -xdev \( -path /proc -o -path /sys -o -path /opt/CyberPatriot -o -path /var/lib/docker -o -path /snap \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null >>"$wd"
  done < <(df --local -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR>1{print $6}')
  [[ -s "$wf" ]] && { review "World-writable FILES" "$(cat "$wf")"; rchange "remove world-write bit from $(wc -l <"$wf") files" _chmod_list o-w "$wf"; }
  [[ -s "$wd" ]] && { review "World-writable DIRECTORIES without sticky bit" "$(cat "$wd")"; rchange "set sticky bit on $(wc -l <"$wd") world-writable dirs" _chmod_list +t "$wd"; }
  # SUID / SGID
  local su="$REPORT_DIR/suid_sgid_all.txt" sd="$REPORT_DIR/suid_dangerous.txt"; : >"$su"; : >"$sd"
  while read -r mp; do find "$mp" -xdev \( -path /proc -o -path /sys -o -path /snap -o -path /opt/CyberPatriot \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null >>"$su"; done \
     < <(df --local -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR>1{print $6}')
  while read -r f; do b="$(basename "$f")"
    if in_list "$b" "${DANGEROUS_SUID[@]}" || [[ "$f" =~ ^/(home|tmp|var/tmp|opt|usr/local|srv|mnt|media|dev/shm|root)/ ]]; then echo "$f" >>"$sd"; fi
  done <"$su"
  info "$(wc -l <"$su") SUID/SGID files (full list: $su)"
  [[ -s "$sd" ]] && { review "Dangerous / misplaced SUID-SGID binaries (GTFOBins-style)" "$(while read -r f; do echo "$(stat -c '%a %U' "$f") $f"; done <"$sd")"; rchange "remove SUID/SGID bit from $(wc -l <"$sd") dangerous binaries" _chmod_list u-s,g-s "$sd"; }
  # capabilities
  if have getcap; then
    cap="$(getcap -r / 2>/dev/null | grep -vE '^/(proc|sys|snap|opt/CyberPatriot)')"
    review "Files with Linux capabilities (cap_setuid/dac_override/sys_admin = privilege escalation)" "$cap"
    grep -E 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_module|sys_ptrace)' <<<"$cap" | awk '{print $1}' >"$REPORT_DIR/caps_bad.txt"
    [[ -s "$REPORT_DIR/caps_bad.txt" ]] && rchange "remove dangerous capabilities from $(wc -l <"$REPORT_DIR/caps_bad.txt") files" _setcap_clear "$REPORT_DIR/caps_bad.txt"
  fi
  # immutable / append-only attributes (used to protect planted files)
  if have lsattr && slow_ok; then
    local imm="$REPORT_DIR/immutable.txt"
    lsattr -R /etc /home /root /var/www /usr/local /opt /srv /tmp /usr/bin /usr/sbin 2>/dev/null | awk 'NF==2 && ($1 ~ /i/ || $1 ~ /a/){print $2}' | grep -v '^/opt/CyberPatriot' >"$imm"
    [[ -s "$imm" ]] && { review "Files with immutable/append-only flag (chattr +i/+a) - often planted" "$(cat "$imm")"; rchange "remove immutable flag from $(wc -l <"$imm") files" _chattr_clear "$imm"; }
  fi
  # extended ACLs (chmod looks fine but an ACL can still grant a user access)
  if have getfacl && slow_ok; then
    local acl="$REPORT_DIR/acl_files.txt"
    getfacl -R -s -p /etc /root /home /var/www /srv /opt /usr/local 2>/dev/null | awk '/^# file: /{sub(/^# file: /,""); print}' | grep -v '^/opt/CyberPatriot' >"$acl"
    if [[ -s "$acl" ]]; then
      review "Files/dirs with EXTENDED ACLs (getfacl) - verify who they grant access to" "$(head -40 "$acl")"
      have setfacl && rchange "remove extended ACLs from $(wc -l <"$acl") files" _acl_strip "$acl"
    fi
  fi
}
_chmod_list()  { local mode="$1" l="$2" f; while IFS= read -r f; do [[ -e "$f" ]] && { undo "chmod $(stat -c %a "$f") '$f'"; chmod "$mode" "$f"; }; done <"$l"; }
_setcap_clear(){ local f; while IFS= read -r f; do undo "# setcap was removed from $f: $(getcap "$f")"; setcap -r "$f"; done <"$1"; }
_chattr_clear(){ local f; while IFS= read -r f; do chattr -i -a "$f" 2>/dev/null; done <"$1"; }
_acl_strip()   { local f; while IFS= read -r f; do [[ -e "$f" ]] || continue; undo "# ACL removed from $f was: $(getfacl -c -p "$f" 2>/dev/null | tr '\n' ' ')"; setfacl -b "$f"; done <"$1"; }

# =============================================================================
#  MODULE persistence : cron, timers, rc scripts, profiles, preload, PAM, keys...
# =============================================================================
PERSIST_RE='(nc |ncat|netcat|socat|/dev/tcp|bash -i|sh -i|mkfifo|curl |wget |python[23]? -c|perl -e|php -r|base64|chmod [0-7]*[+]?s|chmod \+s|/tmp/|/dev/shm|nohup|LD_PRELOAD|insmod|authorized_keys)'
unowned_files() { # dirs... -> regular files not owned by any package (handles the /lib -> /usr/lib merge)
  local f r; find "$@" -type f 2>/dev/null | while read -r f; do
    r="$(readlink -f "$f")"; dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "$r" >/dev/null 2>&1 || echo "$f"; done; }
_cron_clean() { local f="$1"; backup "$f"; sed -i -E -e '/^[[:space:]]*#/b' -e "\\#$PERSIST_RE# s/^/# cp_disabled: /" "$f"; }
_ucron_clean() { # comment out suspicious lines of one user's crontab (original saved + undo line)
  local u="$1" t bk="$BACKUP_DIR/crontab_$1.txt" rc
  crontab -l -u "$u" >"$bk" 2>/dev/null || return 1
  undo "crontab -u '$u' '$bk'   # restore crontab of $u"
  t="$(mktemp)"; sed -E -e '/^[[:space:]]*#/b' -e "\\#$PERSIST_RE# s/^/# cp_disabled: /" "$bk" >"$t" && crontab -u "$u" "$t"; rc=$?
  rm -f "$t"; return $rc
}
# /etc/hosts: keep loopback lines that only name localhost/this host; everything else is suspicious (redirected domains)
HOSTS_AWK='/^[[:space:]]*#/ || NF==0 {if(!bad)print; next}
 { ok=1; for(i=2;i<=NF;i++){ if ($i ~ /^#/) break
     if (!($i ~ /^(localhost(\.localdomain)?|ip6-[a-z0-9-]+)$/ || $i==hn || index($i,hn".")==1)) ok=0 }
   if ($1 ~ /^(127\.|::1$|ff0|fe00|::)/ && ok) { if(!bad)print } else { if(bad) print; else print "# cp_disabled: " $0 } }'
_hosts_clean() { local t hn; hn="$(hostname)"; backup /etc/hosts; t="$(mktemp)"; awk -v hn="$hn" -v bad=0 "$HOSTS_AWK" /etc/hosts >"$t" && cat "$t" >/etc/hosts; rm -f "$t"; }
mod_persistence() {
  section "Persistence & backdoor hunting (cron/hosts/PAM/tmp-processes are fixed; the rest is REPORT-ONLY)"
  local u f out p pid cmd ex hn
  out="$( { for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do [[ -f $f ]] && grep -HvE '^[[:space:]]*(#|$)' "$f"; done; } 2>/dev/null | grep -E "$PERSIST_RE")"
  review "System cron entries with suspicious patterns" "$out"
  for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [[ -f "$f" ]] && grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | grep -qE "$PERSIST_RE" && rchange "cron: comment out suspicious lines in $f" _cron_clean "$f"
  done
  out="$(for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | sed "s/^/$u: /"; done)"
  review "ALL user crontabs (any entry here deserves a look)" "$out"
  for u in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | grep -qE "$PERSIST_RE" && rchange "cron: comment out suspicious lines in the crontab of '$u'" _ucron_clean "$u"
  done
  slow_ok && review "Cron/at/init/systemd/profile files NOT owned by any package" "$(unowned_files /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/init.d /etc/systemd/system /etc/xdg/autostart /etc/profile.d /etc/update-motd.d /etc/NetworkManager/dispatcher.d /etc/network/if-up.d /etc/network/if-down.d /etc/network/if-pre-up.d /etc/network/if-post-down.d 2>/dev/null | grep -vE '/(\.placeholder|README)$' | head -40)"
  review "at jobs" "$(atq 2>/dev/null)"
  review "systemd timers" "$(systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $(NF-1), $NF}' | head -20)"
  review "systemd units with suspicious ExecStart" "$(grep -rHE "ExecStart.*$PERSIST_RE" /etc/systemd/system 2>/dev/null | head -15)"
  review "User-level systemd units / lingering users" "$(find /home /root -path '*/.config/systemd/user/*' -type f 2>/dev/null; ls /var/lib/systemd/linger 2>/dev/null)"
  [[ -f /etc/rc.local ]] && review "/etc/rc.local commands" "$(grep -vE '^[[:space:]]*(#|$|exit 0)' /etc/rc.local)"
  review "Shell startup files with suspicious content" "$(grep -nE "$PERSIST_RE|alias [a-z]+=.*(sudo|ssh|su|passwd|rm|ls|cat)" /etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/* /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_login /home/*/.bash_logout /home/*/.zshrc /home/*/.xprofile /home/*/.xsessionrc /home/*/.xinitrc /root/.bashrc /root/.profile 2>/dev/null | grep -vE "alias (ls|ll|la|l|grep|egrep|fgrep|alert|dir|vdir)=" | head -30)"
  review "/etc/environment: proxy / LD_ / PATH tampering" "$(grep -vE '^[[:space:]]*(#|$)' /etc/environment 2>/dev/null | grep -iE 'proxy|LD_|PATH=.*(^|[:="])(\.|/tmp|/home)')"
  review "Per-user autostart entries" "$(find /home /root -path '*/.config/autostart/*' -type f 2>/dev/null)"
  if [[ -s /etc/ld.so.preload ]]; then review "/etc/ld.so.preload is NON-EMPTY (library injection)" "$(cat /etc/ld.so.preload)"; echo /etc/ld.so.preload >"$REPORT_DIR/preload.txt"; rchange "quarantine /etc/ld.so.preload" quarantine_list "$REPORT_DIR/preload.txt"; fi
  review "Processes started with LD_PRELOAD" "$(grep -l LD_PRELOAD /proc/[0-9]*/environ 2>/dev/null | head)"
  slow_ok && review "ld.so.conf.d files not owned by a package" "$(unowned_files /etc/ld.so.conf.d)"
  slow_ok && review "PAM modules not owned by any package (backdoored PAM?)" "$(unowned_files /lib/security /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib/aarch64-linux-gnu/security 2>/dev/null | head)"
  review "APT hooks (Pre/Post-Invoke)" "$(grep -rnE 'Pre-Invoke|Post-Invoke|Update-Post' /etc/apt/apt.conf.d 2>/dev/null | grep -vE 'update-notifier|20archive|99update')"
  review "udev rules that run programs" "$(grep -rnE 'RUN\+?=' /etc/udev/rules.d 2>/dev/null)"
  review "modprobe/modules-load entries that run commands or load odd modules" "$(grep -rhE '^[[:space:]]*install[[:space:]]' /etc/modprobe.d 2>/dev/null | grep -vE '/bin/(true|false)|/sbin/(true|false)'; cat /etc/modules /etc/modules-load.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')"
  out="$(lsmod 2>/dev/null | awk 'NR>1{print $1}' | while read -r f; do p="$(modinfo -n "$f" 2>/dev/null)"; [[ "$p" == /lib/modules/* || "$p" == /usr/lib/modules/* || "$p" == "(builtin)" ]] || echo "$f -> ${p:-unknown}"; done)"
  review "Loaded kernel modules NOT from /lib/modules" "$out"
  review "Processes running from /tmp, /dev/shm, /var/tmp or deleted binaries" "$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '\(deleted\)|/tmp/|/dev/shm|/var/tmp')"
  # processes executing from temp dirs are almost always implants (deleted binaries are NOT killed: updates cause those)
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"; [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
    ex="$(readlink "$p/exe" 2>/dev/null)"
    [[ "$ex" =~ ^/(tmp|dev/shm|var/tmp)/ ]] && rchange "KILL process $pid running from a temp dir: $ex" kill -9 "$pid"
  done
  # netcat-style listeners
  while read -r pid cmd; do
    [[ -z "$pid" || "$pid" == $$ ]] && continue
    [[ "$cmd" =~ (^|[[:space:]/])(nc|ncat|netcat|socat)([[:space:]]|$) ]] && [[ "$cmd" =~ (-[a-zA-Z]*l|TCP-LISTEN|--listen|-lp) ]] && rchange "KILL listener process $pid: $cmd" kill -9 "$pid"
  done < <(ps -eo pid=,args= 2>/dev/null)
  review "SSH authorized_keys files and their keys (every key must be justified)" "$(for f in $(find /home /root -name 'authorized_keys*' -type f 2>/dev/null); do echo "== $f"; awk '{print $1, $NF}' "$f" | cut -c1-120; done)"
  for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
    [[ -f "$f" ]] && { echo "$f" >"$REPORT_DIR/rootkeys.txt"; rchange "quarantine root's SSH authorized_keys ($f) - nobody should log in as root by key" quarantine_list "$REPORT_DIR/rootkeys.txt"; }
  done
  hn="$(hostname)"
  review "/etc/hosts: non-default entries (redirected domains?)" "$(awk -v hn="$hn" -v bad=1 "$HOSTS_AWK" /etc/hosts 2>/dev/null)"
  [[ -n "$(awk -v hn="$hn" -v bad=1 "$HOSTS_AWK" /etc/hosts 2>/dev/null)" ]] && rchange "comment out suspicious /etc/hosts entries (kept as '# cp_disabled:')" _hosts_clean
  review "/etc/resolv.conf nameservers" "$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null)"
  review "/etc/shells entries that are not standard" "$(grep -vE '^[[:space:]]*(#|$)|^/(usr/)?bin/(sh|bash|rbash|dash|zsh|fish|tmux|screen|sync)$|nologin$' /etc/shells)"
  review "GRUB kernel options that weaken the system" "$(grep -E '^GRUB_CMDLINE' /etc/default/grub 2>/dev/null | grep -E 'init=|single|rd\.break|apparmor=0|selinux=0|systemd\.unit=|nomodeset=0|nosmep|nosmap|mitigations=off')"
  review "NIS '+' entries in passwd/group" "$(grep -E '^\+' /etc/passwd /etc/group /etc/shadow 2>/dev/null)"
  review "Recently modified (3 days) files in key dirs" "$(find /etc /usr/local /opt /root /var/www /srv -xdev -type f -mtime -3 ! -path '/opt/CyberPatriot/*' ! -path "$STATE_DIR/*" ! -path '/root/cp_harden_*' ! -path '*/site-packages/*' ! -path '*/dist-packages/*' 2>/dev/null | head -40)"
}

# =============================================================================
#  MODULE sysctl : kernel / network hardening (also written to /etc/sysctl.conf)
# =============================================================================
SYSCTLS=(
  net.ipv4.ip_forward=0 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0
  net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0
  net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0
  net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0
  net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1
  net.ipv4.icmp_echo_ignore_broadcasts=1 net.ipv4.icmp_ignore_bogus_error_responses=1
  net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 net.ipv4.tcp_syncookies=1
  net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
  net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0
  net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0
  kernel.randomize_va_space=2 fs.suid_dumpable=0 kernel.dmesg_restrict=1 kernel.kptr_restrict=2
  fs.protected_hardlinks=1 fs.protected_symlinks=1 fs.protected_fifos=2 fs.protected_regular=2 kernel.sysrq=0
  kernel.yama.ptrace_scope=1 kernel.unprivileged_bpf_disabled=1 net.core.bpf_jit_harden=2
)
mod_sysctl() {
  section "sysctl hardening"
  local kv k v live conf n=0
  QUIET=1
  for kv in "${SYSCTLS[@]}"; do
    k="${kv%%=*}"; v="${kv#*=}"
    sysctl -n "$k" >/dev/null 2>&1 || continue
    live="$(sysctl -n "$k" 2>/dev/null)"; conf="$(conf_get /etc/sysctl.conf "$k")"
    conf="${conf// /}"
    if [[ "$live" != "$v" || "$conf" != "$v" ]]; then
      n=$((n+1)); set_conf /etc/sysctl.conf "$k" "$v" speq
      [[ "$live" != "$v" ]] && change "sysctl -w $k=$v" sysctl -w "$k=$v"
    fi
  done
  QUIET=0
  (( n )) && info "$n sysctl setting(s) $( (( APPLY )) && echo applied || echo 'would be applied') (live + /etc/sysctl.conf)" || good "sysctl already hardened"
  review "sysctl.d files that set the same keys (FYI: /etc/sysctl.conf is applied last and wins)" "$(grep -rHE 'ip_forward|randomize_va_space|accept_redirects|accept_source_route|rp_filter|syncookies' /etc/sysctl.d/ 2>/dev/null | grep -v '^[^:]*:#')"
}

# =============================================================================
#  MODULE kernel : module blacklist, mounts, GRUB, core dumps
# =============================================================================
mod_kernel() {
  section "Kernel modules, mounts, boot loader, core dumps"
  local m
  write_file /etc/modprobe.d/cp-hardening.conf 644 < <( for m in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do echo "install $m /bin/true"; echo "blacklist $m"; done
    (( AGGRESSIVE )) && for m in usb-storage firewire-core thunderbolt; do echo "install $m /bin/true"; echo "blacklist $m"; done )
  write_file /etc/systemd/coredump.conf.d/cp-hardening.conf 644 <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
  # /dev/shm and optionally /tmp mount options
  if ! grep -qE '^[^#]*[[:space:]]/dev/shm[[:space:]]' /etc/fstab 2>/dev/null; then
    ensure_line /etc/fstab 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0'; (( APPLY )) && mount -o remount /dev/shm 2>/dev/null
  fi
  if (( AGGRESSIVE )) && ! grep -qE '^[^#]*[[:space:]]/tmp[[:space:]]' /etc/fstab 2>/dev/null; then
    rask "mount /tmp as tmpfs with nosuid,nodev,noexec (installers that run from /tmp will fail)" && ensure_line /etc/fstab 'tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0'
  fi
  review "Mounts missing nosuid/nodev on /tmp,/var/tmp,/dev/shm" "$(findmnt -rn -o TARGET,OPTIONS /tmp /var/tmp /dev/shm 2>/dev/null | grep -vE 'nosuid.*nodev|nodev.*nosuid')"
  # GRUB
  if [[ -f /boot/grub/grub.cfg ]] && ! grep -q '^set superusers' /boot/grub/grub.cfg 2>/dev/null; then
    info "GRUB has no password. Optional: run  grub-mkpasswd-pbkdf2  and add superusers/password_pbkdf2 to /etc/grub.d/40_custom, then update-grub (not automated: needs your secret)."
  fi
  [[ -f /etc/default/grub ]] && sed_file "grub: remove apparmor=0 / selinux=0" /etc/default/grub 'apparmor=0|selinux=0' 's/[[:space:]]*(apparmor|selinux)=0//g'
  have systemctl && ! [[ "$(systemctl is-enabled ctrl-alt-del.target 2>/dev/null)" == masked ]] && change "mask Ctrl-Alt-Del reboot" systemctl mask ctrl-alt-del.target
}

# =============================================================================
#  MODULE desktop : guest login, autologin, user list, screen lock, browsers
# =============================================================================
write_firefox_prefs() { # profile_dir owner
  local d="$1" o="$2" f="$1/user.js"
  cat >"$f" <<'EOF'
user_pref("dom.disable_open_during_load", true);
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.downloads.enabled", true);
user_pref("security.tls.version.min", 3);
user_pref("signon.rememberSignons", false);
user_pref("app.update.auto", true);
user_pref("app.update.enabled", true);
user_pref("extensions.blocklist.enabled", true);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("network.prefetch-next", false);
user_pref("browser.send_pings", false);
user_pref("geo.enabled", false);
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("browser.download.manager.scanWhenDone", true);
user_pref("security.warn_entering_weak", true);
EOF
  chown "$o" "$f"
}
mod_desktop() {
  section "Desktop / login screen / browsers"
  local f sect pd o
  if [[ -d /etc/lightdm ]]; then
    info "LightDM detected"
    write_file /etc/lightdm/lightdm.conf.d/99-cp-hardening.conf 644 <<'EOF'
[Seat:*]
allow-guest=false
greeter-hide-users=true
greeter-show-manual-login=true
autologin-user=
xserver-allow-tcp=false

[SeatDefaults]
allow-guest=false
greeter-hide-users=true
greeter-show-manual-login=true
autologin-user=
EOF
    for f in /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d/*.conf; do
      [[ -f "$f" && "$f" != *99-cp-hardening.conf ]] || continue
      sed_file "lightdm: no guest in $f" "$f" '^[[:space:]]*allow-guest[[:space:]]*=[[:space:]]*true' 's/^([[:space:]]*allow-guest)[[:space:]]*=.*/\1=false/'
      sed_file "lightdm: no autologin in $f" "$f" '^[[:space:]]*autologin-user[[:space:]]*=[[:space:]]*[^[:space:]]' 's/^([[:space:]]*autologin-user)[[:space:]]*=.*/\1=/'
    done
  fi
  if [[ -f /etc/gdm3/custom.conf || -f /etc/gdm/custom.conf ]]; then
    f=/etc/gdm3/custom.conf; [[ -f $f ]] || f=/etc/gdm/custom.conf
    info "GDM detected"
    ini_set $f daemon AutomaticLoginEnable false; ini_set $f daemon TimedLoginEnable false
    sed_file "gdm: remove AutomaticLogin user" $f '^[[:space:]]*AutomaticLogin[[:space:]]*=[[:space:]]*[^[:space:]]' 's/^([[:space:]]*AutomaticLogin)[[:space:]]*=.*/# \1=/'
    [[ -d /etc/dconf ]] && {
      write_file /etc/dconf/db/gdm.d/00-cp-login-screen 644 <<'EOF'
[org/gnome/login-screen]
disable-user-list=true
EOF
      [[ -f /etc/dconf/profile/gdm ]] || write_file /etc/dconf/profile/gdm 644 <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF
    }
  fi
  if [[ -d /etc/dconf || $(command -v dconf) ]]; then   # screen lock + no automount (system-wide, locked): GNOME + Cinnamon (Mint)
    write_file /etc/dconf/db/local.d/00-cp-desktop 644 <<'EOF'
[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true

[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true

[org/gnome/desktop/privacy]
remember-recent-files=false

[org/cinnamon/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/cinnamon/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
EOF
    write_file /etc/dconf/db/local.d/locks/cp-desktop 644 <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/autorun-never
/org/cinnamon/desktop/session/idle-delay
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/desktop/media-handling/automount
/org/cinnamon/desktop/media-handling/autorun-never
EOF
    [[ -f /etc/dconf/profile/user ]] || write_file /etc/dconf/profile/user 644 <<'EOF'
user-db:user
system-db:local
EOF
    (( APPLY )) && have dconf && dconf update 2>/dev/null
  fi
  # Firefox: enterprise policy (all profiles) + user.js in every profile (apt + snap locations)
  if have firefox || [[ -d /usr/lib/firefox ]] || { have snap && snap list firefox >/dev/null 2>&1; }; then
    write_file /etc/firefox/policies/policies.json 644 <<'EOF'
{
  "policies": {
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "PopupBlocking": { "Default": true },
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "SSLVersionMin": "tls1.2",
    "EnableTrackingProtection": { "Value": true },
    "DontCheckDefaultBrowser": true
  }
}
EOF
  fi
  while IFS=: read -r u _ uid _ _ h _; do
    (( uid >= UID_MIN && uid <= UID_MAX )) && [[ -d "$h" ]] || continue
    for pd in "$h"/.mozilla/firefox/*.default* "$h"/.mozilla/firefox/*.default-release* "$h"/snap/firefox/common/.mozilla/firefox/*.default*; do
      [[ -d "$pd" ]] || continue
      if (( APPLY )); then backup "$pd/user.js"; write_firefox_prefs "$pd" "$u"; _done "Firefox hardening prefs -> $pd/user.js"; else _would "Firefox hardening prefs -> $pd/user.js"; fi
    done
  done </etc/passwd
  review "Browser extensions installed per profile (remove anything you do not recognise)" "$(ls -d /home/*/.mozilla/firefox/*/extensions/* /home/*/snap/firefox/common/.mozilla/firefox/*/extensions/* /home/*/.config/google-chrome/*/Extensions/* /home/*/.config/chromium/*/Extensions/* 2>/dev/null | head -30)"
  # Chrome / Chromium managed policy
  for pd in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed /etc/chromium-browser/policies/managed; do
    [[ -d "$(dirname "$(dirname "$pd")")" ]] || continue
    case "$pd" in /etc/opt/chrome/*) { have google-chrome || have google-chrome-stable; } || continue;; *) { have chromium || have chromium-browser; } || continue;; esac
    write_file "$pd/cp-hardening.json" 644 <<'EOF'
{
  "DefaultPopupsSetting": 2,
  "PasswordManagerEnabled": false,
  "SSLVersionMin": "tls1.2",
  "BlockThirdPartyCookies": true,
  "SafeBrowsingProtectionLevel": 1,
  "MetricsReportingEnabled": false
}
EOF
  done
}

# =============================================================================
#  MODULE logging : auditd, rsyslog, journald, AppArmor, fail2ban
# =============================================================================
mod_logging() {
  section "Logging, auditing, AppArmor"
  local p
  if (( DEBFAM )); then
    for p in auditd; do pkg_installed "$p" || change "install $p" pkg_install "$p"; done
    (( INSTALL_EXTRAS )) && for p in fail2ban rkhunter chkrootkit lynis clamav debsums acct; do pkg_installed "$p" || change "install $p" pkg_install "$p"; done
  fi
  write_file /etc/audit/rules.d/cp-hardening.rules 640 <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/pam.d/ -p wa -k pam
-w /etc/login.defs -p wa -k login
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /etc/localtime -p wa -k time-change
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/hosts -p wa -k network
-w /etc/issue -p wa -k network
EOF
  if have auditd || [[ -x /sbin/auditd ]]; then
    svc_enabled auditd || change "enable auditd at boot" systemctl enable auditd
    svc_active auditd  || change "start auditd" systemctl start auditd
    (( APPLY )) && have augenrules && augenrules --load >/dev/null 2>&1
  fi
  if have rsyslogd || svc_has rsyslog; then
    svc_enabled rsyslog || change "enable rsyslog" systemctl enable rsyslog
    svc_active rsyslog  || change "start rsyslog" systemctl start rsyslog
    [[ -f /etc/rsyslog.conf ]] && grep -q '^\$FileCreateMode' /etc/rsyslog.conf && set_conf /etc/rsyslog.conf '$FileCreateMode' 0640
  fi
  write_file /etc/systemd/journald.conf.d/cp-hardening.conf 644 <<'EOF'
[Journal]
Storage=persistent
Compress=yes
EOF
  if have aa-status || svc_has apparmor; then
    svc_enabled apparmor || change "enable AppArmor" systemctl enable apparmor
    svc_active apparmor  || change "start AppArmor" systemctl start apparmor
    review "AppArmor profiles in complain mode (should be enforce)" "$(aa-status 2>/dev/null | sed -n '/profiles are in complain mode/,/profiles are in kill/p' | grep -vE 'profiles are' | sed 's/^ *//')"
    have aa-enforce && [[ -d /etc/apparmor.d ]] && (( AGGRESSIVE )) && rchange "put all AppArmor profiles into enforce mode" aa-enforce /etc/apparmor.d/*
  fi
  if svc_has fail2ban; then svc_active fail2ban || change "start fail2ban" systemctl enable --now fail2ban; fi
}

# =============================================================================
#  MODULE misc : banners, umask, ctrl-alt-del, cron/at, time sync, shells
# =============================================================================
mod_misc() {
  section "Banners, umask, cron/at access, time sync, misc"
  local banner='Authorized use only. Activity on this system is monitored and logged. Unauthorized access is prohibited.'
  local f
  for f in /etc/issue /etc/issue.net /etc/motd; do write_file $f 644 <<<"$banner"; done
  for f in /etc/profile /etc/bash.bashrc; do [[ -f $f ]] && ! grep -qE '^[[:space:]]*umask[[:space:]]+0?27' $f && ensure_line $f 'umask 027'; done
  # shell session timeout (aggressive: it will log YOU out of idle shells too)
  (( AGGRESSIVE )) && write_file /etc/profile.d/cp-tmout.sh 644 <<'EOF'
readonly TMOUT=900
export TMOUT
EOF
  # cron / at access
  if (( AGGRESSIVE )); then
    local others; others="$(ls /var/spool/cron/crontabs 2>/dev/null | grep -v '^root$')"
    if [[ -z "$others" ]]; then
      write_file /etc/cron.allow 600 <<<"root"; write_file /etc/at.allow 600 <<<"root"
      [[ -e /etc/cron.deny ]] && change "remove /etc/cron.deny" rm -f /etc/cron.deny
      [[ -e /etc/at.deny ]]   && change "remove /etc/at.deny" rm -f /etc/at.deny
    else warn "non-root users have crontabs ($others) - not restricting cron to root"; fi
  fi
  have timedatectl && ! timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes && change "enable NTP time sync" timedatectl set-ntp true
  review "Accounts with unusual login shells (python/perl/netcat/tmp...)" "$(awk -F: '$7 ~ /(python|perl|ruby|\/nc$|netcat|\/tmp)/{print $1":"$7}' /etc/passwd)"
}

# =============================================================================
#  MODULE updates : apt policy + (slow) actual updates
# =============================================================================
mod_updates() {
  section "Updates"
  [[ $PM == apt ]] || { warn "updates module only automated for apt systems; update manually"; return; }
  write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
  [[ -f /etc/apt/apt.conf.d/10periodic ]] && write_file /etc/apt/apt.conf.d/10periodic 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
  pkg_installed unattended-upgrades || change "install unattended-upgrades" pkg_install unattended-upgrades
  if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    sed_file "unattended-upgrades: enable -security origin" /etc/apt/apt.conf.d/50unattended-upgrades '^//[[:space:]]*"\$\{distro_id\}:\$\{distro_codename\}-security";' 's#^//([[:space:]]*"\$\{distro_id\}:\$\{distro_codename\}-security";)#\1#'
    sed_file "unattended-upgrades: enable -updates origin" /etc/apt/apt.conf.d/50unattended-upgrades '^//[[:space:]]*"\$\{distro_id\}:\$\{distro_codename\}-updates";' 's#^//([[:space:]]*"\$\{distro_id\}:\$\{distro_codename\}-updates";)#\1#'
  fi
  svc_enabled unattended-upgrades || { svc_has unattended-upgrades && change "enable unattended-upgrades service" systemctl enable --now unattended-upgrades; }
  _apt_full_update() {
    local o="-o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=600"
    export DEBIAN_FRONTEND=noninteractive
    dpkg --configure -a; apt-get $o update && apt-get -y $o upgrade && apt-get -y $o dist-upgrade && apt-get -y $o autoremove
    have snap && snap refresh
  }
  rchange "RUN full system update now (apt update/upgrade/dist-upgrade + snap refresh; slow, needs network)" _apt_full_update
  info "Tip: start this module FIRST in a second terminal:  sudo ./cp_harden.sh --apply --yes --only updates   (other modules wait for the apt lock)"
  info "Also set Software & Updates -> 'Check for updates: Daily' (done via APT::Periodic above) and update Firefox: snap refresh firefox"
}

# =============================================================================
#  MODULE scan (opt-in: --with scan) : rootkit/AV/integrity scanners
# =============================================================================
mod_scan() {
  section "Scanners (report only)"
  local o
  if have rkhunter;   then o="$REPORT_DIR/rkhunter.txt";  info "rkhunter..."; rkhunter --check --sk --rwo >"$o" 2>&1; review "rkhunter warnings" "$(head -30 "$o")"; else info "rkhunter not installed (--install-extras)"; fi
  if have chkrootkit; then o="$REPORT_DIR/chkrootkit.txt"; info "chkrootkit..."; chkrootkit -q >"$o" 2>&1; review "chkrootkit findings" "$(head -30 "$o")"; fi
  if have lynis;      then o="$REPORT_DIR/lynis.txt"; info "lynis (quick)..."; lynis audit system --quick --no-colors >"$o" 2>&1; review "lynis warnings/suggestions (top)" "$(grep -E 'Warning|Suggestion' "$o" | head -30)"; fi
  if have debsums;    then o="$REPORT_DIR/debsums.txt"; info "debsums (modified package files)..."; debsums -s >"$o" 2>&1; review "Package files that differ from the package (tampered binaries?)" "$(head -30 "$o")"
  else o="$REPORT_DIR/dpkg_verify.txt"; info "dpkg --verify..."; dpkg -V 2>/dev/null | grep -E '^..5' | grep -v ' c ' >"$o"; review "dpkg --verify: modified non-config files" "$(head -30 "$o")"; fi
  if have clamscan;   then o="$REPORT_DIR/clamav.txt"; info "clamscan (home, tmp, www, opt)..."; clamscan -r -i --exclude-dir='^/sys' --exclude-dir='^/proc' /home /root /tmp /var/www /srv /opt/ 2>/dev/null >"$o"; review "ClamAV infected files" "$(grep FOUND "$o")"; fi
  return 0
}

# =============================================================================
#  MODULE forensics (runs FIRST, read-only) : evidence dump for forensics questions
#  It runs before any change so deleted users / moved files / reset passwords
#  cannot destroy the evidence the forensics questions ask about.
# =============================================================================
mod_forensics() {
  section "Forensics evidence collection (read-only, runs before any change)"
  local o="$REPORT_DIR/forensics.txt" u h
  {
    echo "##### $(date) - $(hostname) - $OS_NAME #####"
    echo; echo "== human accounts =="; awk -F: -v mn="$UID_MIN" '$3>=mn && $3<65534{print}' /etc/passwd
    echo; echo "== group memberships (sudo/admin/adm/docker/shadow/nopasswdlogin) =="; getent group sudo admin adm docker shadow lxd nopasswdlogin 2>/dev/null
    echo; echo "== last logins =="; last -n 30 2>/dev/null; echo "-- failed:"; lastb -n 20 2>/dev/null
    echo; echo "== accounts password status =="; passwd -Sa 2>/dev/null
    echo; echo "== recently installed packages (dpkg.log) =="; grep -h ' install ' /var/log/dpkg.log* 2>/dev/null | sort | tail -60
    echo; echo "== apt history =="; grep -hE 'Commandline|Install:|Remove:' /var/log/apt/history.log* 2>/dev/null | tail -60
    echo; echo "== manually installed packages =="; apt-mark showmanual 2>/dev/null | tail -80
    for h in $(awk -F: -v mn="$UID_MIN" '$3>=mn && $3<65534{print $6}' /etc/passwd) /root; do
      echo; echo "== shell history: $h =="; tail -n 80 "$h/.bash_history" 2>/dev/null
      echo "== home listing: $h =="; ls -laR "$h" 2>/dev/null | head -120
    done
    echo; echo "== open ports =="; ss -tulpn 2>/dev/null
    echo; echo "== network =="; ip -br addr 2>/dev/null; ip route 2>/dev/null; grep -E '^nameserver' /etc/resolv.conf 2>/dev/null
    echo; echo "== running processes =="; ps auxww 2>/dev/null
    echo; echo "== sudo log =="; tail -50 /var/log/sudo.log 2>/dev/null; grep -h 'sudo:' /var/log/auth.log 2>/dev/null | tail -40
    echo; echo "== auth failures/accepted =="; grep -hE 'Accepted|Failed password|session opened' /var/log/auth.log 2>/dev/null | tail -40
    echo; echo "== files modified in last 7 days (key dirs) =="; find /home /root /etc /opt /srv /var/www /usr/local -xdev -type f -mtime -7 ! -path '/opt/CyberPatriot/*' 2>/dev/null | head -150
    echo; echo "== user files: date owner mode size path (newest 300) =="; find /home /root /srv /opt /var/www /usr/local -xdev -type f ! -path '/opt/CyberPatriot/*' ! -path '*/.cache/*' ! -path '*/.mozilla/*' ! -path '*/snap/*' ! -path '*/.local/share/*' -printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\n' 2>/dev/null | sort -r | head -300
    echo; echo "== md5 of media files =="; build_iname "${MEDIA_EXT[@]}"; find_files "${IEXPR[@]}" | xargs -d '\n' -r md5sum 2>/dev/null
    echo; echo "== crontabs =="; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
    echo; echo "== enabled services =="; systemctl list-unit-files --state=enabled --no-legend 2>/dev/null
    echo; echo "== installed packages by install date (last 40) =="; ls -t /var/lib/dpkg/info/*.list 2>/dev/null | head -40 | xargs -r -n1 basename | sed 's/\.list$//'
  } >"$o" 2>&1
  good "evidence dump: $o  ($(wc -l <"$o") lines)  -> search it for the answers to the forensics questions"
  info "Handy: grep -rIl 'STRING' /home /root /var/www /srv /opt 2>/dev/null   |   find / -xdev -iname '*NAME*' 2>/dev/null"
}

# =============================================================================
#  MODULE verify (runs LAST) : post-change sanity checks so a fix never silently breaks a requirement
# =============================================================================
mod_verify() {
  section "Verification: did the changes break anything that must keep working?"
  local t u any m bad=0 sshd_bin
  for t in "${REQ_RAW[@]}"; do
    any=0
    for u in $(req_units "$t"); do
      svc_has "$u" || continue; any=1
      if svc_active "$u"; then good "required service '$u' is running"; else warn "required service '$u' is NOT running"; bad=$((bad+1)); fi
    done
    (( any )) || info "required service '$t': no systemd unit found to check"
  done
  if have visudo; then
    if visudo -c >/dev/null 2>&1; then good "sudoers syntax OK"; else warn "sudoers syntax is BROKEN (fix before logging out!)"; bad=$((bad+1)); fi
  fi
  sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
  if [[ -x "$sshd_bin" && -f /etc/ssh/sshd_config ]]; then
    mkdir -p /run/sshd
    if "$sshd_bin" -t >/dev/null 2>&1; then good "sshd_config valid"; else warn "sshd_config is INVALID"; bad=$((bad+1)); fi
  fi
  if have ufw; then
    if ufw status 2>/dev/null | grep -q '^Status: active'; then good "ufw is active"; else info "ufw is not active$( (( APPLY )) || echo ' (dry run)')"; fi
  fi
  if [[ -n "${ME:-}" ]]; then
    if id "$ME" >/dev/null 2>&1; then good "your account '$ME' still exists"; else warn "YOUR account '$ME' is gone!"; bad=$((bad+1)); fi
    if id -nG "$ME" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then good "'$ME' still has sudo rights"; else info "'$ME' is not in an admin group (fine only if the README says you are a standard user)"; fi
  fi
  for u in "${AUTH_ADMINS[@]}"; do
    id "$u" >/dev/null 2>&1 || { warn "authorized admin '$u' does not exist"; bad=$((bad+1)); }
  done
  for u in "${AUTH_USERS[@]}"; do
    id "$u" >/dev/null 2>&1 || { warn "authorized user '$u' does not exist"; bad=$((bad+1)); }
  done
  for m in /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-account; do
    [[ -f "$m" && ! -s "$m" ]] && { warn "$m is EMPTY"; bad=$((bad+1)); }
  done
  if (( bad == 0 )); then good "verification passed: nothing required appears broken"; else warn "$bad verification problem(s): fix them or use undo.sh BEFORE you log out"; fi
  review "Still-listening ports after changes (compare with what the README requires)" "$(ss -tuln 2>/dev/null | tail -n +2 | awk '{print $1, $5}' | sort -u)"
}

# =============================================================================
#  snapshot / summary / main
# =============================================================================
MODULES=(forensics policy accounts sudoers ssh services svchard firewall software files perms persistence sysctl kernel desktop logging misc updates scan verify)
OPTIN_MODULES="scan"
declare -A MOD_DESC=(
  [forensics]="(runs first, read-only) evidence dump for answering forensics questions"
  [policy]="login.defs, pwquality, PAM complexity/history/lockout/nullok/pam_permit, password aging"
  [accounts]="unauthorized users, admin groups, nopasswdlogin, UID 0, shells, expiry, empty passwords, new passwords, root lock"
  [sudoers]="NOPASSWD/!authenticate, unauthorized sudo entries, sudo defaults"
  [ssh]="sshd_config hardening (validated with sshd -t, verified with sshd -T)"
  [services]="disable unneeded services (incl. ssh if not required), keep required ones running, list listeners"
  [svchard]="Apache, nginx, PHP, MySQL, PostgreSQL, FTP, Samba, NFS, Postfix, BIND, Docker, web-shell scan..."
  [firewall]="UFW enable + default deny + only required ports"
  [software]="prohibited packages, snaps, held packages, apt sources, attack-tool binaries"
  [files]="prohibited media, suspicious files, plaintext creds, hidden files"
  [perms]="critical file modes, home dirs, SUID/SGID, world-writable, capabilities, chattr flags, ACLs"
  [persistence]="cron (auto-cleaned), timers, rc.local, profiles, ld.so.preload, keys, /etc/hosts, tmp-dir processes, listeners"
  [sysctl]="kernel/network sysctl hardening (live + /etc/sysctl.conf)"
  [kernel]="module blacklist, mount options, GRUB, core dumps, ctrl-alt-del"
  [desktop]="guest login, autologin, user list, screen lock, automount, Firefox policy+prefs, Chrome prefs"
  [logging]="auditd + rules, rsyslog, journald, AppArmor, fail2ban"
  [misc]="login banners, umask, cron/at access, NTP"
  [updates]="auto-update policy + full system update (slow)"
  [scan]="(opt-in) rkhunter, chkrootkit, lynis, debsums, clamav"
  [verify]="(runs last) required services up, sudoers/sshd valid, your account intact"
)

want_module() { local m="$1"
  [[ -n "$ONLY" ]] && { in_csv "$ONLY" "$m" || in_csv "$WITH" "$m"; return; }
  in_csv "$SKIP" "$m" && return 1
  if in_csv "$OPTIN_MODULES" "$m"; then in_csv "$WITH" "$m"; return; fi
  return 0
}

snapshot() { # dir
  local d="$1"; mkdir -p "$d"
  getent passwd >"$d/passwd"; getent group >"$d/group"
  pkg_list >"$d/packages" 2>/dev/null
  systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | sort >"$d/enabled_services"
  systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | sort >"$d/running_services"
  ss -tuln 2>/dev/null | tail -n +2 | awk '{print $1,$5}' | sort >"$d/listening_ports"
  stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config 2>/dev/null >"$d/perms"
  have ufw && ufw status verbose >"$d/ufw" 2>&1
  { sysctl -a 2>/dev/null | grep -E '^(net\.ipv4\.(ip_forward|tcp_syncookies|conf\.all\.(rp_filter|accept_redirects))|kernel\.randomize_va_space)'; } >"$d/sysctl"
  if slow_ok; then find / -xdev \( -path /proc -o -path /sys \) -prune -o -type f -perm -4000 -print 2>/dev/null | sort >"$d/suid"; fi
}
snap_diff() {
  local f a b
  for f in passwd group packages enabled_services running_services listening_ports perms suid ufw sysctl; do
    [[ -f "$STATE_DIR/before/$f" && -f "$STATE_DIR/after/$f" ]] || continue
    a="$(diff <(sort "$STATE_DIR/before/$f") <(sort "$STATE_DIR/after/$f") | grep -E '^[<>]' | head -12)"
    [[ -n "$a" ]] && { printf '  %s%s changed:%s\n' "$BO" "$f" "$N"; printf '%s\n' "$a" | sed 's/^/     /'; }
  done
}

summary() {
  section "SUMMARY"
  if (( APPLY )); then say "Changes applied      : $N_CHANGED"; else say "Changes that WOULD be made (dry run): $N_WOULD   <- re-run with --apply (or --auto)"; fi
  say "Risky actions skipped: $N_SKIP     Warnings: $N_WARN     Items to review by hand: $N_REVIEW"
  say "Run log     : $LOG"
  say "Review list : $REPORT_DIR/review.txt   (read it - this is where unique image vulnerabilities hide)"
  say "Forensics   : $REPORT_DIR/forensics.txt   (evidence collected BEFORE any change)"
  say "Undo script : $UNDO   (backups in $BACKUP_DIR, quarantined files in $QUAR_DIR)"
  (( APPLY )) && say "Full /etc backup: $BACKUP_DIR/etc_full.tgz"
  [[ -f "$STATE_DIR/new_password.txt" ]] && say "New password : $STATE_DIR/new_password.txt"
  if (( APPLY )); then printf '\n%sWhat changed on the system (before -> after):%s\n' "$BO" "$N"; snap_diff; fi
  cat <<EOF

${BO}NEXT STEPS (the script cannot do these):${N}
  1. Answer the FORENSICS QUESTIONS from $REPORT_DIR/forensics.txt (collected before anything changed)
  2. Read review.txt line by line: unknown users/keys/cron/timers/PAM/binaries/ports are image-specific.
  3. Re-read the README: admin/user types, required services, allowed software, special tasks.
  4. Check the scoreboard after EVERY batch of changes; if the score DROPS, use undo.sh for that item.
  5. Set a strong password for YOUR OWN account by hand (the script never touches it): passwd <you>
  6. Test: log in as an authorized user, run 'sudo -l', open the browser, check required services still work.
  7. Re-run this script's dry-run at the end: it should report (almost) nothing left to do.
EOF
}

usage() {
cat <<EOF
cp_harden.sh v$CPH_VERSION - CyberPatriot Linux hardening, audit & forensics toolkit

USAGE: sudo $0 [options]

  (no options)          DRY RUN: report only, change nothing
  --auto                FASTEST: find+parse the README, show the parsed users/admins/services for ONE
                        y/N confirmation, then apply everything with no more prompts (= --apply --yes)
  --apply               apply changes (risky ones ask first)
  --yes, -y             answer YES to the risky prompts (use only after a clean dry run!)
  --fast                skip the slowest full-disk scans (content-type media scan, -nouser, >200MB,
                        plaintext-password grep, lsattr/ACL sweeps, package-ownership checks)
  --readme FILE|-|auto  parse the README (html/txt, '-' = stdin, auto = find it) into config/*.txt
  --readme-only         parse the README, write config, then stop (review the files!)
  --init                create the config/ templates and stop
  --only a,b,c          run only these modules      --skip a,b   skip modules
  --with scan           enable the opt-in scan module     --list-modules
  --aggressive          extra, more disruptive hardening (su/pam_wheel, tmpfs /tmp, SSH ciphers,
                        PHP disable_functions, purge unneeded servers, cron/at allow, USB off, TMOUT...)
  --install-extras      apt-install auditd, fail2ban, rkhunter, chkrootkit, lynis, clamav, debsums
  --include-images      also treat jpg/png/gif/... as prohibited media
  --me USER|none        your own account (never deleted / password-changed). --apply REFUSES to run
                        if it cannot tell which account is yours; use 'none' only if you really mean it
  --password PASS       use this password instead of a random one (or env CP_PASSWORD)
  --config DIR          config directory (default: ./config)
  -h, --help

CONFIG FILES (config/*.txt, one entry per line, '#' comments):
  authorized_users  authorized_admins  required_services  required_packages
  prohibited_packages  protected_users  allow_ports

TYPICAL ROUND
  1) sudo ./cp_harden.sh --apply --yes --only updates &   # start slow updates early (2nd terminal; other apt steps wait for the lock)
  2) sudo ./cp_harden.sh --auto                           # parse README, ONE confirmation, apply everything
        -or, the careful way-
     sudo ./cp_harden.sh --readme auto --readme-only      # then FIX config/*.txt by hand
     sudo ./cp_harden.sh                                  # dry run, read the output
     sudo ./cp_harden.sh --apply                          # apply; answer the prompts
  3) read reports/review.txt and reports/forensics.txt, answer the forensics questions
  4) check the scoreboard; undo.sh reverts individual changes, backups/etc_full.tgz restores all of /etc
EOF
}

main() {
  local a
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply) APPLY=1;; --yes|-y) ASSUME_YES=1;; --aggressive) AGGRESSIVE=1;; --install-extras) INSTALL_EXTRAS=1;;
      --auto) AUTO=1;; --fast) FAST=1;;
      --include-images) INCLUDE_IMAGES=1;; --readme) README_SRC="${2:-}"; shift;; --readme-only) README_ONLY=1;;
      --init) INIT_ONLY=1;; --only) ONLY="${2:-}"; shift;; --skip) SKIP="${2:-}"; shift;; --with) WITH="${2:-}"; shift;;
      --config) CONFIG_DIR="${2:-}"; shift;; --password) PW_OVERRIDE="${2:-}"; shift;; --me) ME_OVERRIDE="${2:-}"; shift;;
      --list-modules) LIST_MODS=1;; -h|--help) usage; exit 0;;
      *) echo "unknown option: $1 (try --help)"; exit 2;;
    esac; shift
  done
  if (( LIST_MODS )); then for a in "${MODULES[@]}"; do printf '  %-12s %s\n' "$a" "${MOD_DESC[$a]}"; done; exit 0; fi
  [[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $*"; exit 1; }
  (( AUTO )) && { APPLY=1; ASSUME_YES=1; }
  (( README_ONLY )) && [[ -z "$README_SRC" ]] && README_SRC=auto
  init_state; init_config; detect_os
  if (( INIT_ONLY )); then good "config templates created in $CONFIG_DIR"; exit 0; fi
  printf '%s%s cp_harden v%s%s  |  %s  |  pkg manager: %s  |  mode: %s%s%s\n' "$BO" "$B" "$CPH_VERSION" "$N" "$OS_NAME" "$PM" "$BO" "$( (( AUTO )) && echo 'AUTO (apply, no prompts after confirmation)' || { (( APPLY )) && echo APPLY || echo 'DRY-RUN (no changes)'; })" "$N"
  (( DEBFAM )) || warn "Not an apt-based system: PAM/package/update modules have reduced coverage."
  # --auto with an empty config: pull it from the README first
  if (( AUTO )) && [[ -z "$README_SRC" ]] && (( $(read_list "$CONFIG_DIR/authorized_users.txt" | wc -l) == 0 )); then README_SRC=auto; fi
  if [[ -n "$README_SRC" ]]; then readme_ingest "$README_SRC" || exit 1; (( README_ONLY )) && { good "README processed. Edit $CONFIG_DIR/*.txt, then run again without --readme-only."; exit 0; }; fi
  load_config
  info "Config: ${#AUTH_USERS[@]} authorized users, ${#AUTH_ADMINS[@]} admins, ${#REQ_RAW[@]} required services, ${#REQ_PKGS[@]} protected pkgs, ${#PROHIB_CFG[@]} prohibited pkgs  ($CONFIG_DIR)"
  # safety guard: never apply without knowing which account is yours (it would be treated like any other user)
  if (( APPLY )) && [[ -z "$ME" && "$ME_OVERRIDE" != none ]]; then
    err "cannot tell which account is YOURS (running from a plain root shell?). Re-run with:  sudo $0 --me YOURUSER ...   (or --me none)"
    exit 1
  fi
  if (( AUTO )); then
    printf '\n%sAUTO MODE will now APPLY every change without further prompts.%s\n' "$BO$R" "$N"
    printf '  your account      : %s (never deleted / password-changed)\n  authorized users  : %s\n  authorized admins : %s\n  required services : %s\n  protected software: %s\n' \
      "${ME:-none}" "${AUTH_USERS[*]:-NONE (user deletion will be skipped)}" "${AUTH_ADMINS[*]:-NONE (admin sync will be skipped)}" "${REQ_RAW[*]:-NONE (services will only be reported)}" "${REQ_PKGS[*]:-none}"
    confirm_always "Does this match the README? Apply everything now?" || { echo "aborted - fix config/*.txt (or the README parse) and re-run"; exit 1; }
  elif (( APPLY )) && (( ! ASSUME_YES )); then
    printf '%sAPPLY mode:%s changes will be made. Backups + undo.sh are kept in %s.\n' "$Y" "$N" "$STATE_DIR"
    ask_yes "Continue?" || { echo "aborted"; exit 1; }
  fi
  (( APPLY )) && { info "taking safety backups (full /etc archive, account databases, firewall) ..."; backup_core; }
  snapshot "$STATE_DIR/before"
  for a in "${MODULES[@]}"; do want_module "$a" && "mod_$a"; done
  (( APPLY )) && snapshot "$STATE_DIR/after"
  summary
}

[[ "${BASH_SOURCE[0]:-$0}" == "$0" ]] && main "$@"