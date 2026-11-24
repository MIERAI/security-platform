# host-sbom profile: Linux (dpkg / apk / rpm). READ-ONLY, no sudo. Output: key=value lines + "pkg<TAB>..." lines:
#   pkg  <ecosystem>  <name>  <version>  <source name>  <source version>  <arch>
. /etc/os-release 2>/dev/null
echo "os.family=$ID"; echo "os.version=$VERSION_ID"; echo "os.codename=$VERSION_CODENAME"; echo "os.name=$PRETTY_NAME"
echo "kernel.running=$(uname -r)"; echo "arch=$(uname -m)"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n' 2>/dev/null |
    awk -F'\t' '$1 ~ /^ii/ {print "pkg\tdeb\t"$2"\t"$3"\t"$4"\t"$5"\t"$6}'
fi
if command -v apk >/dev/null 2>&1; then
  # name-version-rN arch {origin} ...
  apk list --installed 2>/dev/null | awk '{n=$1; sub(/-[^-]+-r[0-9]+$/, "", n); v=substr($1, length(n)+2); o=$3; gsub(/[{}]/, "", o); print "pkg\tapk\t"n"\t"v"\t"o"\t"v"\t"$2}'
fi
if command -v rpm >/dev/null 2>&1 && ! command -v dpkg-query >/dev/null 2>&1; then
  rpm -qa --qf 'pkg\trpm\t%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t\t%{ARCH}\n' 2>/dev/null
fi
