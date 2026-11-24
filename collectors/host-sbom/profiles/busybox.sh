# host-sbom profile: OpenWrt-like embedded devices (routers). READ-ONLY. Firmware identity + opkg packages.
. /etc/openwrt_release 2>/dev/null
echo "os.family=openwrt"; echo "os.version=$DISTRIB_RELEASE"; echo "os.name=$DISTRIB_DESCRIPTION"; echo "arch=$DISTRIB_ARCH"
echo "kernel.running=$(uname -r)"
V=/usr/share/xiaoqiang/xiaoqiang_version
if [ -f "$V" ]; then
  echo "firmware.vendor=xiaomi"
  echo "firmware.model=$(awk -F"'" '/option HARDWARE/{print $2}' $V)"
  echo "firmware.version=$(awk -F"'" '/option ROM/{print $2}' $V)"
  echo "firmware.channel=$(awk -F"'" '/option CHANNEL/{print $2}' $V)"
  echo "firmware.build_ts=$(awk -F"'" '/option BUILDTS/{print $2}' $V)"
elif [ -f /etc/glversion ]; then
  echo "firmware.vendor=gl-inet"; echo "firmware.version=$(cat /etc/glversion)"
  echo "firmware.model=$(cat /tmp/sysinfo/model 2>/dev/null)"
  echo "firmware.build_ts=$(date -r /etc/glversion +%s 2>/dev/null)"
else
  echo "firmware.vendor=openwrt"; echo "firmware.version=$DISTRIB_RELEASE $DISTRIB_REVISION"
  echo "firmware.model=$(cat /tmp/sysinfo/model 2>/dev/null)"
fi
if command -v opkg >/dev/null 2>&1; then
  opkg list-installed 2>/dev/null | awk -F' - ' '{print "pkg\topkg\t"$1"\t"$2"\t"$1"\t"$2"\t"}'
elif [ -f /usr/lib/opkg/status ]; then
  awk '/^Package:/{p=$2} /^Version:/{print "pkg\topkg\t"p"\t"$2"\t"p"\t"$2"\t"}' /usr/lib/opkg/status
fi
