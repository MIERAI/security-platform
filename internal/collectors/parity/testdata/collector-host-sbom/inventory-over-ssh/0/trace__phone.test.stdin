# host-sbom profile: Android + Termux (no root). READ-ONLY. Platform facts from getprop; Termux packages from dpkg.
# shellcheck shell=sh
echo "os.family=android"; echo "os.version=$(getprop ro.build.version.release)"
echo "os.name=Android $(getprop ro.build.version.release)"
echo "platform.patch_level=$(getprop ro.build.version.security_patch)"
echo "platform.vendor_patch_level=$(getprop ro.vendor.build.security_patch)"
echo "device.manufacturer=$(getprop ro.product.manufacturer)"; echo "device.model=$(getprop ro.product.model)"
echo "os.build=$(getprop ro.build.display.id)"; echo "kernel.running=$(uname -r)"; echo "arch=$(uname -m)"
dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n' 2>/dev/null |
  awk -F'\t' '$1 ~ /^ii/ {print "pkg\ttermux\t"$2"\t"$3"\t"$2"\t"$3"\t"$4}'
