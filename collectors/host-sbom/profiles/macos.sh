# host-sbom profile: macOS. READ-ONLY, no sudo. OS version/build + Homebrew formulae and casks.
echo "os.family=macos"; echo "os.version=$(sw_vers -productVersion)"; echo "os.build=$(sw_vers -buildVersion)"
echo "os.name=macOS $(sw_vers -productVersion)"; echo "os.rsr=$(sw_vers -productVersionExtra 2>/dev/null)"
echo "kernel.running=$(uname -r)"; echo "arch=$(uname -m)"
B=$(command -v brew || ls /opt/homebrew/bin/brew /usr/local/bin/brew 2>/dev/null | head -1)
if [ -n "$B" ]; then
  echo "brew.prefix=$($B --prefix)"
  HOMEBREW_NO_AUTO_UPDATE=1 $B list --formula --versions 2>/dev/null | awk '{print "pkg\tbrew\t"$1"\t"$NF"\t"$1"\t"$NF"\t"}'
  HOMEBREW_NO_AUTO_UPDATE=1 $B list --cask --versions 2>/dev/null | awk '{print "pkg\tbrew-cask\t"$1"\t"$NF"\t"$1"\t"$NF"\t"}'
fi
