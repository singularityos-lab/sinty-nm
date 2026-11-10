#!/bin/sh
set -eu
tag=$1
root=$(pwd)
work=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sinty-nmd-release
rm -rf "$work"
mkdir -p "$work"
version=$(go list -m -f '{{.Version}}' github.com/singularityos-lab/libsingularity/src/system/core/go)
rev=${version##*-}
git clone -q https://github.com/singularityos-lab/libsingularity "$work/libsingularity"
git -C "$work/libsingularity" checkout -q "$rev"
for arch in amd64:x86_64 arm64:aarch64; do
	goarch=${arch%%:*}
	cpu=${arch#*:}
	prefix=$work/core-$cpu
	(cd "$work/libsingularity/src/system/core" && zig build --release=safe -Dtarget="$cpu-linux-gnu" -Dcpu=baseline -Dpc-prefix="$prefix" --prefix "$prefix")
	out=$work/out-$cpu
	mkdir -p "$out"
	PKG_CONFIG_PATH=$prefix/lib/pkgconfig CGO_ENABLED=1 GOOS=linux GOARCH=$goarch \
		CC="zig cc -target $cpu-linux-gnu" CGO_LDFLAGS='-Wl,-rpath,$ORIGIN' \
		go build -trimpath -ldflags "-s -w" -o "$out/sinty-nmd" ./cmd/sinty-nmd
	cp -L "$prefix/lib/libsinty-system-core.so.1" "$out/"
	tar czf "$root/sinty-nmd-$tag-$cpu.tar.gz" -C "$out" sinty-nmd libsinty-system-core.so.1
done
