#!/usr/bin/env bash

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
TOPDIR=$(readlink -ef "$DIR"/..)
PARENT=$(readlink -ef "$TOPDIR"/..)

cd "$DIR"
cd ../debian
VER=$(cat changelog | grep blocky | egrep -o '[0-9]+\.[0-9\.]+')

TMPD=/tmp/$$.blocky
mkdir $TMPD
cd $TMPD
cp -a "$TOPDIR" .
TDIR=blocky-${VER}
TARBALL=blocky_${VER}.orig.tar.gz
mv blocky "$TDIR"
tar cfz "$TARBALL" "$TDIR"
mv -f "$TARBALL" "$PARENT"

cd "$TOPDIR"/debian

debuild -us -uc
rm -rf "$TMPD"
