#!/bin/sh
kernelRelease=$(eval uname -r)
include="-I/lib/modules/$kernelRelease/build/include \
	 -I/lib/modules/$kernelRelease/build/include/generated/uapi"
warning="-W -Wall -Wno-compare-distinct-pointer-types"

echo "Compiling ..."
clang $include $warning -O2 -target bpf -c ulb.c -o ulb.o
echo "Compilation DONE "
sleep 1
echo "Attaching ..."
sudo ip -force link set dev lo xdp obj ulb.o 
echo "Attachment DONE"

