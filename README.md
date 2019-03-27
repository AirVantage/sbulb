# udploadbalancer
An UDP load balancer prototype using bpf.

You need kernel header, clang to build it.
And iproute2 to attach bpf code.

The `run.sh` script will build and attach the bpf code.
