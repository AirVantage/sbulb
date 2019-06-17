# udploadbalancer
An UDP load balancer prototype using bcc (XDP/Bpf)

```
usage: ulb.py [-h] -vs VIRTUAL_SERVER -rs REAL_SERVER -p PORT [PORT ...]
              [-d {0,1,2,3,4}]
              ifnet

positional arguments:
  ifnet                 network interface to load balance (e.g. eth0)

optional arguments:
  -h, --help            show this help message and exit
  -vs VIRTUAL_SERVER, --virtual_server VIRTUAL_SERVER
                        <Required> Virtual server address (e.g. 10.40.0.1)
  -rs REAL_SERVER, --real_server REAL_SERVER
                        <Required> Real server address(es) (e.g. 10.40.0.1)
  -p PORT [PORT ...], --port PORT [PORT ...]
                        <Required> UDP port(s) to load balance
  -d {0,1,2,3,4}, --debug {0,1,2,3,4}
                        Use to set bpf verbosity (0 is minimal)
```
Eg : `sudo python3 ulb.py lo -vs 10.41.44.13 -rs 127.0.0.1  -p 5683 5684`
 
