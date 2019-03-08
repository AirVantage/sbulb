# udploadbalancer
An UDP load balancer prototype using bcc (XDP/Bpf)

```
usage: ulb.py [-h] -vip VIRTUAL_IP -rs REAL_SERVER -p PORT [PORT ...]
               [-d {0,1,2,3,4}]
               ifnet

positional arguments:
  ifnet                 network interface to load balance (e.g. eth0)

optional arguments:
  -h, --help            show this help message and exit
  -vip VIRTUAL_IP, --virtual_ip VIRTUAL_IP
                        <Required> The virtual IP of this loadbalancer
  -rs REAL_SERVER, --real_server REAL_SERVER
                        <Required> Real server addresse(s) e.g.
                        5E:FF:56:A2:AF:15/10.40.0.1
  -p PORT [PORT ...], --port PORT [PORT ...]
                        <Required> UDP port(s) to load balance
  -d {0,1,2,3,4}, --debug {0,1,2,3,4}
                        Use to set bpf verbosity (0 is minimal)
```
Eg : `sudo python3 ulb.py lo -vip 10.41.44.13 -rs 00:00:00:00:00:00/127.0.0.1  -p 5683 5684`
 
