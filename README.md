# http_stress
An HTTP stress tool used to simulate a huge number of concurrent connections.

Simple usage:

```
$ http_stress 127.0.0.1:8080/index.html
```

Enable SSL:

```
$ http_stress -s 127.0.0.1:8443/index.html
```


Custom request (100) and concurrent connections (40000):

```
$ http_stress -c 40000 -r 100 127.0.0.1:8080/index.html
```

Print help:

```
$ http_stress --help
```



If you get tons of errors you probably need to tweak your linux limits, check https://medium.com/@pawilon/tuning-your-linux-kernel-and-haproxy-instance-for-high-loads-1a2105ea553e and https://helecloud.com/blog/handling-hundreds-of-thousands-of-concurrent-http-connections-on-aws/ to see how to setup them.
