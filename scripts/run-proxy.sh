go build ec2-proxy/proxy.go
sudo ./proxy -listen vsock://:1024 -listen unix:///tmp/network.sock
