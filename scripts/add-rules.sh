sudo curl --unix-socket /tmp/network.sock http:/unix/services/forwarder/expose -X POST -d '{"local":":8443","remote":"192.168.127.2:8443"}'
sudo curl --unix-socket /tmp/network.sock http:/unix/services/forwarder/expose -X POST -d '{"local":":8445","remote":"192.168.127.2:8445"}'