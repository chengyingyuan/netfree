netfree
============================================================

# Rational

This project is a network tunnel solution inspired by simpletun and tcpredirect. Tcpredirect tries forwarding tcp traffic, encrypting and decrypting network traffic as necessary. It can be applied well in situation where network privacy is concerned when proxying http or https traffic. Unfortunately, it doesn't support udp and lower ip layer protocols. Simpletun builds a good example for proxying network traffic. But as its name indicating, it is simple and cannot encrypt/decrypt connection. So, netfree enhances both of them, making proxying as well as security easily.

Here is the applying case.

I have a raspberry pi with two wifi interfaces, one for wifi host spot(hostapd), one for internet access. I'm going to route all traffic from hostapd to internet. But I donn't want to expose my internect connections to local isp. So I rent a vps from a cloud provider, such as digitalocean or amazon. Through netfree, I can package my internect connections into udp tunnel to the cloud vps, where the packages gotten unpacked and NATed to internet. In netfree terminology, raspberry pi is client side, and cloud vps is server side.

# Usage

For debian based distributions, such as raspbian or ubuntu, make ensure libssl-dev, gcc, make installed ahead.

sudo apt-get update
sudo apt-get install -y libssl-dev gcc make

Change to project root directory, run

make

Change to scripts directory, 

cp netfree_config.sh.example netfree_config.sh

Run related scripts depending on tunnel side.


# References

https://github.com/gregnietsky/simpletun
https://backreference.org/2010/03/26/tuntap-interface-tutorial/
https://backreference.org/2009/11/13/openssh-based-vpns/
http://sites.inka.de/~W1011/devel/tcp-tcp.html
http://blog.bofh.it/debian/id_379
https://hamy.io/post/0002/openvpn-tcp-or-udp-tunneling/
https://stackoverflow.com/questions/973439/how-to-set-the-dont-fragment-df-flag-on-a-socket
https://linux.die.net/man/7/ip
