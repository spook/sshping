default: sshping

sshping: /usr/include/libssh/libssh.h /usr/lib/x86_64-linux-gnu/libssh.so
	g++ -g -I ext/ -o bin/sshping src/sshping.cxx /usr/lib/x86_64-linux-gnu/libssh.so

/usr/include/libssh/libssh.h /usr/lib/x86_64-linux-gnu/libssh.so:
	echo '*** Please install libssh-dev, or alter this Makefile for libssh.so'
	exit 2

test: sshping
	#TBD


