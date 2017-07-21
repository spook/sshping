default: sshping

sshping:
	g++ -g -I ext/ -o bin/sshping src/sshping.cxx /usr/lib/x86_64-linux-gnu/libssh.so

test: sshping
	#TBD


