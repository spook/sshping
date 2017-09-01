default: sshping

sshping: src/sshping.cxx /usr/include/libssh/libssh.h
	g++ -I ext/ -o bin/sshping src/sshping.cxx -lssh

/usr/include/libssh/libssh.h
	echo '*** Please install libssh-dev, libssh-devel, or similar package'
	exit 2



