default: sshping

sshping: bin/sshping

bin/sshping: src/sshping.cxx /usr/include/libssh/libssh.h
	g++ -I ext/ -o bin/sshping src/sshping.cxx -lssh

/usr/include/libssh/libssh.h:
	echo '*** Please install libssh-dev, libssh-devel, or similar package'
	exit 2

man: /usr/bin/pod2man doc/sshping.8

doc/sshping.8: doc/sshping.pod
	pod2man -c "ssh-based ping test utility" -d 2017-10-31 -r v0.1.1 doc/sshping.pod doc/sshping.8

/usr/bin/pod2man:
	echo '*** Please install pod2man so that we can create the man page'
	exit 2

