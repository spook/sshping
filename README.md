# sshping
ssh-based ping: measure character-echo latency and bandwidth for an interactive ssh session

## Description

Use this utility to test the performance of interactive ssh sessions
or scp file transfers.  It uses ssh to log into a remote system, then 
runs two tests: the first test sends one character at a time, waiting
for each character to be returned while it records the latency time
for each.  The second test sends a dummy file over scp to /dev/null
on the remote system.

For the echo test, you may specify a character count limit (-c) or a test
time limit (-t), and also the command (-e) used on the remote system that
echoes characters back.

For the speed test, you may specify the number of megabytes to send (-s)
and the target location for the copies (-z).

## Usage
```
Usage: sshping [options] [user@]addr[:port]
 
  SSH-based ping that measures interactive character echo latency
  and file transfer throughput.  Pronounced "shipping".
 
Options:
  -b  --bindaddr IP    Bind to this source address
  -c  --count NCHARS   Number of characters to echo, default 1000
  -d  --delimited      Use delimiters in big numbers, eg 1,234,567
  -e  --echocmd CMD    Use CMD for echo command; default: cat > /dev/null
  -h  --help           Print usage and exit
  -i  --identity FILE  Identity file, ie ssh private keyfile
  -p  --password PWD   Use password PWD (can be seen, use with care)
  -r  --runtests e|s   Run tests e=echo s=speed; default es=both
  -s  --size MB        For speed test, send MB megabytes; default=8 MB
  -t  --time SECS      Time limit for echo test
  -T  --connect-time S Time limit for ssh connection; default 10 sec
  -v  --verbose        Show more output, use twice for lots: -vv
  -z  --target PATH    Target location for xfer test; default=/dev/null
```

### Example

```
# bin/sshping -d cheyenne.example.com
---  ssh Login Time: 4,286,336,535 nsec
--- Minimum Latency:   134,679,785 nsec
---  Median Latency:   139,936,318 nsec  +/- 20,996,458 std dev
--- Average Latency:   145,943,038 nsec
--- Maximum Latency:   254,836,720 nsec
---      Echo count:         1,000 Bytes
---   Transfer Size:     8,000,000 Bytes
---   Transfer Rate:       250,622 Bytes/second
```

## Building

Install the libssh-dev (or libssh-devel) package, version 0.6 or later.
From the main directory (where this README.md file is located), run 'make'.
The binary will be in the bin/ directory.  You may copy this to your
system binary location, for example:

    sudo cp bin/sshping /usr/local/bin/
    sudo chown root.root /usr/local/bin/sshping
    sudo chmod 555 /usr/local/bin/sshping

To build the man pages, install the pod2man utility (you may already
have it installed, it's often part of standard Perl). Then run 'make man'.
The uncompressed man page will be in the doc/ directory.
You can view it from there (man doc/sshping.8) but normally it's placed
in /usr/share/man/man8 in gzip'd format:

    sudo cp doc/sshping.8 /usr/share/man/man8/
    sudo gzip /usr/share/man/man8/sshping.8
    sudo chown root.root /usr/share/man/man8/sshping.8.gz
    sudo chmod 644 /usr/share/man/man8/sshping.8.gz

