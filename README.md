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

The default output format is RFC-2822 complaint with simple integers so
parsing is easy.  You may also display delimiters to make reading of 
large numbers easier, or you may use a "human readable" format that
displays values using SI prefixes to keep the numberic value small.

## Usage
```
Usage: sshping [options] [user@]addr[:port]
 
  SSH-based ping that measures interactive character echo latency
  and file transfer throughput.  Pronounced "shipping".
 
Options:
  -b  --bindaddr IP     Bind to this source address
  -c  --count NCHARS    Number of characters to echo, default 1000
  -d  --delimited       Use delimiters in big numbers, eg 1,234,567
  -e  --echocmd CMD     Use CMD for echo command; default: cat > /dev/null
  -h  --help            Print usage and exit
  -H  --human-readable  Use flesh-friendly units
  -i  --identity FILE   Identity file, ie ssh private keyfile
  -p  --password PWD    Use password PWD (can be seen, use with care)
  -r  --runtests e|s    Run tests e=echo s=speed; default es=both
  -s  --size MB         For speed test, send/recv MB megabytes; default=8 MB
  -t  --time SECS       Time limit for echo test
  -T  --connect-time S  Time limit for ssh connection; default 10 sec
  -v  --verbose         Show more output, use twice for lots: -vv
  -z  --remote FILE     Remote file for up/download tests;
                            default=/tmp/sshping-PID.tmp
```

### Examples

```
# bin/sshping -d cheyenne.example.com
ssh-Login-Time:      1,835,377,610 ns
Minimum-Latency:           548,993 ns
Median-Latency:            698,494 ns
Average-Latency:           704,123 ns
Average-Deviation:          72,839 ns
Maximum-Latency:         1,075,017 ns
Echo-Count:                  1,000 B
Upload-Size:             8,000,000 B
Upload-Rate:             9,371,579 B/s
Download-Size:           8,000,000 B
Download-Rate:           5,493,034 B/s

# bin/sshping -H cheyenne.example.com
ssh-Login-Time:               1.84 s
Minimum-Latency:               633 us
Median-Latency:                751 us
Average-Latency:               764 us
Average-Deviation:            63.7 us
Maximum-Latency:              1.15 ms
Echo-Count:                   1.00 kB
Upload-Size:                  8.00 MB
Upload-Rate:                  9.33 MB/s
Download-Size:                8.00 MB
Download-Rate:                5.48 MB/s
```

## Building

Install the libssh-dev (or libssh-devel) package, version 0.6 or later:

    sudo apt-get install libssh-dev
      ...or
    sudo yum install libssh-devel
      ...or whatever works on your platform

From the main directory (where this README.md file is located), run 'make':

    cd sshping
    make

The resultant binary will be in the bin/ directory.  You may copy this to 
your system binary location, for example:

    sudo cp bin/sshping /usr/local/bin/
    sudo chown root.root /usr/local/bin/sshping
    sudo chmod 555 /usr/local/bin/sshping

To build the man pages, install the pod2man utility (you may already
have it installed, it's often part of standard Perl). Then run 'make man'.
The resulting uncompressed man page will be in the doc/ directory.
You can view it from there (man doc/sshping.8) but normally it's placed
in /usr/share/man/man8 in gzip'd format:

    sudo cp doc/sshping.8 /usr/share/man/man8/
    sudo gzip /usr/share/man/man8/sshping.8
    sudo chown root.root /usr/share/man/man8/sshping.8.gz
    sudo chmod 644 /usr/share/man/man8/sshping.8.gz

That's it!

### Building with CMake

You can build this with CMake, which includes creating .deb 
or .rpm packages.  Here's how:

First, install libssh as above.  It's a prerequisite.
And of course you need CMake.
Then from the main directory (where this README.md file is located):

    mkdir build
    cd build
    cmake ..
    make
    make package

You will find the binary `sshping` as well as the .deb and/or .rpm
file in the current (build) directory.  Install those as you
would any other package.

Or you can directly install on the current system with:

    sudo make install

Enjoy!

