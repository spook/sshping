# sshping
ssh-based ping: measure character-echo latency and bandwidth for an interactive ssh session

## Description

Use this utility to test the performance of interactive ssh sessions
or scp file transfers.  It uses ssh to log into a remote system, then 
runs two tests: the first test sends one character at a time, waiting
for each character to be returned while it records the latency time
for each.  The second test sends over scp an 8MB dummy file to /dev/null
on the remote system.

For the echo test, you may specify a character count limit (-c) or a test
time limit (-t), and also the command (-e) used on the remote system that
echoes characters back.

## Usage
```
Usage: sshping [options] [user@]addr[:port]
 
  SSH-based ping that measures interactive character echo latency
  and file transfer throughput.  Pronounced "shipping".
 
Options:
  -b  --bindaddr IP    Bind to this source address
  -c  --count NCHARS   Number of characters to echo, default 1000
  -d  --delimited      Use delmiters in big numbers, eg 1,234,567
  -e  --echocmd CMD    Use CMD for echo command; default: cat > /dev/null
  -h  --help           Print usage and exit
  -i  --identity FILE  Identity file, ie ssh private keyfile
  -p  --password PWD   Use password PWD (can be seen, use with care)
  -r  --runtests e|s   Run tests e=echo s=speed; default es=both
  -t  --time SECS      Time limit for echo test
  -v  --verbose        Show more output, use twice for lots: -vv
```

### Example

```
# bin/sshping -d cheyenne.example.com
---  ssh Login Time: 4,509,979,580 nsec
--- Minimum Latency:        67,054 nsec
---  Median Latency:   140,029,324 nsec  +/- 42,223,551 std dev
--- Average Latency:   150,710,435 nsec
--- Maximum Latency:   351,379,123 nsec
---      Echo count:         1,000 Bytes
---  Transfer Speed:       435,142 Bytes/second
```

## Building

Install the libssh-dev package.  From the main directory (where  
this README.md file is located), run 'make'.  The binary should be 
built in the bin/ directory.

Note: You may have to alter the `Makefile` to point to the location of 
your libssh.so file.

