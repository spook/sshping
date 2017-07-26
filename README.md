# sshping
ssh-based ping: measure character-echo latency for an interactive ssh session

## Usage
```
Usage: sshping [options] [user@]addr[:port]
 
  SSH-based ping that measures interactive character echo latency
  and file transfer throughput.  Pronounced "shipping".
 
Options:
  -c  --count NCHARS   Number of characters to echo, default 1000
  -d  --delimited      Use delmiters in big numbers, eg 1,234,567
  -e  --echocmd CMD    Use CMD for echo command; default: cat > /dev/null
  -h  --help           Print usage and exit
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
---      Echo count:            73 Bytes
---  Transfer Speed:       435,142 Bytes/second
```

### Building

Install the libssh-dev package.  From the main directory (where  
this README.md file is located), run 'make'.  The binary should be 
built in the bin/ directory.

Note: You may have to alter the `Makefile` to point to the location of 
your libssh.so file.

