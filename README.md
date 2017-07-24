# sshping
ssh-based ping: measure character-echo latency for an interactive ssh session

## Usage
```
Usage: sshping [options] [user@]addr[:port]
 
  SSH-based ping that measures interactive character echo latency.
  Pronounced "shipping".
 
Options:
  -c  --count NCHARS   Number of characters to echo, default 1000
  -e  --echocmd CMD    Use CMD for echo command; default: cat > /dev/null
  -h  --help           Print usage and exit
  -i  --identity FILE  Identity file, ie ssh private keyfile
  -p  --password PWD   Use password PWD (can be seen, use with care)
  -r  --runtime SECS   Run for SECS seconds, instead of count limit
  -v  --verbose        Show more output, use twice for more: -vv
```

### Example

```
# bin/sshping cheyenne.example.com
--- Login: 1721 msec
--- Minimum Latency: 4351 nsec
---  Median Latency: 16641 nsec  +/- 1032 std dev
--- Average Latency: 174477 nsec
--- Maximum Latency: 1514953 nsec

### Building

Have the libssh-dev package installed.  From the main directory (where 
this README.md file is located), run 'make'.  The binary should be 
built in the bin/ directory.

Note: You may have to alter the `Makefile` to point to the location of 
your libssh.so file.

