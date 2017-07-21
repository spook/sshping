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
