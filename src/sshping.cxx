/*
   Copyright (c) 2017-2019 by Uncle Spook

   MIT License

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
 */

#ifdef _WIN32
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
  #define LIBSSH_STATIC 1
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <unistd.h>
#endif

#include <algorithm>
#include <inttypes.h>
#include <iostream>
#include <libssh/libssh.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <vector>

#if (LIBSSH_VERSION_MAJOR == 0) && (LIBSSH_VERSION_MINOR < 6)
  #error "*** libssh must be version 0.6 or later"
#endif

#include "optionparser.h"

#define DEFAULT_COUNT 1000
#define MEGA         1000000
#define GIGA      1000000000
#define GIGAF     1000000000.0

#ifndef PRIu64
  #define PRIu64 "llu"
#endif

uint64_t		t0;
uint64_t		t1;
bool            delimited  = false;
bool            key_wait   = false;
bool            human      = false;
int             zero       = 0;
int             verbosity  = 0;
int             char_limit = 0;
int             time_limit = 0;
int             contim     = 10;
int             size       = 8;
char            rembuf[32];
char*           remfile    = NULL;
char*           bynd       = NULL;
char*           port       = NULL;
char*           addr       = NULL;
char*           user       = NULL;
char*           pass       = NULL;
char*           iden       = NULL;
std::string     echo_cmd   = "cat > /dev/null";

/* *INDENT-OFF* */
// Define a required argument for optionparse
struct Arg
    : public option::Arg {
    static option::ArgStatus Reqd(const option::Option & option, bool msg) {
        if (option.arg != 0) return option::ARG_OK;
        if (msg) fprintf(stderr, "Option '%s' requires an argument\n", option.name);
        return option::ARG_ILLEGAL;
    }
};

// CLI options and usage help
enum  { opNONE,
        opBIND,
        opNUM,
        opCTIM,
        opDLM,
        opECMD,
        opHELP,
        opHUMAN,
        opID,
        opKEY,
        opPWD,
        opSIZE,
        opTIME,
        opTEST,
        opVERB,
        opREM };
const option::Descriptor usage[] = {
    {opNONE, 0, "",  "",              Arg::None,     "Usage: sshping [options] [user@]addr[:port]" },
    {opNONE, 0, "",  "",              Arg::None,     " " },
    {opNONE, 0, "",  "",              Arg::None,     "  SSH-based ping that measures interactive character echo latency" },
    {opNONE, 0, "",  "",              Arg::None,     "  and file transfer throughput.  Pronounced \"shipping\"." },
    {opNONE, 0, "",  "",              Arg::None,     " " },
    {opNONE, 0, "",  "",              Arg::None,     "Options:" },
    {opBIND, 0, "b", "bindaddr",      Arg::Reqd,     "  -b  --bindaddr IP    Bind to this source address"},
    {opNUM,  0, "c", "count",         Arg::Reqd,     "  -c  --count NCHARS   Number of characters to echo, default 1000"},
    {opDLM,  0, "d", "delimited",     Arg::None,     "  -d  --delimited      Use delimiters in big numbers, eg 1,234,567"},
    {opECMD, 0, "e", "echocmd",       Arg::Reqd,     "  -e  --echocmd CMD    Use CMD for echo command; default: cat > /dev/null"},
    {opHELP, 0, "h", "help",          Arg::None,     "  -h  --help           Print usage and exit"},
    {opHUMAN,0, "H", "human-readable",Arg::None,     "  -H  --human-readable Use flesh-friendly units"},
    {opID,   0, "i", "identity",      Arg::Reqd,     "  -i  --identity FILE  Identity file, ie ssh private keyfile"},
    {opKEY,  0, "k", "keyboard-wait", Arg::None,     "  -k  --keyboard-wait  Program will wait for keyboard input to close"},
    {opPWD,  0, "p", "password",      Arg::Optional, "  -p  --password PWD   Use password PWD (can be seen, use with care)"},
    {opTEST, 0, "r", "runtests",      Arg::Reqd,     "  -r  --runtests e|s   Run tests e=echo s=speed; default es=both"},
    {opSIZE, 0, "s", "size",          Arg::Reqd,     "  -s  --size MB        For speed tests, send/recv MB megabytes; default=8 MB"},
    {opTIME, 0, "t", "time",          Arg::Reqd,     "  -t  --time SECS      Time limit for echo test"},
    {opCTIM, 0, "T", "connect-time",  Arg::Reqd,     "  -T  --connect-time S Time limit for ssh connection; default 10 sec"},
    {opVERB, 0, "v", "verbose",       Arg::None,     "  -v  --verbose        Show more output, use twice for lots: -vv"},
    {opREM,  0, "z", "remote",        Arg::Reqd,     "  -z  --remote FILE    Remote file for up/download tests;"},
    {opNONE, 0, "",  "",              Arg::None,     "                           default=/tmp/sshping-PID.tmp" },
    {0,0,0,0,0,0}
};
/* *INDENT-ON* */

#ifdef _WIN32
// TODO: Move this and other Winderz stuff to its own file
  #include <Ws2tcpip.h>
  #include <windows.h>
  #include <conio.h>

  double PCFreq = 0;

  // Replacement for the getpass UNIX method
  char *getpass(const char *prompt) {
	  static const int PASS_MAX = 512;
      char getpassbuf[PASS_MAX + 1];
      size_t i = 0;
      int c;
      if (prompt) {
          fputs(prompt, stderr);
          fflush(stderr);
      }
      for (;;) {
      	c = _getch();
          if (c != 0) {
              if (c == '\r') {
                  getpassbuf[i] = '\0';
                  break;
              }
              else if (c == '\3') {
                  exit(0);
              }
              else if (c == '\b' && i != 0) {
                  getpassbuf[i] = NULL;
                  i--;
              }
              else if (i < PASS_MAX && c != '\b') {
                  getpassbuf[i++] = c;
              }
              if (i >= PASS_MAX) {
                  getpassbuf[i] = '\0';
                  break;
              }
      	  }
      }
      if (prompt) {
          fputs("\r\n", stderr);
          fflush(stderr);
      }
      return _strdup(getpassbuf);
  }

  // Replacement for the getpid UNIX method
  DWORD getpid() {
      return GetCurrentProcessId();
  }

  // Replacement for the strsep UNIX method
  char* strsep(char** stringp, const char* delim) {
      char* start = *stringp;
      char* p;
      p = (start != NULL) ? strpbrk(start, delim) : NULL;
      if (p == NULL) {
          *stringp = NULL;
      }
      else {
          *p = '\0';
          *stringp = p + 1;
      }
      return start;
  } 

  // Replacement for the clock_gettime UNIX method
  uint64_t get_time() {
      LARGE_INTEGER li;
      long temp = 0;
      if (PCFreq == 0) {
          QueryPerformanceFrequency(&li);
          PCFreq = (double)li.QuadPart / GIGA;
      }
      QueryPerformanceCounter(&li);
      return static_cast<uint64_t>(static_cast<double>(li.QuadPart) / PCFreq);
  }

  void keyboard_wait() {
      _getch();
  }
#else
  #include <termios.h>
  #include <arpa/inet.h>
  void keyboard_wait() {
      static struct termios oldt, newt;
      tcgetattr(0, &oldt);
      newt = oldt;
      newt.c_lflag &= ~ICANON;
      newt.c_lflag &= ~ECHO;
      tcsetattr(0, TCSANOW, &newt);
      getchar();
      tcsetattr(0, TCSANOW, &oldt);
  }
  uint64_t get_time() {
      struct timespec tz;
      clock_gettime(CLOCK_MONOTONIC, &tz);
      uint64_t output = (tz.tv_sec * GIGA + tz.tv_nsec);
      return output;
  }
#endif

// Outta here!
void die(const char* msg, int exit_no) {
    fprintf(stderr, "*** %s\n", msg);
    if (key_wait) {
        printf("Press any key to exit...\n");
        keyboard_wait();
    }
    exit(exit_no);
}

void die(int exit_no) {
    if (key_wait) {
        printf("Press any key to exit...\n");
        keyboard_wait();
    }
    exit(exit_no);
}

// Format integers with delimiters
//  'scale' is the input scale, and MUST be multiple of 3 in the range -9 to 24,
//  otherwise this will probably blow up.  You have been warned.
std::string fmtnum(uint64_t n, int scale, const char* units) {

    // Our smallest time precision is nanoseconds, so no need to go smaller than 'nano'.
    // Instead of 'μ' we use 'u' for micro because it's a 1-byte character
    static const char prefixes[] = "num kMGTPEZY";

    if (!human) {
        char buf[21];
        snprintf(buf, sizeof(buf), "%" PRIu64, n);
        std::string fstr = buf;
        if (delimited) {
            ssize_t i = fstr.length() - 3;
            while (i > 0) {
                fstr.insert(i, ",");    // TODO: Use the locale-specific method (LC_NUMERIC) and the ' flag so printf() does the work
                i -= 3;
            }
        }
        if (scale || strlen(units)) fstr += " ";
        if (scale)                  fstr += prefixes[3+scale/3];
        fstr += units;
        return fstr;
    }
    else {
        // Flesh-friendly formats, we'll use 3-digits of precision
        //  x.xx prefix+unit
        //  xx.x prefix+unit
        //  xxx prefix+unit
        double f = n;
        std::string fstr;
        char buf[7 + strlen(units)];
        for (int p=scale; p <= 24; p += 3) {
            if (f >= 1000.0) {
                f /= 1000.0;
                continue;
            }
            if (f >= 100.0) {
                snprintf(buf, sizeof(buf), "%3.0f %c%s", f, prefixes[3+p/3], units);
                fstr = buf;
                return fstr;
            }
            if (f >= 10.0) {
                snprintf(buf, sizeof(buf), "%4.1f %c%s", f, prefixes[3+p/3], units);
                fstr = buf;
                return fstr;
            }
            snprintf(buf, sizeof(buf), "%4.2f %c%s", f, prefixes[3+p/3], units);
            fstr = buf;
            return fstr;
        }

        // If we fall thru, it's too big or too small, so use a generic format
        f = n;
        snprintf(buf, sizeof(buf), "%'f %s", f, units);
        fstr = buf;
        return fstr;
    }
}

// Nanosecond difference between two timestamps
uint64_t nsec_diff(uint64_t u0, uint64_t u1) {
	return u1 > u0 ? u1 - u0 : u0 - u1;
}

// Standard deviation
uint64_t standard_deviation(const std::vector<uint64_t> & list, const uint64_t avg) {
    if (list.size() < 2) return 0;
    double sum = 0;
    for (size_t i=0; i < list.size(); i++) {
        sum += pow(list[i] > avg ? list[i] - avg : avg - list[i], 2);  // unsigned math, hence the ternary
    }
    return static_cast<uint64_t>(static_cast<double>(sqrt(sum/double(list.size()-1))));
}

// Consume all pending output and discard it
int discard_output(ssh_channel & chn,
                   int           max_wait = 1000) {
    char buffer[256];
    while (ssh_channel_is_open(chn) && !ssh_channel_is_eof(chn)) {
        int nbytes = ssh_channel_read_timeout(chn,
                                              buffer,
                                              sizeof(buffer),
                                              /*is-stderr*/ 0,
                                              max_wait);
        if (nbytes < 0) {
            return SSH_ERROR;
        }
        if (nbytes == 0) {
            return SSH_OK; // timeout, we're done
        }
    }
    return SSH_ERROR;
}

// Try public-key authentication
int authenticate_pubkey(ssh_session & ses) {
    int rc = ssh_userauth_publickey_auto(ses, NULL, NULL);  // TODO:  allow passphrase
    if (verbosity && (rc == SSH_AUTH_ERROR)) {
        fprintf(stderr, "  * Public-key authentication failed: %s\n", ssh_get_error(ses));
    }
    return rc;
}

// Try password authentication
int authenticate_password(ssh_session & ses) {
    if (!pass) {
        char qbuf[256];
        if (user) {
            snprintf(qbuf, sizeof(qbuf),"Enter password for user %s: ", user);
        }
        else {
            strncpy(qbuf, "Enter your password: ", sizeof(qbuf));
        }
        uint64_t t2 = get_time();
        pass = getpass(qbuf);
        uint64_t t3 = get_time();
        t0 = nsec_diff(t3, t2) + t0;
    }
    int rc = ssh_userauth_password(ses, NULL, pass);
    if (verbosity && (rc == SSH_AUTH_ERROR)) {
        fprintf(stderr, "  * Password authentication failed: %s\n", ssh_get_error(ses));
    }
    return rc;
}

// Try keyboard-interactive authentication
int authenticate_kbdint(ssh_session & ses) {
    int rc = ssh_userauth_kbdint(ses, NULL, NULL);
    while (rc == SSH_AUTH_INFO) {
        const char* name        = ssh_userauth_kbdint_getname(ses);
        const char* instruction = ssh_userauth_kbdint_getinstruction(ses);
        int         nprompts    = ssh_userauth_kbdint_getnprompts(ses);
        if (strlen(name) > 0) {
            printf("%s\n", name);
        }
        if (strlen(instruction) > 0) {
            printf("%s\n", instruction);
        }
        for (int iprompt = 0; iprompt < nprompts; iprompt++) {
            const char* prompt;
            char        echo;
            prompt = ssh_userauth_kbdint_getprompt(ses, iprompt, &echo);
            if (echo) {
                char buffer[128], * ptr;
                printf("%s", prompt);
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    return SSH_AUTH_ERROR;
                }
                buffer[sizeof(buffer) - 1] = '\0';
                if ((ptr = strchr(buffer, '\n')) != NULL) {
                    *ptr = '\0';
                }
                if (ssh_userauth_kbdint_setanswer(ses, iprompt, buffer) < 0) {
                    return SSH_AUTH_ERROR;
                }
                memset(buffer, 0, strlen(buffer));
            }
            else {
                if (!pass) {
                    uint64_t t2 = get_time();
                    pass = getpass(prompt);
                    uint64_t t3 = get_time();
                    t0 = nsec_diff(t3, t2) + t0;
                }
                if (ssh_userauth_kbdint_setanswer(ses, iprompt, pass) < 0) {
                    return SSH_AUTH_ERROR;
                }
            }
        }
        rc = ssh_userauth_kbdint(ses, NULL, NULL);
    }
    if (verbosity &&  (rc == SSH_AUTH_ERROR)) {
        fprintf(stderr, "  * Keyboard-interactive authentication failed: %s\n", ssh_get_error(ses));
    }
    return rc;
}

// Try "none" authentication
int authenticate_none(ssh_session & ses) {
    int rc = ssh_userauth_none(ses, NULL);
    if (verbosity && (rc == SSH_AUTH_ERROR)) {
        fprintf(stderr, "  * Null authentication failed: %s\n", ssh_get_error(ses));
    }
    return rc;
}

// Try all server-allowed authentication methods
int authenticate_all(ssh_session & ses) {

    // We must first call the 'none' method to "load" the available methods
    int rc = ssh_userauth_none(ses, NULL);
    if (rc == SSH_AUTH_SUCCESS || rc == SSH_AUTH_ERROR) {
        return rc;
    }

    // Find out what the server allows
    int method = ssh_userauth_list(ses, NULL);
    if (method & SSH_AUTH_METHOD_NONE) {
        rc = authenticate_none(ses);
        if (rc == SSH_AUTH_SUCCESS) {
            if (verbosity) printf("+++ Authenticated by NULL method\n");
            return rc;
        }
        if (verbosity) printf("  + Authentication by NULL method failed\n");
    }
    if (method & SSH_AUTH_METHOD_PUBLICKEY) {
        rc = authenticate_pubkey(ses);
        if (rc == SSH_AUTH_SUCCESS) {
            if (verbosity) printf("+++ Authenticated by public key method\n");
            return rc;
        }
        if (verbosity) printf("  + Authentication by public key method failed\n");
    }
    if (method & SSH_AUTH_METHOD_INTERACTIVE) {
        rc = authenticate_kbdint(ses);
        if (rc == SSH_AUTH_SUCCESS) {
            if (verbosity) printf("+++ Authenticated by keyboard-interacive method\n");
            return rc;
        }
        if (verbosity) printf("  + Authentication by keyboard-interactive method failed\n");
    }
    if (method & SSH_AUTH_METHOD_PASSWORD) {
        rc = authenticate_password(ses);
        if (rc == SSH_AUTH_SUCCESS) {
            if (verbosity) printf("+++ Authenticated by password method\n");
            return rc;
        }
        if (verbosity) printf("  + Authentication by password method failed\n");
    }
    return SSH_AUTH_ERROR;
}

// Start the session to the target system
ssh_session begin_session() {

    // Create session
    if (verbosity) {
        printf("+++ Attempting connection to %s:%s\n", addr, port);
    }
    ssh_session ses;
    ses = ssh_new();
    if (ses == NULL) {
        return NULL;
    }

    // Set options
    int sshverbose = verbosity >= 2 ? SSH_LOG_PROTOCOL : 0;
    int stricthost = 0;
    ssh_options_set(ses, SSH_OPTIONS_HOST, addr);
    ssh_options_set(ses, SSH_OPTIONS_PORT_STR, port);
    if (user) {
        ssh_options_set(ses, SSH_OPTIONS_USER, user);
    }
    if (contim) {
        ssh_options_set(ses, SSH_OPTIONS_TIMEOUT, &contim);
        ssh_options_set(ses, SSH_OPTIONS_TIMEOUT_USEC, &zero);
    }
    ssh_options_set(ses, SSH_OPTIONS_COMPRESSION, "no");
    ssh_options_set(ses, SSH_OPTIONS_STRICTHOSTKEYCHECK, &stricthost);
    ssh_options_set(ses, SSH_OPTIONS_LOG_VERBOSITY, &sshverbose);
    if (iden) {
        ssh_options_set(ses, SSH_OPTIONS_IDENTITY, iden);
    }
    if (bynd) {
        ssh_options_set(ses, SSH_OPTIONS_BINDADDR, bynd);
    }

    // Try to connect
    t0 = get_time();
    int rc = ssh_connect(ses);
    if (rc != SSH_OK) {
        fprintf(stderr, "*** Error connecting: %s\n", ssh_get_error(ses));
        return NULL;
    }
    if (verbosity) {
        printf("+++ Connected to %s:%s\n", addr, port);
    }

    // Authenticate the user
    if (authenticate_all(ses) != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "*** Cannot authenticate user %s\n", user ? user : "");
        return NULL;
    }
    return ses;
}

// Login to a shell
ssh_channel login_channel(ssh_session & ses) {

    // Start the channel
    ssh_channel chn = ssh_channel_new(ses);
    if (chn == NULL) {
        return NULL;
    }
    int rc = ssh_channel_open_session(chn);
    if (rc != SSH_OK) {
        ssh_channel_free(chn);
        return NULL;
    }

    // Make it be interactive-like
    rc = ssh_channel_request_pty(chn);
    if (rc != SSH_OK) {
        ssh_channel_free(chn);
        return NULL;
    }
    rc = ssh_channel_change_pty_size(chn, 80, 24);
    if (rc != SSH_OK) {
        ssh_channel_free(chn);
        return NULL;
    }

    // Run a shell
    rc = ssh_channel_request_shell(chn);
    if (rc != SSH_OK) {
        ssh_channel_free(chn);
        return NULL;
    }

    // Flush output from the login
    rc = discard_output(chn, 1300);
    if (rc != SSH_OK) {
        ssh_channel_free(chn);
        return NULL;
    }

    // Marker: Timing point for the initial handshake
    t1 = get_time();
    if (verbosity) {
        printf("+++ Login shell established\n");
    }
    printf("ssh-Login-Time: %21s\n", fmtnum(nsec_diff(t0, t1), -9, "s").c_str());

    return chn;
}

// Run a single-character-at-a-time echo test
int run_echo_test(ssh_channel & chn) {

    // Start the echo server
    echo_cmd += "\n";
    int nbytes = ssh_channel_write(chn, echo_cmd.c_str(), echo_cmd.length());
    if (nbytes != (int)echo_cmd.length()) {
        return SSH_ERROR;
    }
    int rc = discard_output(chn, 1500);
    if (rc != SSH_OK) {
        return rc;
    }
    if (verbosity) {
        printf("+++ Echo responder started\n");
    }

    //  Send one character at a time, read back the response, getting timing data as we go
    uint64_t              tot_latency = 0;
    char                  wbuf[]      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n";
    char                  rbuf[2];
    std::vector<uint64_t> latencies;
    time_t                endt = time(NULL) + time_limit;
    time_t                tv   = 0;
    for (int n = 0; (!char_limit || (n < char_limit))
                 && (!time_limit || (time(NULL) <= endt)); n++) {

        uint64_t tw = get_time();

        int i = n % (sizeof(wbuf) - 2);
        nbytes = ssh_channel_write(chn, &wbuf[i], 1);
        if (nbytes != 1) {
            fprintf(stderr, "\n*** write put %d bytes, expected 1\n", nbytes);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read_timeout(chn, &rbuf, 1, /*is-stderr*/ 0, 2500);
        if (nbytes != 1) {
            fprintf(stderr, "\n*** read got %d bytes, expected 1\n", nbytes);
            return SSH_ERROR;
        }
        if (wbuf[i] != rbuf[0]) {
            fprintf(stderr, "\n*** Echo failed, sent %%x%2.2x yet got %%x%2.2x\n", wbuf[i], rbuf[0]);
            return SSH_ERROR;
        }

        uint64_t tr = get_time();

        uint64_t latency = nsec_diff(tw, tr);
        latencies.push_back(latency);
        tot_latency += latency;

        if (verbosity && ((time(NULL) - tv) > 3)) {
            tv = time(NULL);
            printf("  + %d/%d\r", n, char_limit);
            fflush(stdout);
        }
        if (delimited && !verbosity) {
            if ((time(NULL) - tv) > 1) {
                tv = time(NULL);
                printf("Echo-Count:        %13d\r", n);
                fflush(stdout);
            }
        }
    }

    int num_sent = latencies.size();
    if (!num_sent) {
        fprintf(stderr, "*** Unable to get any echos in given time\n");
        return SSH_ERROR;
    }
    if (num_sent < 13) {
        printf("-*- Warning: too few echos to be statistically valid\n");
    }
    uint64_t avg_latency = tot_latency / num_sent;
    uint64_t med_latency;
    std::sort(latencies.begin(), latencies.end());
    uint64_t min_latency = latencies[0];
    uint64_t max_latency = latencies[num_sent - 1];
    if (num_sent & 1) {
        med_latency = latencies[(num_sent + 1) / 2 - 1];
    }
    else {
        med_latency = (latencies[num_sent / 2 - 1] + latencies[(num_sent + 1) / 2 - 1]) / 2;
    }
    uint64_t stddev = standard_deviation(latencies, avg_latency);
    printf("Minimum-Latency:   %18s\n", fmtnum(min_latency, -9, "s").c_str());
    printf("Median-Latency:    %18s\n", fmtnum(med_latency, -9, "s").c_str());
    printf("Average-Latency:   %18s\n", fmtnum(avg_latency, -9, "s").c_str());
    printf("Average-Deviation: %18s\n", fmtnum(stddev,      -9, "s").c_str());
    printf("Maximum-Latency:   %18s\n", fmtnum(max_latency, -9, "s").c_str());
    printf("Echo-Count:        %17s\n", fmtnum(num_sent,     0, "B").c_str());

    // Terminate the echo responder
    // TODO
    if (verbosity) {
        printf("+++ Echo responder finished\n");
    }
    return SSH_OK;
}

// Run an upload speed test
int run_upload_test(ssh_session ses) {

    // Inits
    if (verbosity) {
        printf("+++ Upload speed test started, remote file is %s\n", remfile);
    }
    printf("Upload-Size:       %17s\n", fmtnum(size * MEGA, 0, "B").c_str());

    ssh_scp scp = ssh_scp_new(ses, SSH_SCP_WRITE, remfile);
    if (scp == NULL) {
        fprintf(stderr, "*** Cannot allocate scp context: %s\n", ssh_get_error(ses));
        return SSH_ERROR;
    }

    int rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "*** Cannot init scp context: %s\n", ssh_get_error(ses));
        ssh_scp_free(scp);
        return rc;
    }

    uint64_t t2 = get_time();

#ifdef _WIN32
	const int mode = 448;
#else
	const int mode = S_IRWXU;
#endif
    char buf[MEGA];
    srand(getpid());
    for (size_t i=0; i < sizeof(buf); i++) {
        buf[i] = (rand() & 0x3f) + 32;
    }
    for (int i=0; i < size; i++) {
        rc = ssh_scp_push_file(scp, remfile, MEGA, mode);
        if (rc != SSH_OK) {
            fprintf(stderr, "*** Can't open remote file: %s\n", ssh_get_error(ses));
            return rc;
        }

        rc = ssh_scp_write(scp, buf, MEGA);
        if (rc != SSH_OK) {
            fprintf(stderr, "*** Can't write to remote file: %s\n", ssh_get_error(ses));
            return rc;
        }
    }
    ssh_scp_close(scp);
    ssh_scp_free(scp);

    uint64_t t3 = get_time();
    double duration = double(nsec_diff(t3, t2)) / GIGAF;
    if (duration == 0.0) duration = 0.000001;
    uint64_t Bps = static_cast<uint64_t>(static_cast<double>(size * MEGA) / duration);

    printf("Upload-Rate:       %19s\n", fmtnum(Bps, 0, "B/s").c_str());
    if (verbosity) {
        printf("+++ Upload speed test completed\n");
    }
    return SSH_OK;
}

// Run a download speed test
int run_download_test(ssh_session ses) {

    // Inits
    if (verbosity) {
        printf("+++ Download speed test started, remote file is %s\n", remfile);
    }
    printf("Download-Size:     %17s\n", fmtnum(size * MEGA, 0, "B").c_str());

    char   buf[MEGA];
    size_t avail = 0;
    size_t remaining = size * MEGA;

    uint64_t t2 = get_time();
    while (remaining) {
        ssh_scp scp = ssh_scp_new(ses, SSH_SCP_READ, remfile);
        if (scp == NULL) {
            fprintf(stderr, "*** Cannot allocate scp context: %s\n", ssh_get_error(ses));
            return SSH_ERROR;
        }

        int rc = ssh_scp_init(scp);
        if (rc != SSH_OK) {
            fprintf(stderr, "*** Cannot init scp context: %s\n", ssh_get_error(ses));
            ssh_scp_free(scp);
            return rc;
        }

        rc = ssh_scp_pull_request(scp);
        if (rc != SSH_SCP_REQUEST_NEWFILE) {
            fprintf(stderr, "*** Cannot request download file - got %d: %s\n", rc, ssh_get_error(ses));
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            return rc;
        }

        if (!avail) {
            avail = ssh_scp_request_get_size(scp);
            if (verbosity) {
                printf("+++ Available size of download: %lu Bytes\n", avail);
                if (remaining > avail) {
                    printf("  + (Will repeat download as needed)\n");
                }
            }
            if (!avail) {
                fprintf(stderr, "*** Remote file size must be non-zero\n");
                ssh_scp_close(scp);
                ssh_scp_free(scp);
                return rc;
            }
        }

        size_t amount = avail;
        if (amount > remaining)   amount = remaining;
        if (amount > sizeof(buf)) amount = sizeof(buf);
        ssh_scp_accept_request(scp);
        rc = ssh_scp_read(scp, buf, amount);
        if (rc == SSH_ERROR) {
            fprintf(stderr, "*** Failed read on file download: %s\n", ssh_get_error(ses));
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            return rc;
        }

        remaining -= amount;
        ssh_scp_close(scp);
        ssh_scp_free(scp);
    }

    uint64_t t3 = get_time();
    double duration = double(nsec_diff(t3, t2)) / GIGAF;
    if (duration == 0.0) duration = 0.000001;
    uint64_t Bps = static_cast<uint64_t>(static_cast<double>(size * MEGA) / duration);

    printf("Download-Rate:     %19s\n", fmtnum(Bps, 0, "B/s").c_str());
    if (verbosity) {
        printf("+++ Download speed test completed\n");
    }
    return SSH_OK;
}

// Terminate the channel
void logout_channel(ssh_channel & chn) {
    ssh_channel_close(chn);
    ssh_channel_send_eof(chn);
    ssh_channel_free(chn);
    if (verbosity) {
        printf("+++ Login shell closed\n");
    }
}

// Finish the session
void end_session(ssh_session & ses) {
    ssh_disconnect(ses);
    ssh_free(ses);
    if (verbosity) {
        printf("+++ Disconnected\n");
    }
}

// returns port, ip_and_port gets converted to just ip
std::string parse_ip_address(std::string& ip_and_port) {
    char buf[16];
    // is ip address alone
    if (inet_pton(AF_INET, ip_and_port.c_str(), buf) ||
        inet_pton(AF_INET6, ip_and_port.c_str(), buf)) {
        return "22";
    }

    // That didn't work, try splitting the port off

    // Remove square brackets
    ip_and_port.erase(remove(ip_and_port.begin(), ip_and_port.end(), '['),
        ip_and_port.end());
    ip_and_port.erase(remove(ip_and_port.begin(), ip_and_port.end(), ']'),
        ip_and_port.end());

    const size_t ip_and_port_colon = ip_and_port.find_last_of(':');
    const std::string ip = ip_and_port.substr(0, ip_and_port_colon);
    const std::string port = ip_and_port.substr(ip_and_port_colon + 1);
    // is ip and port
    if (inet_pton(AF_INET, ip.c_str(), buf) ||
        inet_pton(AF_INET6, ip.c_str(), buf)) {
        ip_and_port = ip;
        return port;
    }

    // That didn't work check if hostname
    if (ip_and_port_colon != std::string::npos) {
        ip_and_port = ip;
        return port;
    }

    // if empty string, not valid ip address
    return "22";
}

// The Main
int main(int   argc,
         char* argv[]) {

    // Process the command line
    argc -= (argc > 0); argv += (argc > 0); // skip program name argv[0] if present
    option::Stats  stats(usage, argc, argv);
    option::Option* opts = new option::Option[stats.options_max];
    option::Option* buffer = new option::Option[stats.buffer_max + 16];
    option::Parser parse(usage, argc, argv, opts, buffer);
    key_wait = opts[opKEY];
    if (opts[opHELP]) {
        option::printUsage(std::cerr, usage);
        die(0);
    }
    if (parse.error() || (argc < 1) || (parse.nonOptionsCount() != 1)) {
        option::printUsage(std::cerr, usage); // I wish it didn't use streams
        die("Command error, see usage\n", 255);
    }
    bool anyunk = false;
    for (option::Option* opt = opts[opNONE]; opt; opt = opt->next()) {
        if (!anyunk) {
            option::printUsage(std::cerr, usage);
        }
        fprintf(stderr, "*** Unknown option %s\n", opt->name);
        anyunk = true;
    }
    if (anyunk) {
        die(0);
    }

    // Parse values
    port = (char*)parse.nonOption(0);
    user = strsep(&port, "@");
    if (!port || !port[0]) {
        port = user;
        user = NULL;
    }
    std::string ip = port;
    std::string temp_port = parse_ip_address(ip);
    port = (char*)temp_port.c_str();
    addr = (char*)ip.c_str();
    int nport = atoi(port);
    if (!nport || (nport < 1) || (nport > 65535)) {
        die("Bad port, must be integer from 1 to 65535\n", 255);
    }

    // Setup options
    human     = opts[opHUMAN];
    delimited = opts[opDLM];
    if (opts[opECMD]) {
        echo_cmd = opts[opECMD].arg;
    }
    if (opts[opPWD]) {
        pass = (char*)opts[opPWD].arg;
    }
    if (opts[opID]) {
        iden = (char*)opts[opID].arg;
    }
    if (opts[opBIND]) {
        bynd = (char*)opts[opBIND].arg;
    }
    if (opts[opREM]) {
        remfile = (char*)opts[opREM].arg;
    }
    else {
        snprintf(rembuf, sizeof(rembuf), "/tmp/sshping-%9.9d.tmp", getpid());
        remfile = (char*)rembuf;   // point to buffer we just filled in
    }
    if (opts[opSIZE]) {
        size = atoi(opts[opSIZE].arg);
    }
    if (opts[opNUM]) {
        char_limit = atoi(opts[opNUM].arg);
    }
    if (opts[opTIME]) {
        time_limit = atoi(opts[opTIME].arg);
    }
    if (opts[opCTIM]) {
        contim = atoi(opts[opCTIM].arg);
    }
    if (!opts[opNUM] && !opts[opTIME]) {
        char_limit = DEFAULT_COUNT;
    }
    bool do_echo  = !opts[opTEST] || strchr(opts[opTEST].arg, 'e');
    bool do_speed = !opts[opTEST] || strchr(opts[opTEST].arg, 's');
    if (do_echo && (char_limit <= 0) && (time_limit <= 0)) {
        die("For the echo test, a time limit or character count is required\n", 255);
    }
    if (do_speed && (size <= 0)) {
        die("For the speed test, the transfer size must be 1 MB or more\n", 255);
    }
    verbosity = opts[opVERB].count();

    // Keep valgrind happy ;-)
    delete[] opts;
    delete[] buffer;

    // Show what's up
    if (verbosity) {
        printf("User: %s\n", user ? user : "--not specified--");
        printf("Host: %s\n", addr);
        printf("Port: %d\n", nport);
        printf("Echo: %s\n", echo_cmd.c_str());
        printf("\n");
    }

    // Begin Session and login
    ssh_session ses = begin_session();
    if (!ses) {
        die("Cannot establish ssh session", 255);
    }
    ssh_channel chn = login_channel(ses);
    if (!chn) {
        die("Cannot login and run echo command", 255);
    }

    // Run the tests
    if (do_echo) {
        run_echo_test(chn);
    }
    if (do_speed) {
        run_upload_test(ses);
        run_download_test(ses);
    }

    // Program will wait for keyboard input to close
    if (key_wait) {
        printf("Press any key to exit...\n");
        keyboard_wait();
    }

    // Cleanup
    logout_channel(chn);
    end_session(ses);
}

