/*
   Copyright (c) 2017 by Uncle Spook

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

#include <algorithm>
#include <inttypes.h>
#include <iostream>
#include <libssh/libssh.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

struct timespec t0;
struct timespec t1;
bool            delimited  = false;
int             zero       = 0;
int             verbosity  = 0;
int             char_limit = 0;
int             time_limit = 0;
int             contim     = 10;
int             size       = 8;
char*           tgt        = (char*)"/dev/null";
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
        opID,
        opPWD,
        opSIZE,
        opTIME,
        opTEST,
        opVERB,
        opTGT };
const option::Descriptor usage[] = {
    {opNONE, 0, "",  "",             Arg::None, "Usage: sshping [options] [user@]addr[:port]" },
    {opNONE, 0, "",  "",             Arg::None, " " },
    {opNONE, 0, "",  "",             Arg::None, "  SSH-based ping that measures interactive character echo latency" },
    {opNONE, 0, "",  "",             Arg::None, "  and file transfer throughput.  Pronounced \"shipping\"." },
    {opNONE, 0, "",  "",             Arg::None, " " },
    {opNONE, 0, "",  "",             Arg::None, "Options:" },
    {opBIND, 0, "b", "bindaddr",     Arg::Reqd, "  -b  --bindaddr IP    Bind to this source address"},
    {opNUM,  0, "c", "count",        Arg::Reqd, "  -c  --count NCHARS   Number of characters to echo, default 1000"},
    {opDLM,  0, "d", "delimited",    Arg::None, "  -d  --delimited      Use delimiters in big numbers, eg 1,234,567"},
    {opECMD, 0, "e", "echocmd",      Arg::Reqd, "  -e  --echocmd CMD    Use CMD for echo command; default: cat > /dev/null"},
    {opHELP, 0, "h", "help",         Arg::None, "  -h  --help           Print usage and exit"},
    {opID,   0, "i", "identity",     Arg::Reqd, "  -i  --identity FILE  Identity file, ie ssh private keyfile"},
    {opPWD,  0, "p", "password",     Arg::Reqd, "  -p  --password PWD   Use password PWD (can be seen, use with care)"},
    {opTEST, 0, "r", "runtests",     Arg::Reqd, "  -r  --runtests e|s   Run tests e=echo s=speed; default es=both"},
    {opSIZE, 0, "s", "size",         Arg::Reqd, "  -s  --size MB        For speed test, send MB megabytes; default=8 MB"},
    {opTIME, 0, "t", "time",         Arg::Reqd, "  -t  --time SECS      Time limit for echo test"},
    {opCTIM, 0, "T", "connect-time", Arg::Reqd, "  -T  --connect-time S Time limit for ssh connection; default 10 sec"},
    {opVERB, 0, "v", "verbose",      Arg::None, "  -v  --verbose        Show more output, use twice for lots: -vv"},
    {opTGT,  0, "z", "target",       Arg::Reqd, "  -z  --target PATH    Target location for xfer test; default=/dev/null"},
    {0,0,0,0,0,0}
};
/* *INDENT-ON* */

// Outta here!
void die(const char* msg) {
    fprintf(stderr, "*** %s\n", msg);
    exit(255);
}

std::string fmtnum(uint64_t n) {
    char buf[21];
    snprintf(buf, sizeof(buf), "%" PRIu64, n);
    std::string fstr = buf;
    if (!delimited) return fstr;
    ssize_t i = fstr.length() - 3;
    while (i > 0) {
        fstr.insert(i, ",");
        i -= 3;
    }
    return fstr;
}

// Nanosecond difference between two timestamps
uint64_t nsec_diff(const struct timespec & t0,
                   const struct timespec & t1) {
    uint64_t u0 = t0.tv_sec * GIGA + t0.tv_nsec;
    uint64_t u1 = t1.tv_sec * GIGA + t1.tv_nsec;
    return u1 > u0 ? u1 - u0 : u0 - u1;
}

// Standard deviation
uint64_t standard_deviation(const std::vector<uint64_t> & list, const uint64_t avg) {
    if (list.size() < 2) return 0;
    double sum = 0;
    for (size_t i=0; i < list.size(); i++) {
        sum += pow(list[i] > avg ? list[i] - avg : avg - list[i], 2);  // unsigned math, hence the ternary
    }
    return sqrt(sum/double(list.size()-1));
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
        char  qbuf[256];
        if (user) {
            snprintf(qbuf, sizeof(qbuf),"Enter password for user %s: ", user);
        }
        else {
            strncpy(qbuf, "Enter your password: ", sizeof(qbuf));
        }
        pass = getpass(qbuf);
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
                char* ptr;
                ptr = getpass(prompt);
                if (ssh_userauth_kbdint_setanswer(ses, iprompt, ptr) < 0) {
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
    clock_gettime(CLOCK_MONOTONIC, &t0);
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

    // --- Marker: Timing point for the initial handshake
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (verbosity) {
        printf("+++ Login shell established\n");
    }
    printf("---  ssh Login Time: %13s nsec\n", fmtnum(nsec_diff(t0, t1)).c_str());

    return chn;
}

// Run a single-character-at-a-time echo test
int run_echo_test(ssh_channel & chn) {

    // Start the echo server
    echo_cmd += "\n";
    int nbytes = ssh_channel_write(chn, echo_cmd.c_str(), echo_cmd.length());
    if (nbytes != echo_cmd.length()) {
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
    for (int n = 0; (!char_limit || (n < char_limit))
                 && (!time_limit || (time(NULL) <= endt)); n++) {

        struct timespec tw;
        clock_gettime(CLOCK_MONOTONIC, &tw);

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

        struct timespec tr;
        clock_gettime(CLOCK_MONOTONIC, &tr);

        uint64_t latency = nsec_diff(tw, tr);
        latencies.push_back(latency);
        tot_latency += latency;
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
    printf("--- Minimum Latency: %13s nsec\n", fmtnum(min_latency).c_str());
    printf("---  Median Latency: %13s nsec  +/- %s std dev\n", fmtnum(med_latency).c_str(), fmtnum(stddev).c_str());
    printf("--- Average Latency: %13s nsec\n", fmtnum(avg_latency).c_str());
    printf("--- Maximum Latency: %13s nsec\n", fmtnum(max_latency).c_str());
    printf("---      Echo count: %13s Bytes\n", fmtnum(num_sent).c_str());

    // Terminate the echo responder
    // TODO
    if (verbosity) {
        printf("+++ Echo responder finished\n");
    }
    return SSH_OK;
}

// Run a speed test
int run_speed_test(ssh_session ses) {

    // Inits
    if (verbosity) {
        printf("+++ Speed test started\n");
    }
    printf("---   Transfer Size: %13s Bytes\n", fmtnum(size * MEGA).c_str());

    ssh_scp scp = ssh_scp_new(ses, SSH_SCP_WRITE, tgt);
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

    struct timespec t2;
    clock_gettime(CLOCK_MONOTONIC, &t2);

    char buf[MEGA];
    memset(buf, 's', MEGA);
    for (int i=0; i < size; i++) {
        rc = ssh_scp_push_file(scp, "speedtest.tmp", MEGA, S_IRUSR);
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

    struct timespec t3;
    clock_gettime(CLOCK_MONOTONIC, &t3);
    double duration = double(nsec_diff(t3, t2)) / GIGAF;
    if (duration == 0.0) duration = 0.000001;
    uint64_t Bps = double(size * MEGA) / duration;

    printf("---   Transfer Rate: %13s Bytes/second\n", fmtnum(Bps).c_str());
    if (verbosity) {
        printf("+++ Speed test completed\n");
    }
    return SSH_OK;
}

void logout_channel(ssh_channel & chn) {
    // All done, cleanup
    ssh_channel_close(chn);
    ssh_channel_send_eof(chn);
    ssh_channel_free(chn);
    if (verbosity) {
        printf("+++ Login shell closed\n");
    }
}

void end_session(ssh_session & ses) {
    ssh_disconnect(ses);
    ssh_free(ses);
    if (verbosity) {
        printf("+++ Disconnected\n");
    }
}


int main(int   argc,
         char* argv[]) {

    // Process the command line
    argc -= (argc > 0);argv += (argc > 0); // skip program name argv[0] if present
    option::Stats  stats(usage, argc, argv);
    option::Option opts[stats.options_max], buffer[stats.buffer_max];
    option::Parser parse(usage, argc, argv, opts, buffer);
    if (opts[opHELP]) {
        option::printUsage(std::cerr, usage);
        return 0;
    }
    if (parse.error() || (argc < 1) || (parse.nonOptionsCount() != 1)) {
        option::printUsage(std::cerr, usage); // I wish it didn't use streams
        fprintf(stderr, "\n*** Command error, see usage\n");
        return 255;
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
        return 255;
    }

    port = (char*)parse.nonOption(0);
    addr = strsep(&port, ":");
    user = strsep(&addr, "@");
    if (!addr || !addr[0]) {
        addr = user;
        user = NULL;
    }
    if (!port || !port[0]) {
        port = (char*)"22";
    }
    int nport = atoi(port);
    if (!nport || (nport < 1) || (nport > 65535)) {
        fprintf(stderr, "*** Bad port, must be integer from 1 to 65535\n");
        exit(255);
    }

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
    if (opts[opTGT]) {
        tgt  = (char*)opts[opTGT].arg;
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
        fprintf(stderr, "*** For the echo test, a time limit or character count is required\n");
        exit(255);
    }
    if (do_speed && (size <= 0)) {
        fprintf(stderr, "*** For the speed test, the transfer size must be 1 MB or more\n");
        exit(255);
    }
    verbosity = opts[opVERB].count();

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
        die("Cannot establish ssh session");
    }
    ssh_channel chn = login_channel(ses);
    if (!chn) {
        die("Cannot login and run echo command");
    }

    // Run the tests
    if (do_echo) {
        run_echo_test(chn);
    }
    if (do_speed) {
        run_speed_test(ses);
    }

    // Cleanup
    logout_channel(chn);
    end_session(ses);
}
