#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#ifndef TS_PACKET_SIZE
#define TS_PACKET_SIZE 188
#endif

#define TS_SYNC_BYTE 0x47

/* parse one packet pointed to by 'tspkt', and return a pointer to the first
 * data byte inside the packet. if the TS packet is in any way invalid, or its
 * PID does not match 'pid', return NULL. 'pusi' is set to the value of the
 * payload unit start indicator in the header. */
static const uint8_t *parse_ts_packet(const uint8_t *tspkt, uint16_t pid,
    unsigned int *pusi)
{
    uint16_t this_pid;
    if(tspkt[0] != TS_SYNC_BYTE) return NULL;
    if((tspkt[1] & 0x80)) return NULL; /* transport_error_indicator */
    *pusi = (tspkt[1] & 0x40); /* payload_unit_start_indicator */
    
    this_pid = (((tspkt[1] & 0x1f) << 8) | tspkt[2]);
    if(this_pid != pid) return NULL;
    
    if((tspkt[3] & 0xc0)) return NULL; /* transport_scrambling_indicator */
    
    /* teletext packets must have adaptation_field_control equal to 01
     * (only payload) or 10 (only adaptation). the adaptation field is of no
     * interest to us. */
    if(((tspkt[3] & 0x30) >> 4) != 1) return NULL;
    
    /* ignore the continuity counter. */
    return tspkt + 4;
}

#define TS_BUFSIZE_NUM_PACKETS 20

static void read_ts(FILE *tsfile, uint16_t pid)
{
    /* try to read TS_BUFSIZE_NUM_PACKETS packets at once. */
    uint8_t ts_pkts[TS_PACKET_SIZE * TS_BUFSIZE_NUM_PACKETS];
    size_t pkts_read;
    while((pkts_read = fread(ts_pkts, TS_PACKET_SIZE,
        TS_BUFSIZE_NUM_PACKETS, tsfile)) > 0)
    {
        for(size_t i = 0 ; i < pkts_read ; ++i)
        {
            unsigned int pusi;
            const uint8_t *pes_pkt = parse_ts_packet(
                ts_pkts + (i * TS_PACKET_SIZE), pid, &pusi);
            if(pes_pkt)
            {
            }
        }
    }
}

#undef TS_BUFSIZE_NUM_PACKETS

/* the largest valid PID value. */
#define PID_MAX ((2 << 13) - 1)

/* parses the arguments and writes the results of the parsing to 'pid' and
 * 'tsfile'. in case of a failure, a message is printed to stderr. if
 * successful, 0 is returned, 'pid' contains a valid PID, and 'tsfile' is a
 * handle to a file opened for reading in binary mode. */
static int parse_args(int argc, char **argv, uint16_t *pid, FILE **tsfile)
{
    if(argc != 3)
    {
        fprintf(stderr, "Usage : %s <pid> <tsfile>\n", argv[0]);
        return 1;
    }
    
    /* parse the PID. */
    char *endptr;
    unsigned long ttx_pid = strtoul(argv[1], &endptr, 10);
    if(ULONG_MAX == ttx_pid || endptr == argv[1] || *endptr != '\0')
    {
        fprintf(stderr, "Could not convert %s to an unsigned integer.\n",
            argv[1]);
        return 1;
    }
    else if(ttx_pid > PID_MAX)
    {
        fprintf(stderr, "Value %lu is too large for a valid PID.\n", ttx_pid);
        return 1;
    }
    
    /* try opening the file. */
    FILE *f = fopen(argv[2], "rb");
    if(NULL == f)
    {
        fprintf(stderr, "Could not open file %s : %s\n", argv[2],
            strerror(errno));
        return 1;
    }
    
    /* everything's ok, write out the arguments. */
    *pid = (ttx_pid & 0x1fff);
    *tsfile = f;
    return 0;
}

#undef PID_MAX

int main(int argc, char **argv)
{
    uint16_t pid;
    FILE *tsfile;
    int rv = parse_args(argc, argv, &pid, &tsfile);
    if(rv != 0)
    {
        return rv;
    }
    read_ts(tsfile, pid);
    
    fclose(tsfile);
    return 0;
}
