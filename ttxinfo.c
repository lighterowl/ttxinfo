#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#define TS_PACKET_SIZE 188
#define TS_SYNC_BYTE 0x47

/* the following is valid only for packets with a 4-byte header. fortunately, we
 * discard all the ones that don't have such a header in parse_ts_packet. */
#define TS_PACKET_DATA_SIZE 184

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

static void parse_pes_packet(const uint8_t *pkt, size_t size)
{
    printf("Received PES packet : %p, %zu\n", pkt, size);
}

/* try to read the TS and parse the TS headers, looking for packets with a
 * matching PID. assemble full PES packets from the found data, according to
 * PUSI flag value. */
static void read_ts(FILE *tsfile, uint16_t pid)
{
    /* try to read TS_BUFSIZE_NUM_PACKETS at once. */
    uint8_t ts_pkts[TS_PACKET_SIZE * TS_BUFSIZE_NUM_PACKETS];
    size_t pkts_read;
    
    /* whether we're currently assembling a PES or not. */
    unsigned int in_pes = 0;
    
    /* buffer for the PES data. */
    size_t pes_bufsize = 2048;
    size_t pes_offset = 0;
    uint8_t *pes_buf = malloc(pes_bufsize);
    if(pes_buf == NULL) exit(2);
    
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
                if(!in_pes && !pusi)
                {
                    /* first TS packet containing the beginning of a PES not yet
                     * received. this will happen only when starting to read the
                     * stream. */
                    continue;
                }
                else if(!in_pes && pusi)
                {
                    /* a new packet begins. write to the beginning of the
                     * buffer. no bounds check needed, since pes_buf is
                     * guaranteed to be at least 2048 bytes. */
                    in_pes = 1;
                    memcpy(pes_buf, pes_pkt, TS_PACKET_DATA_SIZE);
                    pes_offset = TS_PACKET_DATA_SIZE;
                }
                else if(in_pes && !pusi)
                {
                    /* continuation of PES data. copy the current contents to
                     * the packet buffer, and resize if necessary. */
                    if((pes_offset + TS_PACKET_DATA_SIZE) > pes_bufsize)
                    {
                        pes_bufsize *= 2;
                        pes_buf = realloc(pes_buf, pes_bufsize);
                        if(NULL == pes_buf) return;
                    }
                    memcpy(pes_buf + pes_offset, pes_pkt, TS_PACKET_DATA_SIZE);
                    pes_offset += TS_PACKET_DATA_SIZE;
                }
                else if(in_pes && pusi)
                {
                    /* end of a packet that's currently gathered. pass it down
                     * for processing and copy the current contents at the
                     * beginning of the buffer. */
                    parse_pes_packet(pes_buf, pes_offset);
                    memcpy(pes_buf, pes_pkt, TS_PACKET_DATA_SIZE);
                    pes_offset = TS_PACKET_DATA_SIZE;
                }
            }
        }
    }
    free(pes_buf);
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
