#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <arpa/inet.h>

#define TS_PACKET_SIZE 188
#define TS_SYNC_BYTE 0x47

/* the following is valid only for packets with a 4-byte header. fortunately, we
 * discard all the ones that don't have such a header in parse_ts_packet. */
#define TS_PACKET_DATA_SIZE 184

typedef struct pes_assemble_ctx_
{
    uint8_t *buf;
    size_t size;
    size_t offset;
    unsigned int in_pes;
} pes_assemble_ctx;

typedef void (*pes_ready_fn)(const uint8_t *pes, size_t size, void *user_data);

#define TTX_PES_PRINTF(x, ...) \
do \
{ \
    printf("TTX_PES[%u] : " x, *ttx_pes_pkt_no - 1, __VA_ARGS__); \
} while(0)

#define TTX_PES_PRINT(x) \
do \
{ \
    printf("TTX_PES[%u] : " x, *ttx_pes_pkt_no - 1); \
} while(0)

#define PES_PRIVATE_STREAM_1_ID 0xBD
#define PES_TELETEXT_HEADER_LENGTH 0x24

static void parse_ttx_pes(const uint8_t *pes, size_t size, void *user_data)
{
    unsigned int *ttx_pes_pkt_no = user_data;
    ++(*ttx_pes_pkt_no);
    
    TTX_PES_PRINTF("Received PES packet of size %zu.\n", size);
    /* the PES header contains a lot of data that we really don't need. however,
     * EN 300 472 specifies some values that should appear in PES headers
     * containing teletext data, so let's check them at least. */
    
    if(pes[0] != 0x00 || pes[1] != 0x00 || pes[2] != 0x01)
    {
        TTX_PES_PRINTF("PES magic number incorrect : %hhx%hhx%hhx.\n",
            pes[0], pes[1], pes[2]);
        return;
    }
    if(pes[3] != PES_PRIVATE_STREAM_1_ID)
    {
        TTX_PES_PRINTF("PES stream ID incorrect : %hhx.\n", pes[3]);
        return;
    }
    
    uint16_t pes_pkt_len;
    memcpy(&pes_pkt_len, pes+4, sizeof(pes_pkt_len));
    pes_pkt_len = ntohs(pes_pkt_len);
    if(pes_pkt_len != size - 6) /* pes_pkt_len doesn't include first 6 bytes. */
    {
        TTX_PES_PRINTF("PES packet length mismatch : %hu.\n", pes_pkt_len);
        return;
    }
    if(((pes_pkt_len + 6) % TS_PACKET_DATA_SIZE) != 0)
    {
        TTX_PES_PRINT("Declared PES packet length incorrect.\n");
        return;
    }
    
    if(!(pes[6] & 0x04))
    {
        TTX_PES_PRINT("Data alignment indicator set to zero.\n");
        return;
    }
    
    if(pes[8] != PES_TELETEXT_HEADER_LENGTH)
    {
        TTX_PES_PRINTF("Header length %hhu different from expected (%hhu).\n",
            pes[8], PES_TELETEXT_HEADER_LENGTH);
        return;
    }
    
    /* there are 9 bytes preceding the PES header length field. the value of the
     * field itself refers to the number of header bytes following it. adding
     * these two numbers together, we jump straight to the data. */
    const uint8_t *ttx_data = pes + 9 + PES_TELETEXT_HEADER_LENGTH;
    
    TTX_PES_PRINT("Finished.\n");
}

#undef PES_PRIVATE_STREAM_1_ID
#undef PES_TELETEXT_HEADER_LENGTH
#undef TTX_PES_PRINT
#undef TTX_PES_PRINTF

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

static void assemble_pes_from_ts(pes_assemble_ctx *ctx, const uint8_t *ts_data,
    uint16_t pid, pes_ready_fn pes_ready, void *pes_ready_user_data)
{
    unsigned int pusi;
    const uint8_t *pes_data = parse_ts_packet(ts_data, pid, &pusi);
    if(pes_data)
    {
        if(!ctx->in_pes && !pusi)
        {
            /* this will happen only when starting to read the TS and means that
             * we got some TS packets that were a part of a PES packet whose
             * beginning is not in our stream. */
            return;
        }
        else if(!ctx->in_pes && pusi)
        {
            /* a new packet begins. write to the beginning of the buffer. no
             * bounds check needed, since ctx->buf is guaranteed to be at least
             * 2048 bytes. */
            ctx->in_pes = 1;
            memcpy(ctx->buf, pes_data, TS_PACKET_DATA_SIZE);
            ctx->offset = TS_PACKET_DATA_SIZE;
        }
        else if(ctx->in_pes && !pusi)
        {
            /* continuation of PES data. copy the current contents to the packet
             * buffer, and resize if necessary. */
            if((ctx->offset + TS_PACKET_DATA_SIZE) > ctx->size)
            {
                ctx->size *= 2;
                if((ctx->buf = realloc(ctx->buf, ctx->size)) == NULL) exit(2);
            }
            memcpy(ctx->buf + ctx->offset, pes_data, TS_PACKET_DATA_SIZE);
            ctx->offset += TS_PACKET_DATA_SIZE;
        }
        else if(ctx->in_pes && pusi)
        {
            /* end of a packet that's currently being gathered. fire pes_ready
             * with the current contents and copy the new packet's beginning
             * into the beginning of the buffer. */
            pes_ready(ctx->buf, ctx->offset, pes_ready_user_data);
            memcpy(ctx->buf, pes_data, TS_PACKET_DATA_SIZE);
            ctx->offset = TS_PACKET_DATA_SIZE;
        }
    }
}

#define TS_BUFSIZE_NUM_PACKETS 20

/* try to read the TS and parse the TS headers, looking for packets with a
 * matching PID. assemble full PES packets from the found data, according to
 * PUSI flag value. */
static void read_ts(FILE *tsfile, uint16_t pid)
{
    /* try to read TS_BUFSIZE_NUM_PACKETS at once. */
    uint8_t ts_pkts[TS_PACKET_SIZE * TS_BUFSIZE_NUM_PACKETS];
    size_t pkts_read;
    
    /* context for assembling the PES data. */
    pes_assemble_ctx pes_ctx;
    pes_ctx.size = 2048;
    pes_ctx.offset = 0;
    pes_ctx.in_pes = 0;
    if((pes_ctx.buf = malloc(pes_ctx.size)) == NULL) exit(2);
    
    unsigned int pkt_num = 0;
    
    while((pkts_read = fread(ts_pkts, TS_PACKET_SIZE,
        TS_BUFSIZE_NUM_PACKETS, tsfile)) > 0)
    {
        for(size_t i = 0 ; i < pkts_read ; ++i)
        {
            assemble_pes_from_ts(&pes_ctx, ts_pkts + (i * TS_PACKET_SIZE), pid,
                parse_ttx_pes, &pkt_num);
        }
    }
    free(pes_ctx.buf);
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
