/*
 * transport.c 
 *
 * CS536 PA2 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#include <arpa/inet.h>
#include <time.h>

#define MAXSEGMENT 560 // 60 for maximum options in header (I'm supposed to support but ignore them), and 500 for max payload
#define MAXPAYLOAD 500
#define STCPHEADER 20
#define WINDOW 5192
#define MAXFAILS 5
#define RTTADJUST 1.5 // Factor of avg RTT to be considered a timeout
#define RTTDELTA 0.1

enum state { CSTATE_ESTABLISHED };    /* obviously you should have more states */

typedef struct
{
	tcp_seq num;
	timespec resend;
	tcphdr *header;
	char *data;
	int fails;
} sent_info;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    enum state connection_state;   /* state of the connection (established, etc.) */

    /* any other connection-wide global variables go here */
    struct timespec* timeout;
    tcp_seq my_sequence_num; // Num of the next data user will send me
    tcp_seq recv_max; // Highest num recv will accept
    tcp_seq my_last_ack; // The previous ack I sent
    sent_info **sent_array;
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static tcphdr* header(tcp_seq seqNum, uint16_t win);
static tcphdr* ack(tcp_seq seqNum, tcp_seq ackNum, uint16_t win);
static tcphdr* make_header(tcp_seq seqNum, tcp_seq ackNum, uint16_t win, bool_t fin, bool_t syn, bool_t ack);
static void set_timeout(timespec* current, context_t* ctx);
static void adjust_timeout(timespec start, context_t* ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static bool_t send_syn(mysocket_t sd, context_t* ctx);
static bool_t recv_syn(mysocket_t sd, context_t* ctx);
static void app_to_network(mysocket_t sd, context_t* ctx);
static void network_to_app(mysocket_t sd, context_t* ctx);
static void add_sent_info(sent_info *info, context_t* ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
	
    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    
    struct timespec* timeout = (timespec*) malloc(sizeof(struct timespec));
    memset(timeout, 0, sizeof(*timeout));
    timeout->tv_sec = 0;
    timeout->tv_nsec = 200000000;
    ctx->timeout = timeout;
    ctx->sent_array = (sent_info**) malloc(sizeof(int*) * 128);
    memset(ctx->sent_array, 0, sizeof(int*) * 128);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    bool_t success;
	if(is_active) {
		success = send_syn(sd, ctx);
	} else {
		success = recv_syn(sd, ctx);
	}

	if(!success) {
		printf("Handshake failed!\n");
		return;
	}
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);
    control_loop(sd, ctx);
    free(ctx->timeout);
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->my_sequence_num = 1;
#else
    srand(time(NULL));
    /* STCP uses ISNs from [0, 199] inclusive */
    ctx->my_sequence_num = rand() % 200;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;
        printf("waiting...\n");

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* DONE: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        switch(event) {
        case APP_DATA:
        	printf("My user wants to send something!\n");
        	app_to_network(sd, ctx);
        	break;
        case NETWORK_DATA:
        	printf("My peer sent me something!\n");
        	network_to_app(sd, ctx);
        	break;
        case APP_CLOSE_REQUESTED:
        	printf("Not closing the app just yet\n");
        	break;
        default:
        	printf("I can't recognize this status code!\n");
        }
        printf("done!\n");
    }
}

static void app_to_network(mysocket_t sd, context_t* ctx) {
	char *buf = (char*) malloc(MAXPAYLOAD);
	size_t read = stcp_app_recv(sd, buf, MAXPAYLOAD);
	
	tcphdr* send_header = header(ctx->my_sequence_num, WINDOW);
	stcp_network_send(sd, send_header, STCPHEADER, buf, read, NULL);
	
	// add sent info
	sent_info *info = (sent_info*) malloc(sizeof(sent_info));
	info->num = ctx->my_sequence_num;
	set_timeout(&(info->resend), ctx);
	info->header = send_header;
	info->data = buf;
	info->fails = 0;
	
	add_sent_info(info, ctx);
}

static void network_to_app(mysocket_t sd, context_t* ctx) {
	char *buf = (char*) malloc(MAXSEGMENT);
	tcphdr *recv_header = (tcphdr*) buf;
	int received = stcp_network_recv(sd, buf, MAXSEGMENT);
	
	if(ntohl(recv_header->th_seq) != ctx->my_last_ack) {
		printf("Out of order! SCREAM LOUDLY!\n");
		printf("expected: %d, got: %d\n", ctx->my_last_ack, ntohl(recv_header->th_seq));
		return;
	}
	//Right packet...
	int header_size = recv_header->th_off * 4;
	stcp_app_send(sd, buf + header_size, received - header_size);
	printf("reminder: send an ACK!\n");
}

/* Mallocs a header with no flags. Use host order. */
static tcphdr* header(tcp_seq seqNum, uint16_t win) {
	return make_header(seqNum, 0, win, 0, 0, 0);
}


static tcphdr* ack(tcp_seq seqNum, tcp_seq ackNum, uint16_t win) {
	return make_header(seqNum, ackNum, win, 0, 0, 1);
}


/* Mallocs a TCP header with desired info.
 * Use host order.
 */
static tcphdr* make_header(tcp_seq seqNum, tcp_seq ackNum, uint16_t win, bool_t fin, bool_t syn, bool_t ack) {
	tcphdr* header = (tcphdr*) malloc(sizeof(struct tcphdr));
	assert(header);
	memset(header, 0, sizeof(*header));
	header->th_seq = htonl(seqNum);
	header->th_ack = htonl(ackNum);
	header->th_off = 5;
	header->th_win = htons(win);
	header->th_flags = TH_FIN * fin + TH_SYN * syn + TH_ACK * ack;
	return header;
}


/* The active half of the TCP handshake. Returns whether handshake was successful. */
static bool_t send_syn(mysocket_t sd, context_t* ctx) {

	//Send SYN
	tcphdr* sendHeader = make_header(ctx->my_sequence_num, 0, WINDOW, 0, 1, 0);
	if(stcp_network_send(sd, sendHeader, sizeof(*sendHeader), NULL) != sizeof(*sendHeader)) {
		errno = ENETDOWN;
		free(sendHeader);
		return false;
	}

	//Receive SYN ACK	
	timespec time;
	int failed = 0;
	for(; failed < MAXFAILS; failed++) {
		set_timeout(&time, ctx);
		unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA + APP_CLOSE_REQUESTED, &time);
		if(event == TIMEOUT) {
			if(stcp_network_send(sd, sendHeader, sizeof(*sendHeader), NULL) != sizeof(*sendHeader)) {
				errno = ENETDOWN;
				free(sendHeader);
				return false;
			}
			continue;
		} else if(event == APP_CLOSE_REQUESTED) {
			free(sendHeader);
			return false;
		}
		assert(event == NETWORK_DATA);
		break;
	}
	free(sendHeader);
	if(failed >= MAXFAILS) {
		errno = ETIMEDOUT;
		return false;
	}
	
	ctx->my_sequence_num++;
        char* buffer = (char*) malloc(MAXSEGMENT);
	stcp_network_recv(sd, buffer, MAXSEGMENT);
	tcphdr* recvHeader = (tcphdr*) buffer;
	if((recvHeader->th_flags != TH_SYN + TH_ACK) || (ntohl(recvHeader->th_ack) != ctx->my_sequence_num)) {
		errno = ECONNREFUSED;
		free(buffer);
		return false;
	}
	ctx->recv_max = ntohl(recvHeader->th_ack) + ntohl(recvHeader->th_win);
	
	//Send ACK
	sendHeader = ack(ctx->my_sequence_num, ntohl(recvHeader->th_seq) + 1, WINDOW);
	printf("received seq: %d\n", ntohl(recvHeader->th_seq));
	ctx->my_last_ack = ntohl(recvHeader->th_seq) + 1;
	free(buffer);
	if(stcp_network_send(sd, sendHeader, sizeof(*sendHeader), NULL) != sizeof(*sendHeader)) {
		errno = ENETDOWN;
		free(sendHeader);
		return false;
	}
	free(sendHeader);
	return true;
}


/* The passive half of the TCP handshake. Returns whether handshake was successful. */
static bool_t recv_syn(mysocket_t sd, context_t* ctx) {
	//Receive SYN
	timespec time;
	int failed = 0;
	for(; failed < MAXFAILS; failed++) {
		set_timeout(&time, ctx);
		unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA + APP_CLOSE_REQUESTED, &time);		
		if(event == TIMEOUT) {
			continue;
		} else if(event == APP_CLOSE_REQUESTED) {
			return false;
		}
		assert(event == NETWORK_DATA);
		break;
	}
	if(failed >= MAXFAILS) {
		errno = ETIMEDOUT;
		return false;
	}

    char* buffer = (char*) malloc(MAXSEGMENT);
	stcp_network_recv(sd, buffer, MAXSEGMENT);
	tcphdr* recvHeader = (tcphdr*) buffer;
	
	//Send SYN ACK
	tcphdr* sendHeader = make_header(ctx->my_sequence_num, ntohl(recvHeader->th_seq) + 1, WINDOW, 0, 1, 1);
	if(stcp_network_send(sd, sendHeader, sizeof(*sendHeader), NULL) != sizeof(*sendHeader)) {
		errno = ENETDOWN;
		free(sendHeader);
		free(buffer);
		return false;
	}
	timespec startTime;
	timespec_get(&startTime, TIME_UTC);
	ctx->my_sequence_num++;
	ctx->my_last_ack = ntohl(recvHeader->th_seq) + 1;
	//Receive SOMETHING - doesn't HAVE to be ACK, just supposed to be.
	//But it CAN'T be an old SYN! Chuck those ones out!
	while(true) {
		failed = 0;
		for(; failed < MAXFAILS; failed++) {
			set_timeout(&time, ctx);
			unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA + APP_CLOSE_REQUESTED, &time);
			if(event == TIMEOUT) {
				if(stcp_network_send(sd, sendHeader, sizeof(*sendHeader), NULL) != sizeof(*sendHeader)) {
					errno = ENETDOWN;
					free(sendHeader);
					free(buffer);
					return false;
				}		
				continue;
			} else if(event == APP_CLOSE_REQUESTED) {
				free(sendHeader);
				free(buffer);
				return false;
			}
			assert(event == NETWORK_DATA);
			break;
		}
		if(failed == 0) {
			adjust_timeout(startTime, ctx);
		}
		if(failed >= MAXFAILS) {
			errno = ETIMEDOUT;
			free(buffer);
			free(sendHeader);
			return false;
		}
		
		stcp_network_recv(sd, buffer, MAXSEGMENT);
		//I don't care what this is, as long as it's not SYN!
		if(((recvHeader->th_flags) & (TH_SYN)) != TH_SYN) {
			//Not a SYN!
			break;
		}
	}
	free(sendHeader);	
	free(buffer);
	return true;
}


/* Sets current to be RTTADJUST times the timeout plus the current time */
static void set_timeout(timespec* current, context_t* ctx) {
	timespec_get(current, TIME_UTC);
	current->tv_nsec = (long) (current->tv_nsec + ctx->timeout->tv_nsec + ctx->timeout->tv_sec * 1000000000) * RTTADJUST;
	current->tv_sec += (current->tv_nsec - (current->tv_nsec % 1000000000)) / 1000000000;
	current->tv_nsec = (long) current->tv_nsec % 1000000000;
}

static void adjust_timeout(timespec start, context_t* ctx) {
	timespec current;
	timespec_get(&current, TIME_UTC);
	uint64_t nsec = (current.tv_nsec - start.tv_nsec + (current.tv_sec - start.tv_sec) * 1000000000) * RTTDELTA + (ctx->timeout->tv_nsec + ctx->timeout->tv_sec * 1000000000) * (1 - RTTDELTA);
	ctx->timeout->tv_nsec = nsec % 1000000000;
	ctx->timeout->tv_sec = (nsec - (nsec % 1000000000)) / 1000000000;
}

static void add_sent_info(sent_info *info, context_t* ctx) {
  sent_info **cursor = ctx->sent_array;
  while(*cursor) {
    cursor++;
  }
  *cursor = (sent_info*) malloc(sizeof(sent_info));
  memcpy(*cursor, info, sizeof(sent_info));
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

