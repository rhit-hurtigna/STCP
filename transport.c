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
#include <math.h>

#define MAXSEGMENT 560 // 60 for maximum options in header (I'm supposed to support but ignore them), and 500 for max payload
#define MAXPAYLOAD 500
#define STCPHEADER 20
#define WINDOW 15488
#define MAXFAILS 5
#define RTTADJUST 1.3 // Factor of avg RTT to be considered a timeout
#define RTTDELTA 0.1
#define MIN_RTO 0
#define MAX_ACKS 2

enum state { CSTATE_ESTABLISHED, CSTATE_HALF_CLOSED, CSTATE_WAIT_ON_PASSIVE };    /* obviously you should have more states */

typedef struct
{
	tcp_seq num; // If this num or greater was ACKED, then I don't need to worry about this packet
	tcphdr *header;
	char *data;
	size_t data_len;
} sent_info;

typedef struct
{
	tcp_seq num; // Start of the data
	char *data;
	size_t data_len; // End of data is num + data_len - 1
} recv_info;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    enum state connection_state;   /* state of the connection (established, etc.) */

    /* any other connection-wide global variables go here */
    struct timespec* timeout;
    tcp_seq my_sequence_num; // Num of the next data user will give to me that I will send to peer
    tcp_seq recv_max; // Highest num my peer will accept as far as I know
    tcp_seq my_last_ack; // The previous ack I sent
    sent_info **sent_array;
    recv_info **recv_array;
    timespec started; // Used for adjusting RTT
	timespec *resend; // Timer for when to resend oldest packet
	int fails; // How many times oldest packet failed
	int acks; // How many times I've received a useless ack of the oldest packet
	size_t sent;
	size_t recv;
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static tcphdr* header(tcp_seq seqNum, tcp_seq ackNum, uint16_t win);
static tcphdr* ack(tcp_seq seqNum, tcp_seq ackNum, uint16_t win);
static tcphdr* make_header(tcp_seq seqNum, tcp_seq ackNum, uint16_t win, bool_t fin, bool_t syn, bool_t ack);
static void set_timeout(timespec* current, context_t* ctx, int fails);
static void adjust_timeout(timespec start, context_t* ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static bool_t send_syn(mysocket_t sd, context_t* ctx);
static bool_t recv_syn(mysocket_t sd, context_t* ctx);
static void app_to_network(mysocket_t sd, context_t* ctx);
static int receive_on_network(mysocket_t sd, context_t* ctx);
static void add_sent_info(sent_info *info, context_t* ctx);
static int delete_sent_info(tcp_seq ack_num, context_t* ctx, int isFirst);
static int resend_packets(int sd, context_t *ctx);
static void resend_packet(int sd, context_t *ctx);
static void set_window_max(tcp_seq ack_num, int win, context_t *ctx);
static timespec* next_resend(context_t *ctx);
static int can_send(context_t *ctx);
static void send_first_fin(int sd, context_t *ctx);
static void send_second_fin(int sd, context_t *ctx);
static void add_recv_info(context_t *ctx, tcp_seq seqNum, char *data, size_t dataLen);
char* join_recv_info(context_t *ctx, char *buf, size_t init_len, size_t *full_len);

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
    timeout->tv_sec = 2;
    timeout->tv_nsec = 0;
    ctx->timeout = timeout;
    ctx->recv_max = 0;
    ctx->resend = NULL;
    ctx->sent_array = (sent_info**) malloc(sizeof(sent_info*) * 128);
    memset(ctx->sent_array, 0, sizeof(sent_info*) * 128);
    ctx->recv_array = (recv_info**) malloc(sizeof(recv_info*) * 128);
    memset(ctx->recv_array, 0, sizeof(recv_info*) * 128);
    ctx->sent = 0;
    ctx->recv = 0;

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
    // TODO: Free the sent_array, recv_array
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
		if(*(ctx->recv_array)) {
			printf("recv nonempty\n");
		} else {
			printf("recv empty\n");
		}
        event = stcp_wait_for_event(sd, can_send(ctx), next_resend(ctx));
		printf("event!\n");fflush(stdout);
        /* check whether it was the network, app, or a close request */
        if (event & NETWORK_DATA) {
        	printf("My peer sent me something!\n");
        	if(receive_on_network(sd, ctx) == 1) {
        		//Passive side sent their FIN
        		return;
        	}
        }
        else if (event & APP_DATA) {
        	printf("My user wants to send something!\n");
        	app_to_network(sd, ctx);
        }
        else if (event & APP_CLOSE_REQUESTED) {
        	send_first_fin(sd, ctx);
		}
		else if (!event) {
			printf("Timed out!\n");
			if(!*(ctx->sent_array)) {
				//Timed out while there was nothing sent... Means that
				//I'm the server and I'm done sending and the client's
				//done sending too!
				printf("Shutting down connection!\n");
				send_second_fin(sd, ctx);
				printf("returning\n");
				return;
			}
			if(resend_packets(sd, ctx) < 0) {
				printf("Too many failed attempts! Exiting\n");
				return;
			}
		}
		else {
			printf("I can't recognize this status code: %u!\n", event);
		}
        printf("done!\n");
    }
}

static void app_to_network(mysocket_t sd, context_t* ctx) {
	char *buf = (char*) malloc(MAXPAYLOAD);
	size_t read = stcp_app_recv(sd, buf, MAXPAYLOAD);
	
	tcphdr* send_header = header(ctx->my_sequence_num, ctx->my_last_ack, WINDOW);
	ctx->sent++;
	printf("I have now sent %ld data packets!\n", ctx->sent);
	stcp_network_send(sd, send_header, STCPHEADER, buf, read, NULL);
	
	ctx->my_sequence_num += read;
	
	// add sent info
	sent_info *info = (sent_info*) malloc(sizeof(sent_info));
	info->num = ctx->my_sequence_num;
	info->header = send_header;
	info->data = buf;
	info->data_len = read;
	
	add_sent_info(info, ctx);
}

static void send_ack(mysocket_t sd, int win, context_t *ctx) {
	timespec current;
	timespec_get(&current, TIME_UTC);
	printf("sending an ack of %d at %ld secs and %ld nanos\n", ctx->my_last_ack, current.tv_sec, current.tv_nsec);
	//Send ACK
	tcphdr *sendHeader = ack(ctx->my_sequence_num, ctx->my_last_ack, win);
	if(stcp_network_send(sd, sendHeader, sizeof(*sendHeader), NULL) != sizeof(*sendHeader)) {
		errno = ENETDOWN;
	}
	free(sendHeader);
}

static void network_to_app(mysocket_t sd, char *buf, tcphdr *recv_header, int received, context_t *ctx) {
	printf("networkToApp\n");
	int header_size = recv_header->th_off * 4;
	if(header_size == received) {
		//Just a header! I don't care.
		return;
	}
	ctx->recv++;
	printf("I have now received %ld data packets!\n", ctx->recv);
	if(ntohl(recv_header->th_seq) > ctx->my_last_ack) {
		printf("Out of order! SCREAM LOUDLY!\n");
		printf("expected: %d, got: %d\n", ctx->my_last_ack, ntohl(recv_header->th_seq));
		// Add to buffer
		printf("Adding num %d to array.\n", ntohl(recv_header->th_seq));
		add_recv_info(ctx, ntohl(recv_header->th_seq), buf + header_size, received - header_size);
		// Resend my ack
		send_ack(sd, WINDOW, ctx);
	} else if(ntohl(recv_header->th_seq) < ctx->my_last_ack) {
		printf("My ack didn't go through, other side double sent! I was expecting %d, but I got %d.\n", ctx->my_last_ack, ntohl(recv_header->th_seq));
		send_ack(sd, WINDOW, ctx);
	} else {
		//Right packet...
		size_t data_len;
		char *data = join_recv_info(ctx, buf + header_size, received - header_size, &data_len);
		ctx->my_last_ack += data_len;
		printf("Set my last ack to %d\n", ctx->my_last_ack);
		stcp_app_send(sd, data, data_len);
		free(data);
		send_ack(sd, WINDOW, ctx);
	}
}

static void receive_ack(int sd, tcphdr *recv_header, context_t *ctx) {
	printf("received ack of %d\n", ntohl(recv_header->th_ack));
	if(delete_sent_info(ntohl(recv_header->th_ack), ctx, 1) == 0) {
		// The ack deleted at least one old packet!
		while(delete_sent_info(ntohl(recv_header->th_ack), ctx, 0) == 0);
		// Reset timer if there's still a packet left
		if(*(ctx->sent_array)) {
			set_timeout(ctx->resend, ctx, 0);
			timespec_get(&(ctx->started), TIME_UTC);
			ctx->fails = 0;
			ctx->acks = 0;
		} else {
			// Don't want to have a timer counting on nothing!
			free(ctx->resend);
			ctx->resend = NULL;
			ctx->fails = 0;
			ctx->acks = 0;
		}
	} else {
	    if(!!(*(ctx->sent_array))) {
	    	printf("good ptr\n");
	    } else {
	    	printf("bad ptr\n");
	    }
		if(!!(*(ctx->sent_array))) {
			if(ntohl(recv_header->th_ack) == ntohl((*(ctx->sent_array))->header->th_seq)) {
				printf("count re-ack\n");
				ctx->acks++;
				if(ctx->acks >= MAX_ACKS) {
					printf("Too many consecutive ACKS! Resending!\n");
					resend_packet(sd, ctx);
				}
			}
		}
	}
	set_window_max(ntohl(recv_header->th_ack), ntohs(recv_header->th_win), ctx);
}

static int receive_on_network(mysocket_t sd, context_t* ctx) {
	printf("recvOnNetwork\n");
	int wasFin = 0;
	char *buf = (char*) malloc(MAXSEGMENT);
	tcphdr *recv_header = (tcphdr*) buf;
	int received = stcp_network_recv(sd, buf, MAXSEGMENT);
	if((recv_header->th_flags & TH_FIN)) {
		printf("Got a FIN!\n");
		// Send 1 ACK of the FIN
		tcphdr *header = ack(ctx->my_sequence_num, ntohl(recv_header->th_seq) + 1, WINDOW);
		stcp_network_send(sd, header, sizeof(*header), NULL);
		free(header);
		if(ctx->connection_state == CSTATE_HALF_CLOSED) {
			printf("passive side sent their FIN! I'm done!!!\n");
			wasFin = 1;
		} else {
			printf("Active side sent their FIN! Time to send my last file.\n");
			ctx->connection_state = CSTATE_WAIT_ON_PASSIVE;
		}
	}
	if(recv_header->th_flags & TH_ACK) {
		printf("twas an ACK\n");
		receive_ack(sd, recv_header, ctx);
	}
	network_to_app(sd, buf, recv_header, received, ctx);
	free(buf);
	return wasFin;
}

/* Mallocs a header with no flags. Use host order. */
static tcphdr* header(tcp_seq seqNum, tcp_seq ackNum, uint16_t win) {
	return make_header(seqNum, ackNum, win, 0, 0, 0);
}


static tcphdr* ack(tcp_seq seqNum, tcp_seq ackNum, uint16_t win) {
	printf("gonna ack %d\n", ackNum);
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
		set_timeout(&time, ctx, failed);
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
	set_window_max(ntohl(recvHeader->th_ack), ntohs(recvHeader->th_win), ctx);
	
	//Send ACK
	sendHeader = ack(ctx->my_sequence_num, ntohl(recvHeader->th_seq) + 1, WINDOW);
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
		set_timeout(&time, ctx, failed);
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
	
	set_window_max(ntohl(recvHeader->th_ack), ntohs(recvHeader->th_win), ctx);
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
			set_timeout(&time, ctx, failed);
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
static void set_timeout(timespec* current, context_t* ctx, int failed) {
    printf("Current timeout: %ld sec, %ld nanos\n", ctx->timeout->tv_sec, ctx->timeout->tv_nsec);
	timespec_get(current, TIME_UTC);
	current->tv_nsec = (long) (current->tv_nsec + (ctx->timeout->tv_nsec + ctx->timeout->tv_sec * 1000000000) * RTTADJUST * (pow(2, failed)));
	current->tv_sec += (current->tv_nsec - (current->tv_nsec % 1000000000)) / 1000000000;
	current->tv_nsec = (long) current->tv_nsec % 1000000000;
	if(ctx->timeout->tv_sec < 1 && ctx->timeout->tv_nsec < MIN_RTO) {
		ctx->timeout->tv_sec = 0;
		ctx->timeout->tv_nsec = MIN_RTO;
	}
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
  if(*cursor == NULL) {
  	// First packet in the train! Gotta change the ctx.
  	ctx->fails = 0;
  	ctx->acks = 0;
  	ctx->resend = (timespec*) malloc(sizeof(struct timespec));
  	set_timeout(ctx->resend, ctx, 0);
  	timespec_get(&(ctx->started), TIME_UTC);
  }
  while(*cursor) {
    cursor++;
  }
  *cursor = (sent_info*) malloc(sizeof(sent_info));
  memcpy(*cursor, info, sizeof(sent_info));
  timespec current;
  timespec_get(&current, TIME_UTC);
}

static int delete_sent_info(tcp_seq ack_num, context_t* ctx, int isFirst) {
  printf("Deleting for %d\n", ack_num);
  sent_info **cursor = ctx->sent_array;
  while(*cursor != NULL) {
  	if((*cursor)->num <= ack_num) {
  		printf("found: %d!\n", (*cursor)->num);
  		break;
  	}
  	printf("Not acked yet: %d.\n", (*cursor)->num);
    cursor++;
  }
  if(!*cursor) {
  	printf("not found!\n");
  	return 1;
  }
  // Adjust timeout if never failed and was first
  if(ctx->fails == 0 && isFirst == 1) {
	adjust_timeout(ctx->started, ctx);
  }
  
  // Delete!
  free((*cursor)->header);
  free((*cursor)->data); 
  while(*(cursor+1) != NULL) {
  	*cursor = *(cursor + 1);
  	cursor++;
  }
  memset(cursor, 0, sizeof(sent_info*));
  return 0;
}


static void add_recv_info(context_t *ctx, tcp_seq seqNum, char *data, size_t dataLen) {
	printf("START add_recv_info\n");
	//get spot in array
	recv_info **cursor = ctx->recv_array;
	
	
	while(*cursor) {
		printf("num in cursor: %d\n", (*cursor)->num);
		cursor++;
	}
	cursor = ctx->recv_array;
	
	
	recv_info *bubble = NULL;
	while(*cursor) {
		if((*cursor)->num >= seqNum) {
			bubble = *cursor;
			break;
		}
		cursor++;
	}
	if(!bubble) {
		// Easy insert!
		printf("ezInsert\n");
		recv_info *info = (recv_info*) malloc(sizeof(recv_info));
		info->num = seqNum;
		info->data = (char*) malloc(sizeof(char) * dataLen);
		strncpy(info->data, data, dataLen);
		info->data_len = dataLen;
		*cursor = info;
		return;
	}
	if(bubble->num == seqNum) {
		//Already have it!
		printf("alreadyHave\n");
		return;
	}
	//Gonna have to add it
	recv_info *info = (recv_info*) malloc(sizeof(recv_info));
	info->num = seqNum;
	info->data = (char*) malloc(sizeof(char) * dataLen);
	strncpy(info->data, data, dataLen);
	info->data_len = dataLen;
	
	// Ripple it through
	while(info) {
		bubble = *cursor;
		*cursor = info;
		info = bubble;
		cursor++;
	}
	
	
	
	printf("END add_recv_array\n");
	cursor = ctx->recv_array;
	while(*cursor) {
		printf("num in cursor: %d\n", (*cursor)->num);
		cursor++;
	}
}

char* join_recv_info(context_t *ctx, char *buf, size_t init_len, size_t *full_len) {
	printf("join_recv_info\n");
	tcp_seq next_seq = ctx->my_last_ack + init_len;
	recv_info **cursor = ctx->recv_array;
	*full_len = init_len;
	size_t found = 0;
	
	while(*cursor) {
		printf("while *cursor\n");
		if((*cursor)->num != next_seq) {
			break;
		}
		next_seq += (*cursor)->data_len;
		*full_len += (*cursor)->data_len;
		found++;
		cursor++;
	}
	cursor = ctx->recv_array;
	char *data = (char*) malloc(sizeof(char) * *full_len);
	strncpy(data, buf, init_len);
	for(size_t i = 0; i < found; i++) {
		printf("for loop\n");
		strncpy(data + init_len, (*(cursor + i))->data, (*(cursor + i))->data_len);
		init_len += (*(cursor + i))->data_len;
		free((*(cursor + i))->data);
		free(*(cursor + i));
	}
	memset(cursor, 0, sizeof(recv_info*) * found);
	if(found) {
		printf("JOINED TOGETHER %ld things!!!\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n", found + 1);
		cursor += found;
		while(*cursor) {
			printf("reset array\n");
			*(cursor - found) = *cursor;
			*cursor = NULL;
			cursor++;
		}
	}
	
	return data;
}

static timespec* next_resend(context_t *ctx) {
	printf("next_resend was called\n");
	printf("%ld sec, %ld nsec is curr timeout\n", ctx->timeout->tv_sec, ctx->timeout->tv_nsec);
	if(ctx->resend) {
		return ctx->resend;
	}
	if(ctx->connection_state == CSTATE_WAIT_ON_PASSIVE) {
		printf("setting curr\n");
		ctx->resend = (struct timespec*) malloc(sizeof(struct timespec));
		timespec_get(ctx->resend, TIME_UTC);
		printf("set cur\n");
	}
	return ctx->resend;
}

static int check_if_resend(timespec resend, timespec current) {
		long offset_sec = resend.tv_sec - current.tv_sec;
		if(offset_sec < 0) {
			return 1;
		} else if(offset_sec == 0) {
			if(resend.tv_nsec - current.tv_nsec <= 0) {
				return 1;
			}
		} else if(offset_sec == 1) {
			if(resend.tv_nsec - current.tv_nsec <= -1000000000) {
				return 1;
			}
		}
		return 0;
}

static int resend_packets(int sd, context_t *ctx) {
	ctx->fails++;
	printf("PlusOne fails: %d\n", ctx->fails);
	if(ctx->fails > MAXFAILS) {
		printf("FAILFAILXXX\n");
		//return -1;
	}
	resend_packet(sd, ctx);
	return 0;
	// Resend ALL packets
	sent_info *sent;
	sent_info **cursor = ctx->sent_array;
	while(*cursor) {
		sent = *cursor;
		printf("Resending packet with num of %d and seq num of %d.\n", sent->num, ntohl(sent->header->th_seq));
		stcp_network_send(sd, sent->header, STCPHEADER, sent->data, sent->data_len, NULL);
		cursor++;
	}
	printf("Before set time: %ld sec, %ld nsec\n", ctx->resend->tv_sec, ctx->resend->tv_nsec);
	set_timeout(ctx->resend, ctx, ctx->fails);
	printf("After set time: %ld sec, %ld nsec\n", ctx->resend->tv_sec, ctx->resend->tv_nsec);
	return 0;
}

static void resend_packet(int sd, context_t *ctx) {
	// Don't count fails here!
	sent_info *sent = *(ctx->sent_array);
	if(!sent) {
		return;
	}
	ctx->acks = 0;
	printf("Resending based on 3 acks packet with num of %d and seq num of %d.\n", sent->num, ntohl(sent->header->th_seq));
	ctx->sent++;
	printf("I have now sent %ld data packets!\n", ctx->sent);
	stcp_network_send(sd, sent->header, STCPHEADER, sent->data, sent->data_len, NULL);
	printf("Before set time: %ld sec, %ld nsec\n", ctx->resend->tv_sec, ctx->resend->tv_nsec);
	set_timeout(ctx->resend, ctx, ctx->fails);
	printf("After set time: %ld sec, %ld nsec\n", ctx->resend->tv_sec, ctx->resend->tv_nsec);
}

static void set_window_max(tcp_seq ack_num, int win, context_t *ctx) {
	if(ctx->recv_max < ack_num + win - 1) {
		ctx->recv_max = ack_num + win - 1;
	}
}

static int can_send(context_t *ctx) {
	if(ctx->recv_max >= ctx->my_sequence_num) {
		return ANY_EVENT;
	} else {
		printf("Overloading the receiver! They say they can only take %d, and I want to send %d!\n", ctx->recv_max, ctx->my_sequence_num);
		return APP_CLOSE_REQUESTED | NETWORK_DATA;
	}
}

static void send_first_fin(int sd, context_t *ctx) {
	//Send FIN
	tcphdr *header = make_header(ctx->my_sequence_num, ctx->my_last_ack, WINDOW, 1, 0, 0);
	stcp_network_send(sd, header, sizeof(*header), NULL);

	//Set sent_info
	sent_info *info = (sent_info*) malloc(sizeof(sent_info));
	info->num = ctx->my_sequence_num + 1;
	info->header = header;
	info->data = NULL;
	info->data_len = 0;
	add_sent_info(info, ctx);
	
	//Set connection state as half-closed (waiting for other side to send a FIN)
    ctx->connection_state = CSTATE_HALF_CLOSED;
}

static void send_second_fin(int sd, context_t *ctx) {
	//Send FIN
	tcphdr *header = make_header(ctx->my_sequence_num, ctx->my_last_ack, WINDOW, 1, 0, 0);
	stcp_network_send(sd, header, sizeof(*header), NULL);

	//Shut it all down
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

