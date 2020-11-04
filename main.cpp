#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <netinet/in.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_HOSTNAME 128

char host[MAX_HOSTNAME];
int host_len = 0;

void usage() {
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test test.gilgil.net\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}



int ban_pkt(struct nfq_data *tb, u_int32_t* id){
	unsigned char* host_loc = NULL;

	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;

	int ret;
	unsigned char *data;
	unsigned char *p;

	ph = nfq_get_msg_packet_hdr(tb);

	if (ph) {
		*id = ntohl(ph->packet_id);
	}


	ret = nfq_get_payload(tb, &data);
	if (ret == 0){
		return 0;
	}

	p = data;
	p += sizeof(libnet_ipv4_hdr);
	p += sizeof(libnet_tcp_hdr);

	for(int i = 0; i < 128; i++){
		//printf("%02x ", p[i]);
		if(p[i] == 'H' && p[i+1] == 'o' && p[i+2] == 's' && p[i+3] == 't'){
			host_loc = p + (i + 6);
		}

	}
	if(host_loc == NULL){
		return 0;
	}

	if(!strncmp(host, (char*)host_loc, host_len)){
		printf("\n### Not allowed website!! ###\n");
		return 1;
	}else{
		return 0;
	}
}



static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id;
	printf("entering callback\n");


	if(ban_pkt(nfa, &id)){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
		return -1;
	}

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	memcpy(host, argv[1], MAX_HOSTNAME);
	host_len = strlen(argv[1]);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
