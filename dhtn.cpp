/*
 * Copyright (c) 2014 University of Michigan, Ann Arbor.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of Michigan, Ann Arbor. The name of the University 
 * may not be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Author: Xingtong Zhou (xingtong@umich.edu)
 *
*/
#include <stdio.h>		// fprintf(), perror(), fflush()
#include <stdlib.h>		// atoi()
#include <assert.h>		// assert()
#include <limits.h>		// LONG_MAX
#include <iostream>
using namespace std;
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>	// socklen_t
#include "wingetopt.h"
#else
#include <string.h>		// memset(), memcmp(), strlen(), strcpy(), memcpy()
#include <unistd.h>		// getopt(), STDIN_FILENO, gethostname()
#include <signal.h>		// signal()
#include <netdb.h>		// gethostbyname(), gethostbyaddr()
#include <netinet/in.h>	// struct in_addr
#include <arpa/inet.h>	// htons(), inet_ntoa()
#include <sys/types.h>	// u_short
#include <sys/socket.h>	// socket API, setsockopt(), getsockname()
#include <sys/ioctl.h>	// ioctl(), FIONBIO
#endif

#include "netimg.h"
#include "hash.h"
#include "dhtn.h"

#include "ltga.h"
#include "imgdb.h"

#ifdef __APPLE__
#include <GLUT/glut.h>
#else
#include <GL/glut.h>
#endif

void dhtn_usage(char *progname) {
	//TODO
	exit(1);
}

/*
 * dhtn_args: parses command line args.
 */
int dhtn_args(int argc, char * argv[], 
	char ** cli_fqdn, u_short * cli_port, int * id,
	imgdb * imgdb) {
	char c, *p;
	extern char *optarg;
	
	net_assert(!cli_fqdn, "dhtn_args: cli_fqdn not allocated");
	net_assert(!cli_port, "dhtn_args: cli_port not allocated");
	net_assert(!id, "dhtn_args: id not allocated");
	
	*id = ((int) NET_IDMAX) + 1;
	
	while ((c = getopt(argc, argv, "p:I:")) != EOF) {
		switch (c) {
		case 'p':
			for ( p = optarg + strlen(optarg) - 1;
				p != optarg && *p != NETIMG_PORTSEP;
				p--);
			net_assert((p == optarg), "dhtn_args: peer addressed malformed");
			*p++ = '\0';
			*cli_port = htons((u_short) atoi(p));
			
			net_assert((p-optarg > NETIMG_MAXFNAME), "dhtn_args: FQDN too long");
			*cli_fqdn = optarg;
			break;
		case 'I':
			*id = atoi(optarg);
			net_assert((*id < 0 || *id > ((int) NETIMG_IDMAX)), "dhtn_args: id out of range");
			break;
		default:
			break;
		}
	}
	
	return (imgdb->cli(argc, argv));
}

/*
 * setID: sets up a TCP socket listening for connection.
 * Let the call to bind() assign an ephemeral port to this listening socket.
 * Determine and print out the assigned port number to screen so that user
 * would know which port to use to connect to this server.
 * Store the host address and assigned port number to the number variable
 * "self". If "id" given is valid, i.e., in [0, 255], store it as self's ID,
 * else compute self's id from SHA1.
 *
 * Terminates process on error.
 * Returns the bound socket id.
 */
void dhtn::setID(int id) {
	int err, len;
	struct sockaddr_in node;
	char sname[NETIMG_MAXFNAME] = { 0 };
	char addrport[7] = { 0 };
	unsigned char md[SHA1_MDLEN];
	struct hostent * hp;
	
	/* create a TCP socket, store the socket descriptor in "listen_sd" */
	listen_sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	net_assert((listen_sd < 0), "dhtn::setID: socket");
	
	memset((char *) &node, 0, sizeof(struct sockaddr_in));
	node.sin_family = AF_INET:
	node.sin_addr.s_addr = INADDR_ANY;
	node.sin_port =0;
	
	/* bind address to socket */
	err = bind(listen_sd, (struct sockaddr *) &node, sizeof(struct sockaddr_in));
	net_assert(err, "dhtn::setID: bind");
	
	/* listen on socket */
	err = listen(listen_sd, NETIMG_QLEN);
	net_assert(err, "dhtn::setID: listen");
	
	/*
	 * Obtain the ephemeral port assigned by the OS kernel to this 
	 * socket and store it in the local variable "node".
	 */
	len = sizeof(struct sockaddr_in);
	err = getsockname(listen_sd, (struct sockaddr *) &node, (socklen_t *) &len);
	net_assert(err, "dhtn::setID: getsockname");
	
	/* Find out the FQDN of the current host and store it in the local
	 * variable "sname". gethostname() is usually sufficient. */
	err = gethostname(sname, NETIMG_MAXFNAME);
	net_assert(err, "dhtn::setID: gethostname");
	
	/* store the host's address and assigned port number in the "self" member variable */
	self.dhtn_port = node.sin_port;
	hp = gethostbyname(sname);
	het_assert((hp == 0), "dhtn::setID: gethostbyname");
	memcpy(&self.dhtn_addr, hp->h_addr, hp->h_length);
	
	/* if id is not valid, compute id from SHA1 hash of address+port */
	if ( id < 0 || id > (int) NETIMG_IDMAX ) {
		memcpy(addrport, (char *) &self.dhtn_port, 6*sizeof(char));
		addrport[6] = '\0';
		SHA1((unsigned char *) addrport, 6*sizeof(char), md);
		self.dhtn_ID = ID(md);
	} else {
		self.dhtn_ID = (unsigned char) id;
	}
	
	/* inform user which port this node is listening on */
	fprintf(stderr, "DHT node ID %d address is %s:%d\n", self.dhtn_ID, sname, ntohs(self.dhtn_port));
	
	return;
}

/*
 * dhtn default constructor.
 * If given id is valid, i.e., in [0, 255],
 * set self's ID to the given id, otherwise, compute an id from SHA1
 * Initially, both predecessor (pred) and successor (fingers[0]) are 
 * uninitialized (dhtn_port == 0).
 * Initialize member variables fqdn and port to provide command-line interface (cli) values.
 */
dhtn::dhtn(int id, char *cli_fqdn, u_short cli_port) {
	fqdn = cli_fqdn;
	port = cli_port;
	setID(id);
	pred.dhtn_port = 0;
	fingers[0].dhtn_port = 0;
}

/*
 * first: node is the first node in th ID circle.
 * Set both predecessor and successor (fingers[0]) to be "self".
 */
void dhtn::first() {
	pred = fingers[0] = self;
}

/*
 * refID: called when the dht tells us that our ID collides
 * with that of an existing node. We simply closes the listen 
 * socket and call setID() to grab a new ephemeral port and 
 * a corresponding new ID
 */
void dhtn::refID() {
	close(listen_sd);
	setID(((int) NETIMG_IDMAX)+1);
}

/*
 * connremote: connect to a remote host. If the host's address is not given, assume we want
 * to connect to the known host whose fqdn is stored as a member variable. The port given
 * must be in network byte order.
 *
 * Upon successful return, return the connected socket.
 */
int dhtn::connremote(struct in_addr *addr, u_short portnum) {
	int err, sd;
	struct sockaddr_in remote;
	struct hostent *rp;
	
	/* create a new TCP socket. */
	sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	net_assert((sd < 0), "dhtn::connremote: socket");
	
	memset((char *) &remote, 0, sizeof(struct sockaddr_in));
	remote.sin_family = AF_INET;
	remote.sin_port = portnum;
	if ( addr ) {
		memcpy(*remote.sin_addr, addr, sizeof(struct in_addr));
	} else {
		/* obtain remote host's IPv4 address from fqdn and initialize the
		 * socket address with remote host's address. */
		rp = gethostbyname(fqdn);
		net_assert((rp == 0), "dhtn::connremote: gethostbyname");
		memcpy(&remote.sin_addr, rp->h_addr, rp->h_length);
	}
	
	/* connect to remote host */
	err = connect(sd, (struct sockaddr *) &remote, sizeof(struct sockaddr_in));
	net_assert(err, "dhtn::connremote: connect");
	
	return sd;
}

/*
 * join: called ONLY by a node upon start up if fqdn:port is specified 
 * in the command line. It sends a join message to the provided host.
 */
void dhtn::join() {
	int sd, err;
	dhtmsg_t dhtmsg;
	
	sd = connremote(NULL, port);
	
	/* send join message */
	dhtmsg.dhtm_vers = NETIMG_VERS;
	dhtmsg.dhtm_type = DHTM_JOIN;
	dhtmsg.dhtm_ttl = htons(DHTM_TTL);
	memcpy((char *) &dhtmsg.dhtm_node, (char *) &self, sizeof(dhtnode_t));
	
	err = send(sd, (char *) &dhtmsg, sizeof(dhtmsg_t), 0);
	net_assert((err != sizeof(dhtmsg_t)), "dhtn::join: send");
	
	close(sd);
}

/*
 * acceptconn: accept a connection on listen_sd.
 * Set the new socket to linger upon closing.
 * Inform user of connection.
 */
int dhtn:: acceptconn() {
	int td;
	int err, len;
	struct linger linger_opt;
	struct sockaddr_in sender;
	struct hostent *cp;
	
	/* accept the new connection. Use the variable "td" to hold the new
	 * connected socket */
	len = sizeof(struct sockaddr_in);
	td = accept(listen_sd, (struct sockaddr *) &sender, (socklen_t *) &len);
	net_assert((td < 0), "dhtn::acceptconn: accept");
	
	/* make the socket wait for NETIMG_LINGER time unit to make sure
	 * that all data sent has been delivered when closing the socket */
	linger_opt.l_onoff = 1;
	linger_opt.l_linger = NETIMG_LINGER;
	err = setsockopt(td, SOL_SOCKET, SO_LINGER, 
		(char *) &linger_opt, sizeof(struct linger));
	net_assert(err, "dhtn::acceptconn: setsockopt SO_LINGER");
	
	/* inform user of connection */
	cp = gethostbyaddr((char *) &sender.sin_addr, sizeof(struct in_addr) AF_INET);
	fprintf(stderr, "Connected from node %s:%d\n",
		((cp && cp->h_name) ? cp->h_name : inet_ntoa(sender.sin_addr)),
		ntohs(sender.sin_port));
	
	return td;
}

int recvbysize(int sd, char * buffer, unsigned int size) {
	int recvd, bytes = 0;
	do {
		recvd = recv(sd, buffer+bytes, size-bytes, 0);
		if ( status <= 0 ) {
			close(sender);
			break;
		}
		bytes += recvd;
	} while (bytes < (int)size);
	return recvd;
}

void dhtn::forward(dhtmsg_t *dhtmsg) {
	//TODO: subject to change
	/* First check whether we expect the joining node's ID, as contained
	 * in the JOIN message, to fall within the range (self.dhtn_ID, 
	 * fingers[0].dhtn_ID]. If so, we inform the node we are sending
	 * the JOIN message to that we expect it to be our successor. We do
	 * this by setting the highest bit in the type field of the message
	 * using DHTM_ATLOC. */
	int err;
	dhtmsg_t fwdmsg;
	memcpy((char *) &fwdmsg, (char *) dhtmsg, sizeof(dhtmsg_t));
	dhtnode_t * joining = &dhtmsg->dhtm_node;
	if (ID_inrange(joining->dhtn_ID, self.dhtn_ID, fingers[0].dhtn_ID)) {
		fwdmsg.dhtm_type |= DHTM_ATLOC;
	}
	
	int sd = connremote(&fingers[0].dhtn_addr, fingers[0].dhtn_port){;
	err = send(sd, (char *) &fwdmsg, sizeof(dhtmsg_t), 0);
	net_assert((err != sizeof(dhtmsg_t)), "dhtn::forward: send");
	
	/* After we've forwarded the message along, we don't immediately close
	 * the connection as usual. Instead, we wait for any DHTM_REDRT message
	 * telling us that we have overshot in our range expectation (see the
	 * third case in dhtn::handlejoin()). Such a message comes with a 
	 * suggested new successor, we copy this suggested new successor to 
	 * our fingers[0] and try to forward the JOIN message again to the 
	 * new successor. We repeat this until we stop getting DHTM_REDRT
	 * message. */
	dhtmsg_t redrtmsg;
	int recvd = recvbysize(sd, (char *) &redrtmsg, sizeof(dhtmsg_t));
	close(sd);
	if ( recvd > 0 ) {
		memcpy((char *) &fingers[0], (char *) &redrtmsg.dhtm_node, sizeof(dhtnode_t));
		forward(dhtmsg);
	}

	return;
}

void mkmsg(dhtmsg_t * msg, int type, dhtnode_t * node) {
	msg->dhtm_vers = NETIMG_VERS;
	msg->dhtm_type = type;
	msg->dhtm_ttl = htons(DHTM_TTL);
	if ( node ) {
		memcpy((char *) &msg->dhtm_node, (char *) node, sizeof(dhtnode));
	} else {
		memset((char *) &msg->dhtm_node, 0, sizeof(dhtnode_t));
	}
	return;
}

void dhtn::handlejoin(int sender, dhtmsg_t *dhtmsg) {
	// TODO: subject to change
	/* First check if the joining node's ID collides with predecessor or
	 * self. If so, send back to joining node a REID message. */
	int err;
	dhtnode_t * joining = &dhtmsg->dhtm_node;
	if ( joining->dhtn_ID == self.dhtn_ID || joining->dhtn_ID == pred.dhtn_ID ) {
		close(sender);
		
		dhemsg_t reidmsg;
		mkmsg( &reidmsg, DHTM_REID, NULL );
		
		int sd = connremote( &joining->dhtn_addr, joining->dhtn_port);
		err = send(sd, (char *) &reidmsg, sizeof(dhtmsg_t), 0);
		net_assert((err != sizeof(dhtmsg_t)), "dhtn::reud: send");
		close(sd);
		return;
	}
	
	// TODO: subject to change
	if ( ID_inrange(joining->dhtn_ID, pred.dhtn_ID, self.dhtn_ID) ) {
		close(sender);
		
		dhtmsg_t wlcmmsg;
		mkmsg( &wlcmmsg, DHTM_WLCM, &self );
		
		int sd = connremote( &joining->dhtn_addr, joining->dhtn_port);
		err = send(sd, (char *) &wlcmmsg, sizeof(dhtmsg_t), 0);
		net_assert((err != sizeof(dhtmsg_t)), "dhtn:wlcm: send");
		err = send(sd, (char *) &pred, sizeof(dhtnode_t), 0);
		net_assert((err != sizeof(dhtnode_t)), "dhtn:wlcm: send");
		
		memcpy((char *) &pred, (char *) joining, sizeof(dhtnode_t));
		if ( self.dhtn_ID == fingers[0].dhtn_ID ) {
			memcpy((char *) &fingers[0], (char *) joining, sizeof(dhtnode_t));
		}
		close(sd);
		return;
	}
	
	// TODO: subject to change
	if ( dhtmsg->dhtm_type & DHTM_ATLOC ) {
		dhtmsg_t redrtmsg;
		mkmsg( &redrtmsg, DHTM_REDRT, &pred );
		err = send(sender, (char *) &redrtmsg, sizeof(dhtmsg_t), 0);
		net_assert((err != sizeof(dhtmsg_t)), "dhtn:redrt: send");
		close(sender);
		return;
	}
	
	// TODO: subject to change
	close(sender);
	forward(dhtmsg);
	
	return;
}

/* handlepkt: receive and parse packet.
 * The argument "sender" is the socket where the connection has been established.
 * First receive a packet from the sender. Then depending on the packet type,
 * call the appropriate packet handler.
 */
void dhtn::handlepkt(int sender) {
	dhtmsg_t dhtmsg;
	int recvd = recvbysize(sender, (char *) &dhtmsg, sizeof(dhtmsg_t));
	close(sender);
	
	if ( recvd > 0 ) {
		net_assert((dhtmsg.dhtm_vers != NETIMG_VERS), "dhtn::join: bad version");
		
		if (dhtmsg.dhtm_type == DHTM_REID) {
			/* an ID collision has occurred */
			net_assert(!fqdn, "dhtn::handlepkt: received reID but no known node");
			fprintf(stderr, "\tReceived REID from node %d\n", dhtmsg.dhtm_node.dhtn_ID);
			close(sender);
			reID();
			join();
			
		} else if (dhtmsg.dhtm_type & DHTM_JOIN) {
			net_assert(!(pred.dhtn_port && fingers[0].dhtn_port),
				"dhtn::handlepkt: receive a JOIN when not yet integrated into the DHT.");
			fprintf(stderr, "\tReceived JOIN (%d) from node %d\n",
				ntohs(dhtmsg.dhtm_ttl), dhtmsg.dhtm_node.dhtn_ID);
			handlejoin(sender, &dhtmsg);
			
		} else if (dhtmsg.dhtm_type & DHTM_WLCM) {
			fprintf(stderr, "\tReceived WLCM from node %d\n", dhtmsg.dhtm_node.dhtn_ID);
			fingers[0] = dhtmsg.dhtm_node;
			int recvd = recvbysize(sender, (char *) &pred, sizeof(dhtnode_t));
			net_assert((recvd <= 0), "dhtn::handlepkt: welcome recv pred");
			close(sender);
			
		} else {
			net_assert((dhtmsg.dhtm_type & DHTM_REDRT),
				"dhtn::handlepkt: overshoot message received out of band");
			close(sender);
		}
	}

	return;
}

/*
 * This is main loop of dhtn node. It sets up the read set, call select,
 * and handles input on the stdin and connection and packet arriving on
 * the listen_sd socket.
 */
int dhtn::mainloop() {
	char c;
	fd_set rset;
	int err, sender;
	
	/* set up and call select */
	FD_ZERO(&rset);
	FD_SET(listen_sd, &rset);
#ifndef _WIN32
	FD_SET(STDIN_FILENO, &rset);	// wait for input from std input
#endif
	
	err = select(listen_sd+1, &rset, 0, 0, 0);
	net_assert((err <= 0), "dhtn::mainloop: select error");
	
#ifndef _WIN32
	if (FD_ISSET(STDIN_FILENO, &rset)) {
		// user input: if getchar() returns EOF or if user hits q, quit,
		// else flush input and go back to waiting
		if (((c = getchar()) == EOF) || (c == 'q') || (c == 'Q')) {
			fprintf(stderr, "Bye!\n");
			return 0;
		} else if (c == 'p') {
			fprintf(stderr, "Node ID: %d, pred: %d, succ: %d\n", self.dhtn_ID,
				pred.dhtn_ID, fingers[0].dhtn_ID);
		}
		fflush(stdin);
	}
#endif
	
	if (FD_ISSET(listen_sd, &rset)) {
		sender = acceptconn();
		handlepkt(sender);
	}
	
	return 1;
}	

int main( int argc, char * argv [] ) {
	char * cli_fqdn = NULL;
	u_short cli_port;
	int err, id, status;
	
	int sd, td;
	imgdb imgdb;
	iqry_t iqry;
	int found;

#ifdef _WIN32
	WSADATA wsa;
	
	err = WSAStartup(MAKEWORD(2,2), &wsa);	// winsock 2.2
	net_assert(err, "sockinit: WSAStartup");
#endif
	
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN); 	// don't die if peer is dead
#endif
	
	/* parse args */
	int dhtn_args(int argc, char * argv[], 
	char ** cli_fqdn, u_short * cli_port, int * id,
	imgdb * imgdb)
	if (dhtn_args( argc, argv, &cli_fqdn, &cli_port, &id, &imgdb)) {
		dhtn_usage(argv[0]);
	}

	dhtn node(id, cli_fqdn, cli_port);	// initialize node, create listen socket
	
	if ( cli_fqdn ) {
		node.join();	// join DHT if known host given
	} else {
		ndoe.first();	// else this is the first node on ID circle
	}
	
	do {
		status = node.mainloop();
	} while (status);
	
#ifdef _WIN32
	WSACleanup();
#endif
	exit(0);
}
