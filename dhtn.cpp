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

/**************************TOOL FUNCTIONS***************************/
void dhtn_usage(char *progname) {
	//TODO
	fprintf(stderr, "Usage: %s [-p <FQDN:port> -I <nodeID> -i <imagefolder>]\n", progname);
	exit(1);
}

/*
 * dhtn_args: parses command line args.
 */
int dhtn_args(int argc, char * argv[], 
	char ** cli_fqdn, u_short * cli_port, int * id,
	char ** imgdb_folder) {
	char c, *p;
	extern char *optarg;
	
	net_assert(!cli_fqdn, "dhtn_args: cli_fqdn not allocated");
	net_assert(!cli_port, "dhtn_args: cli_port not allocated");
	net_assert(!id, "dhtn_args: id not allocated");
	
	*id = ((int) NETIMG_IDMAX) + 1;
	
	while ((c = getopt(argc, argv, "p:I:i:")) != EOF) {
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
		case 'i':
			*imgdb_folder = optarg;
			break;
		default:
			return 1;
			break;
		}
	}
	
	return 0;
}

int recvbysize(int sd, char * buffer, unsigned int size) {
	int recvd, bytes = 0;
	do {
		recvd = recv(sd, buffer+bytes, size-bytes, 0);
		if ( recvd <= 0 ) {
			close(sd);
			break;
		}
		bytes += recvd;
	} while (bytes < (int)size);
	return recvd;
}

// Caller is responsible to release memory of md!
unsigned char * getimgMD(char * fname) {
	unsigned char * md = new unsigned char [SHA1_MDLEN];
	SHA1((unsigned char *) fname, strlen(fname), md);
	return md;
}

unsigned char getimgID(char * fname) {
	unsigned char * md = getimgMD(fname);
	unsigned char id = ID(md);
	delete [] md;
	return id;
}

void mkmsg(dhtmsg_t * msg, int type, dhtnode_t * node, u_short ttl = DHTM_TTL) {
	msg->dhtm_vers = NETIMG_VERS;
	msg->dhtm_type = type;
	msg->dhtm_ttl = htons(ttl);
	if ( node ) {
		memcpy((char *) &msg->dhtm_node, (char *) node, sizeof(dhtnode_t));
	} else {
		memset((char *) &msg->dhtm_node, 0, sizeof(dhtnode_t));
	}
	return;
}

void mksrch(dhtsrch_t * srch, int type, dhtnode_t * node, char * imgname) {
	dhtmsg_t * msg = (dhtmsg_t *) srch;
	mkmsg(msg, type, node);
	
	unsigned char imgID = getimgID(imgname);
	srch->dhts_imgID = imgID;
	
	memcpy((char *) srch->dhts_name, imgname, NETIMG_MAXFNAME);
	return;
}

void initFingers(dhtnode_t *self, dhtnode_t fingers[]) {
	for ( int i = 0; i < DHTN_FINGERS+1; i++ ) {
		memcpy((char *) &(fingers[i]), (char *) self, sizeof(dhtnode_t));
	}
	return;
}

void calcfID(unsigned char id, unsigned char fID[]) {
	unsigned char pow = 1;
	for ( int i = 0; i < DHTN_FINGERS; i++ ) {
		fID[i] = (id + pow) % (NETIMG_IDMAX+1);
		pow *= 2;
	}
	return;
}

int getForwardIdx(unsigned char selfID, unsigned char fID[], int joinID) {
	int found = 0;
	int idx = 0;
	for ( int i = DHTN_FINGERS-1; i > 0 && !found; i-- ) {
		if (ID_inrange(fID[i], selfID, joinID)) {
			idx = i;
			found = 1;
		}
	}
	return idx;
}

void printFingers(dhtnode_t * self, dhtnode_t fingers[]) {
	printf("***FINGER TABLE***\n");
	printf("  self:\t\t%d\n", self->dhtn_ID);
	for ( int i = 0; i < DHTN_FINGERS+1; i++ ) {
		printf("  %d:\t\t%d\n", i, fingers[i].dhtn_ID);
	}
	return;
}

/*********************IMPLEMENTATION OF DHTN************************/
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
	//cout << "entering dhtn::setID()...\n";
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
	node.sin_family = AF_INET;
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
	net_assert((hp == 0), "dhtn::setID: gethostbyname");
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
	
	calcfID(self.dhtn_ID, fID);
	
	/* inform user which port this node is listening on */
	fprintf(stderr, "DHT node ID %d address is %s:%d\n", self.dhtn_ID, sname, ntohs(self.dhtn_port));
	
	return;
}

// TODO
/*
 * dhtn default constructor.
 * If given id is valid, i.e., in [0, 255],
 * set self's ID to the given id, otherwise, compute an id from SHA1
 * Initially, both predecessor (pred) and successor (fingers[0]) are 
 * uninitialized (dhtn_port == 0).
 * Initialize member variables fqdn and port to provide command-line interface (cli) values.
 */
dhtn::dhtn(int id, char *cli_fqdn, u_short cli_port, char * imagefolder) {
	fqdn = cli_fqdn;
	port = cli_port;
	setID(id);
	for ( int i = 0; i < DHTN_FINGERS+1; i++ ) {
		fingers[i].dhtn_port = 0;
	}

	//dhtn_imgdb.setfolder(imagefolder);
	
	return;
}

/*
 * first: node is the first node in th ID circle.
 * Set both predecessor and successor (fingers[0]) to be "self".
 */
void dhtn::first() {
	initFingers(&self, fingers);
	dhtn_imgdb.reloaddb(self.dhtn_ID, self.dhtn_ID);
	return;
}

/*
 * reID: called when the dht tells us that our ID collides
 * with that of an existing node. We simply closes the listen 
 * socket and call setID() to grab a new ephemeral port and 
 * a corresponding new ID
 */
void dhtn::reID() {
	close(listen_sd);
	setID(((int) NETIMG_IDMAX)+1);
	return;
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
		memcpy(&remote.sin_addr, addr, sizeof(struct in_addr));
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
	initFingers(&self, fingers);
	//dhtn_imgdb.reloaddb(self.dhtn_ID, self.dhtn_ID);
	
	int sd, err;
	dhtmsg_t dhtmsg;
	
	sd = connremote(NULL, port);
	
	/* send join message */
	mkmsg(&dhtmsg, DHTM_JOIN, &self);
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
	cp = gethostbyaddr((char *) &sender.sin_addr, sizeof(struct in_addr), AF_INET);
	fprintf(stderr, "Connected from node %s:%d\n",
		((cp && cp->h_name) ? cp->h_name : inet_ntoa(sender.sin_addr)),
		ntohs(sender.sin_port));
	
	return td;
}

/* forward based on provided id (which is either node ID for a
 * join message or image ID for a searcj message). The second
 * argument could actually be a pointer to a dhtsrch_t that is cast
 * to a dhtmsg_t. So the third argument tells the actual size of
 * the packet pointed to by the second argument.
 */
void dhtn::forward(unsigned char id, dhtmsg_t * dhtmsg, int size) {
	//cout << "entering dhtn::forward()...\n";
	//TODO: subject to change
	/* First check whether we expect the joining node's ID, as contained
	 * in the JOIN message, to fall within the range (self.dhtn_ID, 
	 * fingers[0].dhtn_ID]. If so, we inform the node we are sending
	 * the JOIN message to that we expect it to be our successor. We do
	 * this by setting the highest bit in the type field of the message
	 * using DHTM_ATLOC. */
	if ( ntohs(dhtmsg->dhtm_ttl) == 0 ) {
		printf("ttl = 0, canceling forward...\n");
		return;
	}
	
	int err;
	
	dhtmsg->dhtm_ttl = htons(ntohs(dhtmsg->dhtm_ttl)-1);
	
	int j = 0;
	if (ID_inrange(id, self.dhtn_ID, fingers[0].dhtn_ID)) {
		dhtmsg->dhtm_type |= DHTM_ATLOC;
	} else {
		//TODO
		/* instead of simply forwarding to the successor node, first find the 
		 * largetst index, j, for which joining node's ID <= fID[j] < the node's
		 * ID, in modulo arithmetic */
		j = getForwardIdx(self.dhtn_ID, fID, id);
	}
	printf("forwarding to node %d...\n", fingers[j].dhtn_ID);
	int sd = connremote(&(fingers[j].dhtn_addr), fingers[j].dhtn_port);
	err = send(sd, (char *) dhtmsg, (unsigned int) size, 0);
	net_assert((err != (unsigned int) size), "dhtn::forward: send");
	
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
		printf("receive redrtmsg...\n");
		//TODO
		/* instead of saving the returned node as the new successor, we save it 
		 * in finger[j] */
		memcpy((char *) &fingers[j], (char *) &redrtmsg.dhtm_node, sizeof(dhtnode_t));
		fixup(j);
		fixdn(j);
		
		//printFingers(&self, fingers);
		forward(id, dhtmsg, size);
	}
	
	return;
}

void dhtn::handlejoin(int sender, dhtmsg_t *dhtmsg) {
	//cout << "entering dhtn::handlejoin()...\n";
	//printFingers(&self, fingers);
	
	/* First check if the joining node's ID collides with predecessor or
	 * self. If so, send back to joining node a REID message. */
	int err;
	dhtnode_t * joining = &(dhtmsg->dhtm_node);
	dhtnode_t * pred = &(fingers[DHTN_FINGERS]);
	if ( joining->dhtn_ID == self.dhtn_ID || joining->dhtn_ID == pred->dhtn_ID ) {
		close(sender);
		
		dhtmsg_t reidmsg;
		mkmsg( &reidmsg, DHTM_REID, NULL );
		
		int sd = connremote(&(joining->dhtn_addr), joining->dhtn_port);
		err = send(sd, (char *) &reidmsg, sizeof(dhtmsg_t), 0);
		net_assert((err != sizeof(dhtmsg_t)), "dhtn::reud: send");
		close(sd);
		return;
	}
	
	// wlcm the joining node
	if ( ID_inrange(joining->dhtn_ID, pred->dhtn_ID, self.dhtn_ID) ) {
		close(sender);
		
		dhtmsg_t wlcmmsg;
		mkmsg( &wlcmmsg, DHTM_WLCM, &self );
		
		int sd = connremote( &joining->dhtn_addr, joining->dhtn_port);
		printf("sending wlcmmsg...\n");
		err = send(sd, (char *) &wlcmmsg, sizeof(dhtmsg_t), 0);
		net_assert((err != sizeof(dhtmsg_t)), "dhtn:wlcm: send");
		printf("sending pred node...\n");
		err = send(sd, (char *) pred, sizeof(dhtnode_t), 0);
		net_assert((err != sizeof(dhtnode_t)), "dhtn:wlcm: send");
		
		// updating predecessor, call fixdn
		printf("updating pred node...\n");
		memcpy((char *) pred, (char *) joining, sizeof(dhtnode_t));	
		if ( self.dhtn_ID == fingers[0].dhtn_ID ) {
			printf("updating succ node...\n");
			memcpy((char *) &(fingers[0]), (char *) joining, sizeof(dhtnode_t));
			fixup(0);
		}
		fixdn(DHTN_FINGERS);
		
		//printFingers(&self, fingers);
		close(sd);
		return;
	}
	
	// redrt the sender
	if ( dhtmsg->dhtm_type & DHTM_ATLOC ) {
		dhtmsg_t redrtmsg;
		mkmsg( &redrtmsg, DHTM_REDRT, pred );
		err = send(sender, (char *) &redrtmsg, sizeof(dhtmsg_t), 0);
		net_assert((err != sizeof(dhtmsg_t)), "dhtn:redrt: send");
		close(sender);
		return;
	}
	
	// subject to change
	close(sender);
	forward(joining->dhtn_ID, dhtmsg, sizeof(dhtmsg_t));
	
	return;
}

// TODO
void dhtn::handlesearch(int sender, dhtsrch_t * dhtsrch) {
	
	//cout << "entering dhtn::handlesearch()...\n";
	
	int err;
	unsigned char imgID = dhtsrch->dhts_imgID;
	char * imgname = dhtsrch->dhts_name;
	dhtnode_t * originator = &(dhtsrch->dhts_msg.dhtm_node);
	dhtnode_t * pred = &(fingers[DHTN_FINGERS]);	
	
	printf("searching for image %s(%d)...\n", imgname, imgID);
	if ( dhtn_imgdb.searchdb(imgname) > 0 ) {
		// queried image is in local database or has been cached
		close(sender);
		
		dhtsrch_t rplymsg;
		mksrch( &rplymsg, DHTM_REPLY, NULL, imgname );
		
		int sd = connremote( &originator->dhtn_addr, originator->dhtn_port);
		printf("sending rplymsg(REPLY)...\n");
		err = send(sd, (char *) &rplymsg, sizeof(dhtsrch_t), 0);
		net_assert((err != sizeof(dhtsrch_t)), "dhtn:reply: send");
		
		close(sd);
		return;
	}
	
	if ( ID_inrange(imgID, pred->dhtn_ID, self.dhtn_ID) ) {
		// queried image is within range but not found
		close(sender);
		
		dhtsrch_t rplymsg;
		mksrch( &rplymsg, DHTM_MISS, NULL, imgname );
		
		int sd = connremote( &originator->dhtn_addr, originator->dhtn_port);
		printf("sending rplymsg(MISS)...\n");
		err = send(sd, (char *) &rplymsg, sizeof(dhtsrch_t), 0);
		net_assert((err != sizeof(dhtsrch_t)), "dhtn:reply: send");
		
		close(sd);
		return;
	}
	
	if ( dhtsrch->dhts_msg.dhtm_type & DHTM_ATLOC ) {
		/* if the queried image ID is not within range, but the sender expected
		 * it to be within range, send back a DHTM_REDRT message */
		dhtmsg_t redrtmsg;
		mkmsg( &redrtmsg, DHTM_REDRT, pred );
		printf("sending redrtmsg...\n");
		err = send(sender, (char *) &redrtmsg, sizeof(dhtmsg_t), 0);
		net_assert((err != sizeof(dhtmsg_t)), "dhtn:redrt: send");
		
		close(sender);
		return;
	}
	
	close(sender);
	forward(imgID, (dhtmsg_t *) dhtsrch, sizeof(dhtsrch_t));
	
	return;
}

/* handlepkt: receive and parse packet.
 * The argument "sender" is the socket where the connection has been established.
 * First receive a packet from the sender. Then depending on the packet type,
 * call the appropriate packet handler.
 */
void dhtn::handlepkt(int sender) {
	//cout << "entering dhtn::handlepkt()...\n";
	dhtmsg_t dhtmsg;
	int recvd = recvbysize(sender, (char *) &dhtmsg, sizeof(dhtmsg_t));
	
	if ( recvd > 0 ) {
		net_assert((dhtmsg.dhtm_vers != NETIMG_VERS), "dhtn::join: bad version");
		
		if (dhtmsg.dhtm_type == DHTM_REID) {
			/* an ID collision has occurred */
			net_assert(!fqdn, "dhtn::handlepkt: received reID but no known node");
			fprintf(stderr, "\tReceived REID from node %d\n", dhtmsg.dhtm_node.dhtn_ID);
			close(sender);
			reID();
			join();
			
		} else if (dhtmsg.dhtm_type & DHTM_WLCM) {
			fprintf(stderr, "\tReceived WLCM from node %d\n", dhtmsg.dhtm_node.dhtn_ID);
			// store successor node
			printf("updating succ node...\n");
			memcpy((char *) &(fingers[0]), (char *) &(dhtmsg.dhtm_node), sizeof(dhtnode_t));
			fixup(0);
			// receive predecessor node
			printf("updating pred node...\n");
			recvd = recvbysize(sender, (char *) &(fingers[DHTN_FINGERS]), sizeof(dhtnode_t));
			net_assert((recvd <= 0), "dhtn::handlepkt: welcome recv pred");
			fixdn(DHTN_FINGERS);
			close(sender);
			
			//printFingers(&self, fingers);
			
		} else if (dhtmsg.dhtm_type & DHTM_JOIN) {
			net_assert(!(fingers[DHTN_FINGERS].dhtn_port && fingers[0].dhtn_port),
				"dhtn::handlepkt: receive a JOIN when not yet integrated into the DHT.");
			fprintf(stderr, "\tReceived JOIN (%d) from node %d\n",
				ntohs(dhtmsg.dhtm_ttl), dhtmsg.dhtm_node.dhtn_ID);
			handlejoin(sender, &dhtmsg);	// handlejoin is responsible for closing sender
			
		} else if ( dhtmsg.dhtm_type & DHTM_FIND ) {
			
			//TODO
			/* when you receive a DHTM_FIND packet from a client, you first
			 * search your local database and cache for the image */
			iqry_t iqry;
			memcpy((char *) &iqry, (char *) &dhtmsg, sizeof(dhtmsg_t));
			
			recvd = recvbysize(sender, (char *) &iqry+sizeof(dhtmsg_t), sizeof(iqry_t)-sizeof(dhtmsg_t));
			net_assert((recvd <= 0), "dhtn::handlepkt: recv iqry");
			
			fprintf(stderr, "\tReceived FIND %s(%d) from client \n", iqry.iq_name, getimgID(iqry.iq_name));
			search_sd = sender;
			int found = dhtn_imgdb.searchdb(iqry.iq_name);
			if ( found > 0 ) {
				
				printf("target found in local database...\n");
				sendimg(found);	// sendimg is responsible for closing sender
			
			} else if ( self.dhtn_ID != fingers[0].dhtn_ID ) {
				
				dhtsrch_t srch;
				mksrch(&srch, DHTM_QUERY, &self, iqry.iq_name);
				unsigned char id = getimgID(iqry.iq_name);
				forward(id, (dhtmsg_t *)&srch, sizeof(dhtsrch_t));	
				
				/*
				 * Do not close sender until we receive a response
				 */
				
			} else {
				
				sendimg(0);
			}
		
		} else if ( dhtmsg.dhtm_type == DHTM_MISS ) {	
			
			//TODO
			close(sender);
			sendimg(0);
			
		} else if ( dhtmsg.dhtm_type == DHTM_REPLY ) {
			
			//TODO
			dhtsrch_t rply;
			memcpy((char *) &rply, (char *) &dhtmsg, sizeof(dhtmsg_t));
			
			recvd = recvbysize(sender, (char *) &rply+sizeof(dhtmsg_t), sizeof(dhtsrch_t)-sizeof(dhtmsg_t));
			net_assert((recvd <= 0), "dhtn::handlepkt: recv reply");
			
			fprintf(stderr, "\tReceived REPLY of image %s\n", rply.dhts_name);
			close(sender);
			
			// cache the queried image into local database
			//TODO How do you know that imgdb_size has not exceeded imgdb_maxdbsize?
			unsigned char * md = getimgMD(rply.dhts_name);
			unsigned char id = getimgID(rply.dhts_name);
			dhtn_imgdb.loadimg(id, md, rply.dhts_name);
			dhtn_imgdb.readimg(rply.dhts_name);
			delete [] md;
			sendimg(1);
			
		} else if ( dhtmsg.dhtm_type & DHTM_QUERY ) {
			
			//TODO
			dhtsrch_t srch;
			memcpy((char *) &srch, (char *) &dhtmsg, sizeof(dhtmsg_t));
			
			recvd = recvbysize(sender, (char *) &srch+sizeof(dhtmsg_t), sizeof(dhtsrch_t)-sizeof(dhtmsg_t));
			net_assert((recvd <= 0), "dhtn::handlepkt: recv dhtsrch");
			
			fprintf(stderr, "\tReceived QUERY(%d) from node %d\n",
				ntohs(dhtmsg.dhtm_ttl), dhtmsg.dhtm_node.dhtn_ID);
			handlesearch(sender, &srch);	// handlesearch is responsible for closing sender


		} else {
			net_assert((dhtmsg.dhtm_type & DHTM_REDRT),
				"dhtn::handlepkt: overshoot message received out of band");
			close(sender);
		}
	}

	return;
}

// TODO
void dhtn::fixup(int idx) {
	// just follow the instruction, totally no idea...
	//cout << "entering dhtn::fixup()...\n";
	int stop = 0;
	for ( int k = idx+1; k < DHTN_FINGERS && !stop; k++ ) {
		if (ID_inrange(fID[k], self.dhtn_ID, fingers[idx].dhtn_ID)) {
			memcpy((char *) &(fingers[k]), (char *) &(fingers[idx]), sizeof(dhtnode_t));
		} else {
			stop = 1;
		}
	}
	//printFingers(&self, fingers);
	return;
}

// TODO
void dhtn::fixdn(int idx) {
	//cout << "entering dhtn::fixdn()...\n";
	for ( int k = idx-1; k >= 0; k-- ) {
		if (ID_inrange(fingers[idx].dhtn_ID, fID[k], fingers[k].dhtn_ID)) {
			memcpy((char *) &(fingers[k]), (char *) &(fingers[idx]), sizeof(dhtnode_t));
		}
	}
	if ( idx == DHTN_FINGERS ) {
		dhtn_imgdb.reloaddb(fingers[idx].dhtn_ID, self.dhtn_ID);
	}
	//printFingers(&self, fingers);
	return;
}

// TODO
/*
 * sendimg: send the image to the client
 * First send the specifics of the iamges (width, height, etc.)
 * in an imsg_t packet to the client. The type imsg_t is defined in netimg.h.
 * If "found" is > 0, send the image contained in imgdb. Otherwise, set the
 * img_depth field of the imsg_t packet to 0 and send only the imsg_t packet.
 * For debugging purposes if an image is send, it is send in chunks of segsize
 * instead of as one single image. We're going to send the image slowly, one
 * chunk for every NETIMG_USLEEP microseconds.
 *
 * Terminate process upon encountering any error.
 * Doesn't otherwise modify anything
 */
void dhtn::sendimg(int found) {
	int segsize;
	char * ip;
	int bytes;
	long left;
	imsg_t imsg;
	double imgdsize;
	long imgsize = 0L;
	
	imsg.im_vers = NETIMG_VERS;
	
	if ( found <= 0 ) {
		if ( !found ) {
			cerr << "Bloom filter missed." << endl;
		} else {
			cerr << "Bloom filter false positive." << endl;
		}
		imsg.im_depth = (unsigned char) 0;
	} else {
		imgdsize = dhtn_imgdb.marshall_imsg(&imsg);
		net_assert((imgdsize > (double) LONG_MAX), "dhtn::sendimg: image too large");
		imgsize = (long) imgdsize;
		
		imsg.im_width = htons(imsg.im_width);
		imsg.im_height = htons(imsg.im_height);
		imsg.im_format = htons(imsg.im_format);
	}
	
	/*
	 * Send the imsg packet to client connected to socket search_sd
	 */
	bytes = send(search_sd, (char *) &imsg, sizeof(imsg_t), 0);
	net_assert((bytes != sizeof(imsg_t)), "dhtn::sendimg: send imsg");
	
	if ( found > 0 ) {
		segsize = imgsize/NETIMG_NUMSEG;	/* compute segment size */
		segsize = segsize < NETIMG_MSS ? NETIMG_MSS : segsize;	/* but don't let segment be too small */
		ip = dhtn_imgdb.getimage();	/* ip points to the start of byte buffer holding image */
		for ( left = imgsize; left; left -= bytes ) {
			bytes = send(search_sd, (char *) ip, segsize > left ? left : segsize, 0);
			net_assert((bytes < 0), "dhtn::sendimg: send image");
			ip += bytes;
			fprintf(stderr, "dhtn::sendimg: size %d, sent %d\n", (int) left, bytes);
			usleep(NETIMG_USLEEP);
		}
	}
	
	close(search_sd);
	return;
}

// TODO
void dhtn::sendREDRT(int sender, dhtmsg_t * dhtmsg, int size) {

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
			fprintf(stderr, "Node ID: %d, fingers: ", self.dhtn_ID);
			for ( int i = 0; i < DHTN_FINGERS; i++ ) {
				fprintf(stderr, "%d:%d ", 
					fID[i]%(NETIMG_IDMAX+1), fingers[i].dhtn_ID);
			}
			fprintf(stderr, "pred: %d\n", fingers[DHTN_FINGERS].dhtn_ID);
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
	char * imagefolder = NULL;
	int id, status;
		
#ifdef _WIN32
	WSADATA wsa;
	
	err = WSAStartup(MAKEWORD(2,2), &wsa);	// winsock 2.2
	net_assert(err, "sockinit: WSAStartup");
#endif
	
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN); 	// don't die if peer is dead
#endif
	
	/* parse args */
	if (dhtn_args( argc, argv, &cli_fqdn, &cli_port, &id, &imagefolder)) {
		dhtn_usage(argv[0]);
	}

	dhtn node(id, cli_fqdn, cli_port, imagefolder);	// initialize node, create listen socket
	
	if ( cli_fqdn ) {
		node.join();	// join DHT if known host given
	} else {
		node.first();	// else this is the first node on ID circle
	}
	
	do {
		status = node.mainloop();
	} while (status);
	
#ifdef _WIN32
	WSACleanup();
#endif
	exit(0);
}

