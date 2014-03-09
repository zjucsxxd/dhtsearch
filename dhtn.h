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
 * Author: Sugih Jamin (jamin@eecs.umich.edu)
 *
*/
#ifndef __DHTN_H__
#define __DHTN_H__

#include "hash.h"

#define DHTN_UNINIT -1
#define DHTN_FINGERS 8  // reaches half of 2^8-1
                        // with integer IDs, fingers[0] is immediate successor

#define DHTM_TTL   10
#define DHTM_ATLOC 0x80
#define DHTM_REDRT 0x40
#define DHTM_JOIN  0x01
#define DHTM_REID  0x02
#define DHTM_WLCM  0x04

typedef struct dhtnode_s dhtnode_t;
struct dhtnode_s {
	unsigned char dhtn_rsvd;
	unsigned char dhtn_ID;
  u_short dhtn_port;        // port#, always stored in network byte order
  struct in_addr dhtn_addr; // IPv4 address
};

typedef struct {
  unsigned char dhtm_vers;  // must be NETIMG_VERS
  unsigned char dhtm_type;  // one of DHTM_{REDRT,JOIN,REID,WLCM} type
  u_short dhtm_ttl;         // currently used only by JOIN message
  dhtnode_t dhtm_node;      // REDRT: new successor
                            // JOIN: node attempting to join DHT
                            // REID: not used
                            // WLCM: successor node, to be followed by predecessor node
} dhtmsg_t;

class dhtn {
  char *fqdn;      // known host
  u_short port;    // known host's port
  int listen_sd;   // listen socket
  dhtnode_t self;
  dhtnode_t pred;
  dhtnode_t fingers[DHTN_FINGERS]; // fingers[0] is immediate successor

  void setID(int ID);
  void reID();
  int connremote(struct in_addr *addr, u_short portnum);
  int acceptconn();
  void handlepkt(int sender);
  void handlejoin(int sender, dhtmsg_t *dhtmsg);
  void forward(dhtmsg_t *dhtmsg);

public:
  dhtn(int id, char *fqdn, u_short port); // default constructor
  void first(); // first node on circle
  void join();
  int mainloop();
};  

#endif /* __IMGDB_H__ */
