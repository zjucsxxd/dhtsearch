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
#include "imgdb.h"

#define DHTN_UNINIT -1
#define DHTN_FINGERS 8  // reaches half of 2^8-1
                        // with integer IDs, fingers[0] is immediate successor

#define DHTM_TTL   10
#define DHTM_JOIN  0x01
#define DHTM_REID  0x02
#define DHTM_WLCM  0x04
#define DHTM_FIND 0x08   // image query from client, see netimg.h for iqry_t packet
#define DHTM_QUERY 0x10   // image search on the DHT
#define DHTM_REPLY 0x20   // reply to image search on the DHT
#define DHTM_MISS  0x22   // image not found on the DHT 
#define DHTM_REDRT 0x40
#define DHTM_ATLOC 0x80

typedef struct {
  unsigned char dhtn_rsvd;
  unsigned char dhtn_ID;
  u_short dhtn_port;        // port#, always stored in network byte order
  struct in_addr dhtn_addr; // IPv4 address
} dhtnode_t;

typedef struct {
  unsigned char dhtm_vers;  // must be NETIMG_VERS
  unsigned char dhtm_type;  // one of DHTM_{REDRT,JOIN,REID,WLCM} type
  u_short dhtm_ttl;         // currently used only by JOIN and QUERY messages
  dhtnode_t dhtm_node;      // REDRT: new successor
                            // JOIN: node attempting to join DHT
                            // REID: not used
                            // WLCM: successor node, to be followed by predecessor node
} dhtmsg_t;

typedef struct {
  dhtmsg_t dhts_msg;                
  unsigned char dhts_imgID;
  char dhts_name[NETIMG_MAXFNAME];
} dhtsrch_t;                // used by QUERY, REPLY, and MISS

class dhtn {
  char *fqdn;      // known host
  u_short port;    // known host's port
  int listen_sd;   // listen socket
  int search_sd;   // client search image socket
  imgdb dhtn_imgdb;
  dhtnode_t self;
  unsigned char fID[DHTN_FINGERS]; // = { 1, 2, 4, 8, 16, 32, 64, 128 };
  dhtnode_t fingers[DHTN_FINGERS+1]; // fingers[0] is immediate successor
                    // fingers[DHTN_FINGERS] is the immediate predecessor

  void setID(int ID);
  void reID();
  int connremote(struct in_addr *addr, u_short portnum);
  int acceptconn();
  void handlepkt(int sender);
  void handlejoin(int sender, dhtmsg_t *dhtmsg);
  void handlesearch(int sender, dhtsrch_t *dhtsrch);

  /* forward based on the provided id (which is either node ID for a
   * join message or image ID for a search message).  The second
   * argument could actually be a pointer to a dhtsrch_t that is cast
   * to a dhtmsg_t.  So the third argument tells the actual size of
   * the packet pointed to by the second argument.
   */
  void forward(unsigned char id, dhtmsg_t *dhtmsg, int size);

  void fixup(int idx);
  void fixdn(int idx);
  void sendimg(int found);
  void sendREDRT(int sender, dhtmsg_t *dhtmsg, int size);

public:
  dhtn(int id, char *fqdn, u_short port, char *imagefolder); // default constructor
  void first(); // first node on circle
  void join();
  int mainloop();
};  

#endif /* __IMGDB_H__ */
