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
#include <stdio.h>         // fprintf(), perror(), fflush()
#include <stdlib.h>        // atoi()
#include <assert.h>        // assert()
#include <limits.h>        // LONG_MAX
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>      // socklen_t
#include "wingetopt.h"
#else
#include <string.h>        // memset(), memcmp(), strlen(), strcpy(), memcpy()
#include <unistd.h>        // getopt(), STDIN_FILENO, gethostname()
#include <signal.h>        // signal()
#include <netdb.h>         // gethostbyname()
#include <netinet/in.h>    // struct in_addr
#include <arpa/inet.h>     // htons()
#include <sys/types.h>     // u_short
#include <sys/socket.h>    // socket API
#endif
#ifdef __APPLE__
#include <GLUT/glut.h>
#else
#include <GL/glut.h>
#endif

#include "netimg.h"
#include "dhtn.h"

int sd;                   /* socket descriptor */

imsg_t imsg;
char *image;
long img_size;    
long img_offset;

void
dhtc_usage(char *progname)
{
  fprintf(stderr, "Usage: %s -s serverFQDN.port -q <imagename.tga>\n", progname); 
  exit(1);
}

/*
 * dhtc_args: parses command line args.
 *
 * Returns 0 on success or 1 on failure.  On successful return, *sname points to the server's FQDN,
 * and "port" points to the port to connect at server, in network byte order.  Both "*sname", and
 * "port" must be allocated by caller.  The variable "*imagename" points to the name of the image
 * to search for.
 *
 * Nothing else is modified.
 */
int
dhtc_args(int argc, char *argv[], char **sname, u_short *port, char **imagename)
{
  char c, *p;
  extern char *optarg;

  if (argc < 5) {
    return (1);
  }
  
  while ((c = getopt(argc, argv, "s:q:")) != EOF) {
    switch (c) {
    case 's':
      for (p = optarg+strlen(optarg)-1;      // point to last character of addr:port arg
           p != optarg && *p != NETIMG_PORTSEP;  // search for ':' separating addr from port
           p--);
      net_assert((p == optarg), "dhtc_args: server address malformed");
      *p++ = '\0';
      *port = htons((u_short) atoi(p)); // always stored in network byte order

      net_assert((p-optarg > NETIMG_MAXFNAME), "dhtc_args: FQDN too long");
      *sname = optarg;
      break;
    case 'q':
      net_assert((strlen(optarg) >= NETIMG_MAXFNAME), "dhtc_args: image name too long");
      *imagename = optarg;
      break;
    default:
      return(1);
      break;
    }
  }

  return (0);
}

/*
 * dhtc_sockinit: creates a new socket to connect to the provided server.
 * The server's FQDN and port number are provided.  The port number
 * provided is assumed to already be in netowrk byte order.
 *
 * On success, the global socket descriptor sd is initialized.
 * On error, terminates process.
 */
void
dhtc_sockinit(char *sname, u_short port)
{
  int err;
  struct sockaddr_in server;
  struct hostent *sp;

#ifdef _WIN32
  WSADATA wsa;
  
  err = WSAStartup(MAKEWORD(2,2), &wsa);  // winsock 2.2
  net_assert(err, "dhtc_sockinit: WSAStartup");
#endif

  /* 
   * create a new TCP socket, store the socket in the global variable sd
  */
  sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   // sd global
  net_assert((sd < 0), "dhtc_sockinit: socket");

  /* obtain the server's IPv4 address from sname and initialize the
     socket address with server's address and port number . */
  memset((char *) &server, 0, sizeof(struct sockaddr_in));
  server.sin_family = AF_INET;
  server.sin_port = port;
  sp = gethostbyname(sname);
  net_assert((sp == 0), "dhtc_sockinit: gethostbyname");
  memcpy(&server.sin_addr, sp->h_addr, sp->h_length);

  /* connect to server */
  err = connect(sd, (struct sockaddr *) &server, sizeof(struct sockaddr_in));
  net_assert(err, "dhtc_sockinit: connect");

  return;
}

/*
 * dhtc_sendquery: send a query for provided imagename to connected server.
 * Query is of type iqry_t, defined in netimg.h
 *
 * On send error, return 0, else return 1
 */
int
dhtc_sendquery(char *imagename)
{
  int bytes;
  iqry_t iqry;

  iqry.iq_vers = NETIMG_VERS;
  iqry.iq_type = DHTM_FIND;
  strcpy(iqry.iq_name, imagename); 
  bytes = send(sd, (char *) &iqry, sizeof(iqry_t), 0);
  if (bytes != sizeof(iqry_t)) {
    // the other could have closed connection since
    // only one active search is allowed at any time
    close(sd);
    return(0);
  }

  return(1);
}
  
/*
 * dhtc_recvimsg: receive an imsg_t packet from server and store it 
 * in the global variable imsg.  The type imsg_t is defined in netimg.h.
 * Check that received message is of the right version number.
 * If message is of a wrong version number and for any other
 * error in receiving packet, terminate process.
 * Convert the integer fields of imsg back to host byte order.
 * If the received imsg has im_depth field = 0, it indicates
 * that no image is sent back, most likely due to image not found.
 * In which case, return 0, otherwise return 1.
 */
int
dhtc_recvimsg()
{
  int bytes;
  double img_dsize;

  bytes = recv(sd, (char *) &imsg, sizeof(imsg_t), 0);   // imsg global
  if (bytes <= 0) {
    // the other could have closed connection since
    // only one active search is allowed at any time
    close(sd);
    return(-1);
  }

  net_assert((bytes != sizeof(imsg_t)), "dhtc_recvimsg: malformed header");
  net_assert((imsg.im_vers != NETIMG_VERS), "dhtc_recvimg: wrong imsg version");

  if (imsg.im_depth) {
    imsg.im_height = ntohs(imsg.im_height);
    imsg.im_width = ntohs(imsg.im_width);
    imsg.im_format = ntohs(imsg.im_format);
    
    img_dsize = (double) (imsg.im_height*imsg.im_width*(u_short)imsg.im_depth);
    net_assert((img_dsize > (double) LONG_MAX), "dhtc_recvimsg: image too large");
    img_size = (long) img_dsize;                 // global
    image = (char *)malloc(img_size*sizeof(char));
    return (1);
  }

  return (0);
}

/* Callback functions for GLUT */

/*
 * dhtc_recvimage: called by GLUT when idle
 * On each call, receive as much of the image is available on the network and
 * store it in global variable "image" at offset "img_offset" from the
 * start of the buffer.  The global variable "img_offset" must be updated
 * to reflect the amount of data received so far.  Another global variable "img_size"
 * stores the expected size of the image transmitted from the server.
 * The variable "img_size" must NOT be modified.
 * Terminate process on receive error.
 */
void
dhtc_recvimage(void)
{
  int bytes;
   
  // img_offset is a global variable that keeps track of how many bytes
  // have been received and stored in the buffer.  Initialy it is 0.
  //
  // img_size is another global variable that stores the size of the image.
  // If all goes well, we should receive img_size bytes of data from the server.
  if (img_offset <  img_size) { 
    /* 
     * Receive as much of the remaining image as available from the network
     * put the data in the buffer pointed to by the global variable 
     * "image" starting at "img_offset".
     *
     * For example, the first time this function is called, img_offset is 0
     * so the received data is stored at the start (offset 0) of the "image" 
     * buffer.  The global variable "image" should not be modified.
     *
     * Update img_offset by the amount of data received, in preparation for the
     * next iteration, the next time this function is called.
     */
    bytes = recv(sd, image+img_offset, img_size-img_offset, 0);
    net_assert((bytes < 0), "dhtc_recvimage: recv error");
    fprintf(stderr, "dhtc_recvimage: offset 0x%x, received %d bytes\n", (unsigned int) img_offset, bytes);
    img_offset += bytes;
    
    /* give the updated image to OpenGL for texturing */
    glTexImage2D(GL_TEXTURE_2D, 0, (GLint) imsg.im_format,
                 (GLsizei) imsg.im_width, (GLsizei) imsg.im_height, 0,
                 (GLenum) imsg.im_format, GL_UNSIGNED_BYTE, image);
    /* redisplay */
    glutPostRedisplay();
  }

  return;
}

int
main(int argc, char *argv[])
{
  char *sname, *imagename;
  u_short port;
  int err;

  // parse args, see the comments for dhtc_args()
  if (dhtc_args(argc, argv, &sname, &port, &imagename)) {
    dhtc_usage(argv[0]);
  }

#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);    /* don't die if peer is dead */
#endif
  
  dhtc_sockinit(sname, port);

  if (dhtc_sendquery(imagename)) {

    err = dhtc_recvimsg();
    if (err == 1) { // if image found
      netimg_glutinit(&argc, argv, dhtc_recvimage);
      netimg_imginit();
      
      /* start the GLUT main loop */
      glutMainLoop();

    } else if (err < 0) {
      fprintf(stderr, "%s: dhtn busy, please try again later.\n", argv[0]);

    } else {
      fprintf(stderr, "%s: %s image not found.\n", argv[0], imagename);
    }
  }

  return(0);
}
