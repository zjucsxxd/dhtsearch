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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>        // LONG_MAX
#include <iostream>
#include <iomanip>         // setw()
#include <fstream>
using namespace std;
#ifdef __APPLE__
#include <GLUT/glut.h>
#else
#include <GL/glut.h>
#endif

#include "ltga.h"
#include "netimg.h"
#include "hash.h"
#include "imgdb.h"
  

imgdb::
imgdb()
{
  imgdb_folder = "images";
  imgdb_IDrange[IMGDB_IDRBEG] = 0;
  imgdb_IDrange[IMGDB_IDREND] = 0;
  imgdb_size = 0;
  imgdb_bloomfilter = 0L;
}

/*
 * loadimg:
 * load the image associate with fname into imgdb_db.
 * "md" is the SHA1 output computed over fname and 
 * "id" is the id computed from md.
 * The Bloom Filter is also updated after the image is loaded.
*/
void imgdb::
loadimg(unsigned char id, unsigned char *md, char *fname)
{
  string pathname;
  fstream img_fs;

  /* first check if the file can be opened, to that end, we need to constuct
     the path name first, e.g., "images/ShipatSea.tga".
  */
  pathname = imgdb_folder+IMGDB_DIRSEP+fname;
  img_fs.open(pathname.c_str(), fstream::in);
  net_assert(img_fs.fail(), "imgdb::loadimg: fail to open image file");
  img_fs.close();

  /* if the file can be opened, store the image name, without the folder name,
     into the database */
  strcpy(imgdb_db[imgdb_size].img_name, fname);

  /* store its ID also */
  imgdb_db[imgdb_size].img_ID = id;

  /* update the bloom filter to record the presence of the image in the DB. */
  imgdb_bloomfilter |= (1L << (int) bfIDX(BFIDX1, md)) |
    (1L << (int) bfIDX(BFIDX2, md)) | (1L << (int) bfIDX(BFIDX3, md));

  imgdb_size++;

  return;
}

/*
 * loaddb(): load the image database with the ID and name of all images whose ID are
 * within the ID range of this node.
 * See inline comments below
 */
void
imgdb::
loaddb()
{
  fstream list_fs;
  char fname[NETIMG_MAXFNAME];
  string pathname;
  unsigned char id, md[SHA1_MDLEN];

  /* imgdb_folder contains the name of the folder where the image files are, e.g.,
     "images".  We assume there's a file in that folder whose name is specified by
     IMGDB_FILELIST, e.g., "FILELIST.txt".  To open and read this file, we first
     construct its path name relative to the current directory, e.g., "images/FILELIST.txt".
  */
  pathname = imgdb_folder+IMGDB_DIRSEP+IMGDB_FILELIST;
  list_fs.open(pathname.c_str(), fstream::in);
  net_assert(list_fs.fail(), "imgdb::loaddb: fail to open FILELIST.txt.");

  /* After FILELIST.txt is open for reading, we parse it one line at a time,
     each line is assumed to contain the name of one image file.
  */
  cerr << "Loading DB IDs in (" << (int) imgdb_IDrange[IMGDB_IDRBEG] <<
    ", " << (int) imgdb_IDrange[IMGDB_IDREND] << "]\n";
  do {
    list_fs.getline(fname, NETIMG_MAXFNAME);
    if (list_fs.eof()) break;
    net_assert(list_fs.fail(), "imgdb::loaddb: image file name longer than NETIMG_MAXFNAME");

    /* for each image, we compute its SHA1 from its file name, without the image folder path. */
    SHA1((unsigned char *) fname, strlen(fname), md);

    /* from the SHA1, we compute an object ID */
    id = ID(md);
    cerr << "  (" << setw(3) << (int) id << ") " << fname;

    /* if the object ID is in the range of this node, add its ID and name to the database */
    if (ID_inrange(id, imgdb_IDrange[IMGDB_IDRBEG], imgdb_IDrange[IMGDB_IDREND])) {
      cerr << " *in range*";
      loadimg(id, md, fname);
    }
    cerr << endl;
  } while (imgdb_size < IMGDB_MAXDBSIZE);

  cerr << imgdb_size << " images loaded." << endl;
  if (imgdb_size == IMGDB_MAXDBSIZE) {
    cerr << "Image DB full, some image could have been left out." << endl;
  }
  cerr << endl;
  
  list_fs.close();
  
  return;
}

/*
 * reloaddb:
 * reload the imgdb_db with only images whose IDs are in (begin, end].
 * Clear the database of cached images and reset the Bloom Filter
 * to represent the new set of images.
 */
void imgdb::
reloaddb(unsigned char begin, unsigned char end)
{
  imgdb_IDrange[IMGDB_IDRBEG] = begin;
  imgdb_IDrange[IMGDB_IDREND] = end;
  imgdb_size = 0;
  imgdb_bloomfilter = 0L;
  loaddb();
}

/*
 * searchdb(imgname): search for imgname in the DB.  To search for the
 * imagename, first compute its SHA1, then compute its object ID from
 * its SHA1.  Next check whether there is a hit for the image in the
 * Bloom Filter.  If it is a miss, return 0.  Otherwise, search the
 * database for a match to BOTH the image ID and its name (so a hash
 * collision on the ID is resolved here).  If a match is found, return
 * IMGDB_FOUND, otherwise return IMGDB_MISS if there's a Bloom Filter
 * miss else IMGDB_FALSE.
*/
int
imgdb::
searchdb(char *imgname)
{
  int i;
  string pathname;
  unsigned char id = 0;

  /* Task 2:
   * Compute SHA1 and object ID.
   * Then check Bloom Filter for a hit or miss.
   * If Bloom Filter misses, return IMGDB_MISS.
   */
  /* YOUR LAB 3 CODE HERE */
	unsigned char md[SHA1_MDLEN];
	SHA1((unsigned char *) imgname, strlen(imgname), md);
	id = ID(md);
	unsigned long tmp = (1L << (int) bfIDX(BFIDX1, md)) |
		(1L << (int) bfIDX(BFIDX2, md)) | (1L << (int) bfIDX(BFIDX3, md));
	if ((imgdb_bloomfilter | tmp) != imgdb_bloomfilter) return 0;

  /* To get here means that you've got a hit at the Bloom Filter.
   * Search the DB for a match to BOTH the image ID and name.
  */
  for (i = 0; i < imgdb_size; i++) {
    if ((id == imgdb_db[i].img_ID) && !strcmp(imgname, imgdb_db[i].img_name)) {
      /* load image given pathname relative to current working directory. */
      readimg(imgname);
      return(IMGDB_FOUND);
    }
  }

  return(IMGDB_FALSE);
}

/*
 * marshall_imsg: Initialize *imsg with image's specifics.
 * Upon return, the *imsg fields are in host-byte order.
 * Return value is the size of the image in bytes.
 *
 * Terminate process on encountering any error.
 */
double
imgdb::
marshall_imsg(imsg_t *imsg)
{
  int alpha, greyscale;
  
  imsg->im_depth = (unsigned char)(imgdb_curimg.GetPixelDepth()/8);
  imsg->im_width = imgdb_curimg.GetImageWidth();
  imsg->im_height = imgdb_curimg.GetImageHeight();
  alpha = imgdb_curimg.GetAlphaDepth();
  greyscale = imgdb_curimg.GetImageType();
  greyscale = (greyscale == 3 || greyscale == 11);
  if (greyscale) {
    imsg->im_format = alpha ? GL_LUMINANCE_ALPHA : GL_LUMINANCE;
  } else {
    imsg->im_format = alpha ? GL_RGBA : GL_RGB;
  }

  return((double) (imgdb_curimg.GetImageWidth() *
                   imgdb_curimg.GetImageHeight() *
                   (imgdb_curimg.GetPixelDepth()/8)));
}
  
/*
 * Remove the "#if 0" and "#endif" lines and those in imgdb.h
 * if you want to compile this file without dhtn.cpp to play 
 * with bloom filter and the other functions here and to test 
 * your searchdb function. 
*/
#if 0
void
imgdb::
display()
{
  imsg_t imsg;

  marshall_imsg(&imsg);

  /* give the updated image to OpenGL for texturing */
  glTexImage2D(GL_TEXTURE_2D, 0, (GLint) imsg.im_format,
               (GLsizei) imsg.im_width, (GLsizei) imsg.im_height, 0,
               (GLenum) imsg.im_format, GL_UNSIGNED_BYTE, imgdb_curimg.GetPixels());

  return;
}

int
main(int argc, char *argv[])
{
  int found;
  imgdb imgdb;

  if (argc > 1) {
    imgdb.cli(argc, argv);
  }
  imgdb.loaddb();

  found = imgdb.searchdb(imgname);
  if (found == IMGDB_FALSE) {
    cerr << argv[0] << ": " << imgname << ": Bloom filter false positive." << endl;
  } else if (found == IMGDB_MISS) {
    cerr << argv[0] << ": " << imgname << ": Bloom filter miss." << endl;
  } else { 
    netimg_glutinit(&argc, argv, NULL);
    netimg_imginit();
    imgdb.display();
    glutMainLoop();
  }
  
  return(0);
}
#endif
