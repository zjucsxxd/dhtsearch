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
  
imgdb::imgdb()
{
  imgdb_folder = "images";
  imgdb_IDrange[IMGDB_IDRBEG] = 0;
  imgdb_IDrange[IMGDB_IDREND] = 0;
  imgdb_size = 0;
  imgdb_bloomfilter = 0L;
}


/*
 * cli: parses command line args.
 *
 * Returns 0 on success or 1 on failure.  On successful return,
 * imgdb_folder, imgdb_IDrange[IMGDB_IDRBEG], and/or
 * imgdb_IDrange[IMGDB_IDREND] would have been initialized to the
 * values specified in the command line.
 * Nothing else is modified.
 */
int
imgdb::
cli(int argc, char *argv[])
{
  char c;
  int val;
  extern char *optarg;

  while ((c = getopt(argc, argv, "i:b:e:")) != EOF) {
    switch (c) {
    case 'i':
      imgdb_folder = optarg;
      break;
    case 'b':
      val = (unsigned char ) atoi(optarg);
      net_assert((val < 0 || val > NETIMG_IDMAX), "imgdb::cli: beginID out of range");
      imgdb_IDrange[IMGDB_IDRBEG] = (unsigned char) val;
      break;
    case 'e':
      val = (unsigned char ) atoi(optarg);
      net_assert((val < 0 || val > NETIMG_IDMAX), "imgdb::cli: endID out of range");
      imgdb_IDrange[IMGDB_IDREND] = (unsigned char) val;
      break;
    default:
      return(1);
      break;
    }
  }

  return (0);
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
  fstream list_fs, img_fs;
  char fname[IMGDB_MAXFNAME];
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
    list_fs.getline(fname, IMGDB_MAXFNAME);
    if (list_fs.eof()) break;
    net_assert(list_fs.fail(), "imgdb::loaddb: image file name longer than IMGDB_MAXFNAME");

    /* for each image, we compute its SHA1 from its file name, without the image folder path. */
    SHA1((unsigned char *) fname, strlen(fname), md);

    /* from the SHA1, we compute an object ID */
    id = ID(md);
    cerr << "  (" << setw(3) << (int) id << ") " << fname;

    /* if the object ID is in the range of this node, add its ID and name to the database */
    if (ID_inrange(id, imgdb_IDrange[IMGDB_IDRBEG], imgdb_IDrange[IMGDB_IDREND])) {
      cerr << " *in range*";

      /* first check if the file can be opened, to that end, we need to constuct
         the path name first, e.g., "images/ShipatSea.tga".
      */
      pathname = imgdb_folder+IMGDB_DIRSEP+fname;
      img_fs.open(pathname.c_str(), fstream::in);
      net_assert(img_fs.fail(), "imgdb::loaddb: fail to open image file");
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
 * searchdb(imgname): search for imgname in the DB.
 * To search for the imagename, first compute its SHA1, then
 * compute its object ID from its SHA1.  Next check whether
 * there is a hit for the image in the Bloom Filter.  If it is
 * a miss, return 0.  Otherwise, search the database for a match
 * to BOTH the image ID and its name (so a hash collision on the
 * ID is resolved here).  If a match is found, return 1, otherwise
 * return -1.
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
   * If Bloom Filter misses, return 0.
   */
  /* YOUR CODE HERE */
	/* Compute SHA1, stored in md */
	unsigned char md[SHA1_MDLEN];
	SHA1((unsigned char *) imgname, strlen(imgname), md);
	
	/* from the SHA1, we compute an object ID */
	id = ID(md);
	
	/* TODO Then check Bloom Filter for a hit or miss */
  	unsigned long tmp = (1L << (int) bfIDX(BFIDX1, md)) |
		(1L << (int) bfIDX(BFIDX2, md)) | (1L << (int) bfIDX(BFIDX3, md));	
	if ((imgdb_bloomfilter | tmp) != imgdb_bloomfilter ) return 0;

  /* To get here means that you've got a hit at the Bloom Filter.
   * Search the DB for a match to BOTH the image ID and name.
  */
  for (i = 0; i < imgdb_size; i++) {
    if ((id == imgdb_db[i].img_ID) && !strcmp(imgname, imgdb_db[i].img_name)) {
      /* load image given pathname relative to current working directory. */
      pathname = imgdb_folder+IMGDB_DIRSEP+imgname;
      imgdb_curimg.LoadFromFile(pathname);
      return(1);
    }
  }

  return(-1);
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
 * Remove the "#if 0" and "#endif" lines if you want to compile this file without dhtn.cpp
 * to play with bloom filter and the other functions here and to test your searchdb function. 
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
  char *imgname="ShipatSea.tga";

  if (argc > 1) {
    imgdb.cli(argc, argv);
  }
  imgdb.loaddb();

  found = imgdb.searchdb(imgname);
  if (found < 0) {
    cerr << argv[0] << ": " << imgname << ": image not found." << endl;
  } else if (!found) {
    cerr << argv[0] << ": " << imgname << ": Bloom filter miss, image not found." << endl;
  } else { 
    netimg_glutinit(&argc, argv, NULL);
    netimg_imginit();
    imgdb.display();
    glutMainLoop();
  }
  
  return(0);
}
#endif
