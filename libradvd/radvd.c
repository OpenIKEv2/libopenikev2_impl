/*
 *   $Id: radvd.c,v 1.37 2008/10/15 05:34:35 psavola Exp $
 *
 *   Authors:
 *    Pedro Roque		<roque@di.fc.ul.pt>
 *    Lars Fenneberg		<lf@elemental.net>	 
 *
 *   This software is Copyright 1996-2000 by the above mentioned author(s), 
 *   All Rights Reserved.
 *
 *   The license which is distributed with this software in the file COPYRIGHT
 *   applies to this software. If your distribution is missing this file, you
 *   may request it from <pekkas@netcore.fi>.
 *
 */

#include <config.h>
#include <includes.h>
#include <radvd.h>
#include <pathnames.h>

struct Interface *IfaceList = NULL;

extern FILE *yyin;

char *conf_file = NULL;
char *pname;
int sock = -1;

int yywrap(void){
    return 1;
}

