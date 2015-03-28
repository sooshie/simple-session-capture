#include "filehashmap.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

long double filename_num(char *filename)
{
  unsigned int length = 0;
  long double total = 0;
  long double base = 31.0;

  length = (unsigned)strlen(filename);
  char* cur = filename + length-1;
  int pos = 0;
   while (cur != filename-1)
   {
     total += (int)*cur * pow(base, pos);
     //printf("%30.0Lf\n", total);
     --cur; ++pos;
   }
   return total;
}

int _mkdir(const char *dir) {
  char tmp[256];
  char *p = NULL;
  size_t len;
  int retval = 0; 

  snprintf(tmp, sizeof(tmp),"%s",dir);
  len = strlen(tmp);
  if(tmp[len - 1] == '/')
    tmp[len - 1] = 0;

  for(p = tmp + 1; *p; p++)
    if(*p == '/') {
      *p = 0;
      retval = mkdir(tmp, S_IRWXU | S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP);
      if (retval != 0 && errno != EEXIST)
        return retval;
      *p = '/';
    }
  retval = mkdir(tmp, S_IRWXU | S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP);
  if (retval != 0 && errno != EEXIST)
    return retval;

  return 0;
}

char *directory_structure(char *filename)
{
  long double number = 0;
  char hash[HASHMAX];
  char str[STRING_LEN];
  int retval = 0;
  int temp = 0;
  char a[9];
  char b[9];
  char c[9];
  char d[9];
  char *dir = NULL;

  memset(hash, 0, HASHMAX*sizeof(char));
  memset(str, 0, STRING_LEN*sizeof(char));

  temp = strlen(filename);
  if (temp < (STRING_LEN - 1))
  {
    memcpy(&str, filename, temp);
    memset(&str[temp], 48, STRING_LEN-temp);
    memset(&str[21], 0, 1);
    number = filename_num(str);
  }
  else
    number = filename_num(filename);

  retval = snprintf(hash, HASHMAX, "%.0Lf", number);
  if (retval < 0)
    return NULL;

  memcpy(&a, &hash, 8);
  memset(&a[8], 0, 1);
  memcpy(&b, &hash[8], 8);
  memset(&b[8], 0, 1);
  memcpy(&c, &hash[16], 8);
  memset(&c[8], 0, 1);
  memcpy(&d, &hash[24], 8);
  memset(&d[8], 0, 1);

  //printf("%s\n", hash);
  //printf("%s %s %s %s\n", a, b, c, d);
  temp = DIRLEN * sizeof(char);
  dir = malloc(temp);
    if (dir == NULL)
      return NULL;

  memset(dir, 0, temp);
  snprintf(dir, temp, "%s/%s/%s/%s/", a, b, c, d);
  //printf("*** %s %s %lu\n", dir, filename, sizeof(dir));

  return dir;
}
