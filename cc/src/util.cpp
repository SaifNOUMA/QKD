#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <oqs/oqs.h>
#include "conf.h"

#ifndef UTIL_CPP
#define UTIL_CPP

/*
 * Save an array in memory.
*/
int save_array(const char *path,
               uint8_t* array, size_t size_array)
{
  FILE *file;

  file = fopen(path, "w");
  fwrite(array, sizeof(uint8_t), size_array, file);
  fclose(file);

  return 0;
}

/*
 * Save the size of an array in memory.
*/
int save_size_array(char *path,
                    unsigned long size_array)
{
  FILE *file;

  file = fopen(path, "w");
  putw(size_array, file);
  fclose(file);

  return 0;
}

/*
 * Load an array from memory.
*/
int load_array(const char *path,
               uint8_t** array, size_t size_array)
{
  FILE *file;

  file = fopen(path, "r");
  fread(*array, sizeof(uint8_t), size_array, file);
  fclose(file);

  return 0;
}

/*
 * Load a size of an array from memory.
*/
int load_size_array(char *path,
                    unsigned long *size_array)
{
  FILE *file;

  file = fopen(path, "r");
  *size_array = getw(file);
  fclose(file);

  return 0;
}

#endif
