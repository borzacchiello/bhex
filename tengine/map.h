#ifndef __MAP_H
#define __MAP_H

/*
MIT License

Copyright (c) 2017 Tobin Bell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
 * Hash map implementation for C.
 *
 * This hash map uses strings as keys, and allows association of any arbitrary
 * value type through the use of `void *` pointers.
 * The map holds the pointer values: if a value is replaced, the element will be
 * disposed. The only exception is the "map_remove" api that transfers the
 * ownership of the object to the caller.
 */
typedef struct map map;

/**
 * Create a new, empty map.
 *
 * The returned map has dynamically allocated memory associated with it, and
 * this memory must be reclaimed after use with `map_destroy`.
 */
map* map_create();

/**
 * Set a dispose callback for values in the map
 *
 * The map holds the pointers of the value: if a value is replaced, the element
 * will be disposed
 */
void map_set_dispose(map* m, void (*c)(void*));

/**
 * Free the memory used for a map after use.
 *
 * Note that this routine does not free any memory that was allocated for the
 * values stored in the map. That memory must be freed by the client as
 * appropriate.
 */
void map_destroy(map* m);

/**
 * Get the size of a map.
 */
int map_size(const map* m);

/**
 * Determine whether a map contains a given key.
 *
 * Keys are case-sensitive.
 */
int map_contains(const map* m, const char* key);

/**
 * Set the value for a given key within a map.
 *
 * This will add a new key if it does not exist. If the key already exists, the
 * new value will replace the old one.
 */
void map_set(map* m, const char* key, void* value);

/**
 * Retrieve the value for a given key in a map.
 *
 * Crashes if the map does not contain the given key.
 */
void* map_get(const map* m, const char* key);

/**
 * Remove a key and return its value from a map. This call transfers the
 * ownership of the object to the caller
 *
 * Crashes if the map does not already contain the key.
 */
void* map_remove(map* m, const char* key);

/**
 * Iterate over a map's keys.
 *
 * Usage:
 *
 * for (char *key = map_first(m); key != NULL; key = map_next(m, key)) {
 *   ...
 * }
 *
 * Note that the `key` passed to `map_next` must have come from a previous call
 * to `map_first` or `map_next`. Passing strings from other sources produces
 * undefined behavior.
 */
const char* map_first(map* m);
const char* map_next(map* m, const char* key);

#endif
