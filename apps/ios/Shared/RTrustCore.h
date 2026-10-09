#ifndef RTRUST_CORE_H
#define RTRUST_CORE_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
char *rtrust_ios_prepare(const uint8_t *bytes, size_t length);
char *rtrust_ios_export(const uint8_t *bytes, size_t length, int32_t format);
void rtrust_ios_free(char *result);
bool rtrust_ios_start(const uint8_t *bytes, size_t length);
void rtrust_ios_stop(void);
uint8_t rtrust_ios_status(void);
char *rtrust_ios_observations(void);
bool rtrust_ios_push(const uint8_t *bytes, size_t length);
size_t rtrust_ios_pop(uint8_t *bytes, size_t capacity);
#endif
