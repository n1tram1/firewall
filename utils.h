#ifndef __UTILS_H
#define __UTILS_H

#define DEBUGFS "/sys/kernel/debug/tracing/"

#define array_len(ARR) (sizeof(ARR) / sizeof(*(ARR)))
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

#endif /* ! __UTILS_H */
