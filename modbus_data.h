/* tests/unit-test.h.  Generated from unit-test.h.in by configure.  */
/*
 * Copyright © 2008-2014 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _UNIT_TEST_H_
#define _UNIT_TEST_H_

/* nts defined by configure.ac */
#define HAVE_INTTYPES_H 1
#define HAVE_STDINT_H 1

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
# ifndef _MSC_VER
# include <stdint.h>
# else
# include "stdint.h"
# endif
#endif

modbus_t *ctx = NULL;
modbus_mapping_t *mb_mapping;

uint16_t UT_BITS_ADDRESS = 0x130;
uint16_t UT_BITS_NB = 0x25;
uint8_t UT_BITS_TAB[] = { 0xCD, 0x6B, 0xB2, 0x0E, 0x1B };

uint16_t UT_INPUT_BITS_ADDRESS = 0x1C4;
uint16_t UT_INPUT_BITS_NB = 0x16;
uint8_t UT_INPUT_BITS_TAB[] = { 0xAC, 0xDB, 0x35 };

uint16_t UT_REGISTERS_ADDRESS = 0x160;
uint16_t UT_REGISTERS_NB = 0x3;
uint16_t UT_REGISTERS_NB_MAX = 0x20;
uint16_t UT_REGISTERS_TAB[] = { 0x022B, 0x0001, 0x0064 };

/* Raise a manual exception when this address is used for the first byte */
uint16_t UT_REGISTERS_ADDRESS_SPECIAL = 0x170;
/* The response of the server will contains an invalid TID or slave */
uint16_t UT_REGISTERS_ADDRESS_INVALID_TID_OR_SLAVE = 0x171;
/* The server will wait for 1 second before replying to test timeout */
uint16_t UT_REGISTERS_ADDRESS_SLEEP_500_MS = 0x172;
/* The server will wait for 5 ms before sending each byte */
uint16_t UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS = 0x173;

/* If the following value is used, a bad response is sent.
   It's better to test with a lower value than
   UT_REGISTERS_NB_POINTS to try to raise a segfault. */
uint16_t UT_REGISTERS_NB_SPECIAL = 0x2;

const uint16_t UT_INPUT_REGISTERS_ADDRESS = 0x200;
const uint16_t UT_INPUT_REGISTERS_NB = 0xC8;
uint16_t UT_INPUT_REGISTERS_TAB[200] = {0};

float UT_REAL = 123456.00;

uint32_t UT_IREAL_ABCD = 0x0020F147;
uint32_t UT_IREAL_DCBA = 0x47F12000;
uint32_t UT_IREAL_BADC = 0x200047F1;
uint32_t UT_IREAL_CDAB = 0xF1470020;


#endif /* _UNIT_TEST_H_ */
