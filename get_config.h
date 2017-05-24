//
// Created by champer on 24/05/17.
//

#ifndef IPV6_MODBUS_OPCUA_SERVER_GET_CONFIG_H
#define IPV6_MODBUS_OPCUA_SERVER_GET_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>

#define KEYVALLEN 100

extern uint8_t DEVICE_NUM;
extern uint8_t TIMEOUT;
extern uint8_t DELAY;


char * l_trim(char * szOutput, const char *szInput);
char * r_trim(char *szOutput, const char *szInput);
char * a_trim(char * szOutput, const char * szInput);
int Get_Config_String(char *profile, char *AppName, char *KeyName, char *KeyVal );
int Parse_Config_File();

#endif //IPV6_MODBUS_OPCUA_SERVER_GET_CONFIG_H
