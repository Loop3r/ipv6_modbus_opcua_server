//
// Created by champer on 27/04/17.
//

#ifndef MODBUS_SERVER_SOCKET_H
#define MODBUS_SERVER_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>


#include <modbus/modbus.h>
#include "open62541.h"

#define IOT_DAEMON_PORT     5222
#define MODBUS_SERVER_PORT   2225
#define IOT_DAEMON_ADDR    "127.0.0.1"
//#define MODBUS_SERVER_ADDR  "192.168.1.170"
#define OPCUA_SERVER_PORT 2226

#define CO       0x01
#define DUST     0x02
#define LIAOWEI  0x03
#define DIANBIAO 0x04
#define FLOW     0x05
#define ENCODER  0x06

#define NB_CONNECTION        5
#define IPV6_DEVICE_NUM      10
#define IPV6_RESP_LEN        100

#define REGISTER_WRITE_HEAD   ((buf[5]-1)*30)


void close_sigint(int dummy);
void *Modbus_Server(void *arg);
void *IPv6_Client(void *arg);
int Parse_IPv6_Resp(uint8_t *buf);
uint8_t Get_Data_Type(uint8_t *data);

void *Opcua_Server(void * arg);
void *Opcua_Server_Write(void * arg);
void  Change_Server_IntValue(UA_Server *server, UA_NodeId node,UA_UInt16 value);
void  Change_Server_FloatValue(UA_Server *server, UA_NodeId node,UA_Float value);
void  Opcua_Server_Parse(UA_Byte *opcuabuf);
void  Opcua_Server_AddNode(UA_Byte *nodebuf);


#endif //MODBUS_SERVER_SOCKET_H