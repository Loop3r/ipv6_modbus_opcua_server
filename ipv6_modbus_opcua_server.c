/*
 * Copyright © 2008-2014 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include <stdlib.h>
#include <pthread.h>
#include "socket.h"

pthread_t modbus_server_thread;	
pthread_t ipv6_client_thread;	
pthread_t opcua_server_thread;
pthread_t opcua_data_thread;


int main(int argc, char*argv[])
{

	pthread_create(&ipv6_client_thread, NULL, IPv6_Client, NULL);
	pthread_create(&modbus_server_thread, NULL, Modbus_Server, NULL);
	pthread_create(&opcua_server_thread, NULL, Opcua_Server, NULL);
	pthread_create(&opcua_data_thread, NULL, Opcua_Server_Write, NULL);
	while(1){
		;
	}

}


