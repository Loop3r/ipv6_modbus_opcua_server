//
// Created by champer on 27/04/17.
//

#include "socket.h"
#include "modbus_data.h"

int server_socket = -1;
int IPv6_Client_SocketFd = -1;

UA_Boolean running = true;
UA_Server *server;

typedef struct{
    UA_UInt16 addr;
    UA_UInt16 type;
    UA_UInt16 data;
}Opcua_Data;

typedef struct{
    Opcua_Data data[100];
    UA_UInt16 length;//data count
}Opcua_DataBuf;
Opcua_DataBuf opcuadatabuf;

typedef struct{
    UA_UInt16 addr;
    UA_UInt16 type;
    UA_Float data[5];
}Opcua_DB_Data;//ÓÉÓÚµç±íÊýŸÝÌØÊâ£¬ËùÒÔ×šÃÅÎªÆä¿ª±ÙÒ»žöÐÂµÄÊý×é

typedef struct{
    Opcua_DB_Data data[100];
    UA_UInt16 length;//data count
}Opcua_DB_DataBuf;
Opcua_DB_DataBuf opcuadbdatabuf;

void close_sigint(int dummy)
{
    if (server_socket != -1) {
        close(server_socket);
    }
    modbus_free(ctx);
    modbus_mapping_free(mb_mapping);

    exit(dummy);
}

void swap(uint8_t *a, uint8_t *b){
    uint8_t temp;
    temp = *a;
    *a = *b;
    *b = temp;
}

float* Hex_to_Float(uint8_t *buf){
    int a[5] = {0};
    float *tempf;
    tempf=(float*)malloc(sizeof(float) * 5);
    for(int i=0; i<5; i++){
        swap(&buf[7+i*4], &buf[9+i*4]);
        swap(&buf[8+i*4], &buf[10+i*4]);
    }
    for(int i=0; i<5; i++){
        a[i] = (buf[7+i*4]<<24) + (buf[8+i*4]<<16) + (buf[9+i*4]<<8) + buf[10+i*4];
        tempf[i] = *(float*)&a[i];
    }
    return tempf;
}

void *Modbus_Server(void *arg)
{
    uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
    int master_socket;
    int rc;
    fd_set refset;
    fd_set rdset;
    /* Maximum file descriptor number */
    int fdmax;

    ctx = modbus_new_tcp(INADDR_ANY, MODBUS_SERVER_PORT);

    mb_mapping = modbus_mapping_new_start_address(
            UT_BITS_ADDRESS, UT_BITS_NB,
            UT_INPUT_BITS_ADDRESS, UT_INPUT_BITS_NB,
            UT_REGISTERS_ADDRESS, UT_REGISTERS_NB_MAX,
            UT_INPUT_REGISTERS_ADDRESS, UT_INPUT_REGISTERS_NB
    );
    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n",
                modbus_strerror(errno));
        modbus_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* Initialize values of INPUT REGISTERS */
    for (int i=0; i < UT_INPUT_REGISTERS_NB; i++) {
        mb_mapping->tab_input_registers[i] = UT_INPUT_REGISTERS_TAB[i];
    }

    server_socket = modbus_tcp_listen(ctx, NB_CONNECTION);
    if (server_socket == -1) {
        fprintf(stderr, "Unable to listen TCP connection\n");
        modbus_free(ctx);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, close_sigint);

    /* Clear the reference set of socket */
    FD_ZERO(&refset);
    /* Add the server socket */
    FD_SET(server_socket, &refset);

    /* Keep track of the max file descriptor */
    fdmax = server_socket;

    for (;;) {
        rdset = refset;
        if (select(fdmax+1, &rdset, NULL, NULL, NULL) == -1) {
            perror("Server select() failure.");
            close_sigint(1);
        }

        /* Run through the existing connections looking for data to be
         * read */
        for (master_socket = 0; master_socket <= fdmax; master_socket++) {

            if (!FD_ISSET(master_socket, &rdset)) {
                continue;
            }

            if (master_socket == server_socket) {
                /* A client is asking a new connection */
                socklen_t addrlen;
                struct sockaddr_in clientaddr;
                int newfd;

                /* Handle new connections */
                addrlen = sizeof(clientaddr);
                memset(&clientaddr, 0, sizeof(clientaddr));
                newfd = accept(server_socket, (struct sockaddr *)&clientaddr, &addrlen);
                if (newfd == -1) {
                    perror("Server accept() error");
                } else {
                    FD_SET(newfd, &refset);

                    if (newfd > fdmax) {
                        /* Keep track of the maximum */
                        fdmax = newfd;
                    }
                    printf("New connection from %s:%d on socket %d\n",
                           inet_ntoa(clientaddr.sin_addr), clientaddr.sin_port, newfd);
                }
            } else {
                modbus_set_socket(ctx, master_socket);
                rc = modbus_receive(ctx, query);
                if (rc > 0) {
                    modbus_reply(ctx, query, rc, mb_mapping);
                } else if (rc == -1) {
                    /* This example server in ended on connection closing or
                     * any errors. */
                    printf("Connection closed on socket %d\n", master_socket);
                    close(master_socket);

                    /* Remove from reference set */
                    FD_CLR(master_socket, &refset);

                    if (master_socket == fdmax) {
                        fdmax--;
                    }
                }
            }
        }
    }
}

void *IPv6_Client(void *arg)
{
    struct sockaddr_in clientAddr;
    int ret;
    uint8_t IPv6_Req[4] = {0xA1, 0xA2, 0x01, 0x00};
    uint8_t IPv6_Resp[100];

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    fd_set rset;
    FD_ZERO(&rset);


    clientAddr.sin_family  = AF_INET;
    clientAddr.sin_port = htons(IOT_DAEMON_PORT);
    clientAddr.sin_addr.s_addr = inet_addr(IOT_DAEMON_ADDR);
    IPv6_Client_SocketFd = socket(AF_INET,SOCK_STREAM,0);
    setsockopt(IPv6_Client_SocketFd,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
    FD_SET(IPv6_Client_SocketFd, &rset);
    if(IPv6_Client_SocketFd < 0)
    {
        perror("ipv6 client socket");
        exit(EXIT_FAILURE);
    }
    if(connect(IPv6_Client_SocketFd,(struct sockaddr*)&clientAddr,sizeof(clientAddr)) < 0)
    {
        perror("IPv6 client connect");
        exit(EXIT_FAILURE);
    }

    while(1)
    {
        for (int i = 0; i < IPV6_DEVICE_NUM; i++) {
            IPv6_Req[3] = (uint8_t)i;
            if (-1 == send(IPv6_Client_SocketFd, IPv6_Req, 4, 0)) {
                perror("ipv6 client write");
            }

            int recvd = recv(IPv6_Client_SocketFd, &IPv6_Resp[0], IPV6_RESP_LEN, 0);
            if(recvd==-1&&errno==EAGAIN)
            {
                printf("timeout\n");
            }
            else
            {
                Parse_IPv6_Resp(&IPv6_Resp[0]);
            }

#if 0
            ret = select(IPv6_Client_SocketFd + 1, &rset, NULL, NULL, &timeout);
            switch (ret) {
                case 0:
                    printf("ipv6 client timeout\n");
                    break;
                case -1:
                    perror("ipv6 client select");
                    break;
                default:
                    printf("aaaaaaaaaaaaaaaa");
                    if (FD_ISSET(IPv6_Client_SocketFd, &rset)) {
                        recv(IPv6_Client_SocketFd, IPv6_Resp, IPV6_RESP_LEN, 0);
                        Parse_IPv6_Resp(IPv6_Resp);
                    }
            }
#endif
            //sleep(1);
        }
    }
}

int Parse_IPv6_Resp(uint8_t *buf)
{
    float *tempf;

    if(buf[0] == 0xA1 && buf[1] == 0xA2 && buf[2] == 0x00 && buf[3] == 0xAA)
    {

        if(Get_Data_Type(buf) == CO)
        {
            printf("get node%d CO data:%d\n", buf[4], (buf[7]<<8)+buf[8]);
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD] = (uint16_t)buf[4];                     //addr
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 1] = (uint16_t)(buf[5]);               //type
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 2] = (uint16_t)((buf[7]<<8)+buf[8]);   //data
            Opcua_Server_Parse(buf);
        }
        if(Get_Data_Type(buf) == DUST)
        {
            printf("get node%d DUST data:%d\n", buf[4], (buf[7]<<8)+buf[8]);
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD] = (uint16_t)buf[4];                     //addr
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 1] = (uint16_t)(buf[5]);               //type
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 2] = (uint16_t)((buf[7]<<8)+buf[8]);   //data
            Opcua_Server_Parse(buf);
        }
        if(Get_Data_Type(buf) == LIAOWEI)
        {
            printf("get node%d LIAOWEI data:%d\n", buf[4], (buf[7]<<8)+buf[8]);
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD] = (uint16_t)buf[4];                     //addr
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 1] = (uint16_t)(buf[5]);               //type
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 2] = (uint16_t)((buf[7]<<8)+buf[8]);   //data
            Opcua_Server_Parse(buf);
        }
        if(Get_Data_Type(buf) == DIANBIAO)
        {
            tempf = Hex_to_Float(&buf[0]);
            printf("get node%d DIANBIAO data:%.6f, %.6f, %.6f, %.6f, %.6f\n", buf[4],
                   *tempf, *(tempf+1),  *(tempf+2),  *(tempf+3),  *(tempf+4));
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD] = (uint16_t)buf[4];                     //addr
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 1] = (uint16_t)(buf[5]);               //type
            for(int i=0; i<5; i++){
                UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 2 + i] = (uint16_t)((buf[7+i*2]<<8)+buf[8+i*2]);   //data
            }
            Opcua_Server_Parse(buf);
        }
        if(Get_Data_Type(buf) == FLOW)
        {
            printf("get node%d FLOW data:%d\n", buf[4], (buf[7]<<8)+buf[8]);
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD] = (uint16_t)buf[4];                     //addr
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 1] = (uint16_t)(buf[5]);               //type
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 2] = (uint16_t)((buf[7]<<8)+buf[8]);   //data
            Opcua_Server_Parse(buf);
        }
        if(Get_Data_Type(buf) == ENCODER)
        {
            printf("get node%02x ENCODER direction:%d,sign:%d,data:%d\n", buf[4], buf[7], buf[8], (buf[9]<<8)+buf[10]);
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD] = (uint16_t)buf[4];                     //addr
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 1] = (uint16_t)(buf[5]);               //type
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 2] = (uint16_t)(buf[7]);
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 3] = (uint16_t)(buf[8]);
            UT_INPUT_REGISTERS_TAB[REGISTER_WRITE_HEAD + 4] = (uint16_t)((buf[9]<<8)+buf[10]);
            Opcua_Server_Parse(buf);
        }
    }
    for (int i=0; i < UT_INPUT_REGISTERS_NB; i++) {
        mb_mapping->tab_input_registers[i] = UT_INPUT_REGISTERS_TAB[i];
    }

    return 0;
}

uint8_t Get_Data_Type(uint8_t *data)
{
    return data[5];
}




void  Opcua_Server_Parse(UA_Byte *opcuabuf)
{
    if((opcuadbdatabuf.length==0)&&(opcuabuf[5]==DIANBIAO)){
        opcuadbdatabuf.data[0].addr = opcuabuf[4];
        opcuadbdatabuf.data[0].type=opcuabuf[5];
        opcuadbdatabuf.data[0].data[0]=(float)( (opcuabuf[7]<<24) + (opcuabuf[8]<<16) + (opcuabuf[9]<<8) + opcuabuf[10] );
        opcuadbdatabuf.data[0].data[1]=(float)( (opcuabuf[11]<<24) + (opcuabuf[12]<<16) + (opcuabuf[13]<<8) + opcuabuf[14] );
        opcuadbdatabuf.data[0].data[2]=(float)( (opcuabuf[15]<<24) + (opcuabuf[16]<<16) + (opcuabuf[17]<<8) + opcuabuf[18] );
        opcuadbdatabuf.data[0].data[3]=(float)( (opcuabuf[19]<<24) + (opcuabuf[20]<<16) + (opcuabuf[21]<<8) + opcuabuf[22] );
        opcuadbdatabuf.data[0].data[4]=(float)( (opcuabuf[23]<<24) + (opcuabuf[24]<<16) + (opcuabuf[25]<<8) + opcuabuf[26] );
        opcuadbdatabuf.length = opcuadbdatabuf.length + 1;
        Opcua_Server_AddNode(opcuabuf);
    }
    else if(opcuabuf[5]==DIANBIAO){
        for (int i = 0; i < opcuadbdatabuf.length; i++) {
            if ((opcuadbdatabuf.data[i].addr == opcuabuf[4]) && (opcuadbdatabuf.data[i].type == opcuabuf[5])) {
                opcuadbdatabuf.data[0].data[0] = (float) ((opcuabuf[7] << 24) + (opcuabuf[8] << 16) +
                                                          (opcuabuf[9] << 8) + opcuabuf[10]);
                opcuadbdatabuf.data[0].data[1] = (float) ((opcuabuf[11] << 24) + (opcuabuf[12] << 16) +
                                                          (opcuabuf[13] << 8) + opcuabuf[14]);
                opcuadbdatabuf.data[0].data[2] = (float) ((opcuabuf[15] << 24) + (opcuabuf[16] << 16) +
                                                          (opcuabuf[17] << 8) + opcuabuf[18]);
                opcuadbdatabuf.data[0].data[3] = (float) ((opcuabuf[19] << 24) + (opcuabuf[20] << 16) +
                                                          (opcuabuf[21] << 8) + opcuabuf[22]);
                opcuadbdatabuf.data[0].data[4] = (float) ((opcuabuf[23] << 24) + (opcuabuf[24] << 16) +
                                                          (opcuabuf[25] << 8) + opcuabuf[26]);
            } else if (i == opcuadbdatabuf.length - 1) {
                opcuadbdatabuf.data[opcuadbdatabuf.length].addr = opcuabuf[4];
                opcuadbdatabuf.data[opcuadbdatabuf.length].type = opcuabuf[5];
                opcuadbdatabuf.data[opcuadbdatabuf.length].data[0] = (float) ((opcuabuf[7] << 24) +
                                                                              (opcuabuf[8] << 16) + (opcuabuf[9] << 8) +
                                                                              opcuabuf[10]);
                opcuadbdatabuf.data[opcuadbdatabuf.length].data[1] = (float) ((opcuabuf[11] << 24) +
                                                                              (opcuabuf[12] << 16) +
                                                                              (opcuabuf[13] << 8) + opcuabuf[14]);
                opcuadbdatabuf.data[opcuadbdatabuf.length].data[2] = (float) ((opcuabuf[15] << 24) +
                                                                              (opcuabuf[16] << 16) +
                                                                              (opcuabuf[17] << 8) + opcuabuf[18]);
                opcuadbdatabuf.data[opcuadbdatabuf.length].data[3] = (float) ((opcuabuf[19] << 24) +
                                                                              (opcuabuf[20] << 16) +
                                                                              (opcuabuf[21] << 8) + opcuabuf[22]);
                opcuadbdatabuf.data[opcuadbdatabuf.length].data[4] = (float) ((opcuabuf[23] << 24) +
                                                                              (opcuabuf[24] << 16) +
                                                                              (opcuabuf[25] << 8) + opcuabuf[26]);
                opcuadbdatabuf.length = opcuadbdatabuf.length + 1;
                Opcua_Server_AddNode(opcuabuf);
            }else{}
        }
    }else{}

    if((opcuadatabuf.length == 0)&&(opcuabuf[5]!=DIANBIAO)){
        opcuadatabuf.data[0].addr = opcuabuf[4];
        opcuadatabuf.data[0].type = opcuabuf[5];
        opcuadatabuf.data[0].data = (opcuabuf[7]<<8) + opcuabuf[8];
        opcuadatabuf.length = opcuadatabuf.length + 1;
        Opcua_Server_AddNode(opcuabuf);
    }
    else{
        for(int i=0;i<opcuadatabuf.length;i++){
            if((opcuadatabuf.data[i].addr == opcuabuf[4])&&(opcuadatabuf.data[i].type== opcuabuf[5])){
                printf("get the node of addr is %d and the type is %d\n",opcuabuf[4],opcuabuf[5]);
                opcuadatabuf.data[i].data = (opcuabuf[7]<<8) + opcuabuf[8];
            }
            else if(i==opcuadatabuf.length -1 ){
                opcuadatabuf.data[opcuadatabuf.length].addr = opcuabuf[4];
                opcuadatabuf.data[opcuadatabuf.length].type = opcuabuf[5];
                opcuadatabuf.data[opcuadatabuf.length].data = (opcuabuf[7]<<8) + opcuabuf[8];
                opcuadatabuf.length = opcuadatabuf.length + 1;
                Opcua_Server_AddNode(opcuabuf);
            }else{}
        }

    }
}

void  Opcua_Server_AddNode(UA_Byte *nodebuf)
{
    char nodeDisplayName[10] = {0};
    char *p=NULL;
    if(nodebuf[5]==CO){
        strcat(nodeDisplayName,"CO_");
        p = strstr(nodeDisplayName,"CO_");
        if(p != NULL) {
            sprintf(p,"CO_%d",nodebuf[4]);
        }
        UA_UInt16 coInteger = 123;
        UA_VariableAttributes coAttr;
        UA_VariableAttributes_init(&coAttr);
        UA_Variant_setScalar(&coAttr.value, &coInteger, &UA_TYPES[UA_TYPES_UINT16]);
        coAttr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        UA_NodeId coNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        UA_NodeId coparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        UA_NodeId coparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        UA_NodeId covariableType = UA_NODEID_NULL; /* no variable type defined */
        UA_QualifiedName cobrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, coNodeId, coparentNodeId, coparentReferenceNodeId,
                                  cobrowseName, covariableType, coAttr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));
    }
    else if(nodebuf[5]==DUST){
        strcat(nodeDisplayName,"DUST_");
        p = strstr(nodeDisplayName,"DUST_");
        if(p != NULL) {
            sprintf(p,"DUST_%d",nodebuf[4]);
        }
        UA_UInt16 dtInteger = 123;
        UA_VariableAttributes dtattr;
        UA_VariableAttributes_init(&dtattr);
        UA_Variant_setScalar(&dtattr.value, &dtInteger, &UA_TYPES[UA_TYPES_UINT16]);
        dtattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        UA_NodeId dtNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        UA_NodeId dtparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        UA_NodeId dtparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        UA_NodeId dtvariableType = UA_NODEID_NULL; /* no variable type defined */
        UA_QualifiedName dtbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, dtNodeId, dtparentNodeId, dtparentReferenceNodeId,
                                  dtbrowseName, dtvariableType, dtattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

    }
    else if(nodebuf[5]==LIAOWEI){
        strcat(nodeDisplayName,"LIAOWEI_");
        p = strstr(nodeDisplayName,"LIAOWEI_");
        if(p != NULL) {
            sprintf(p,"LIAOWEI_%d",nodebuf[4]);
        }
        UA_UInt16 lwInteger = 123;
        UA_VariableAttributes lwattr;
        UA_VariableAttributes_init(&lwattr);
        UA_Variant_setScalar(&lwattr.value, &lwInteger, &UA_TYPES[UA_TYPES_UINT16]);
        lwattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        UA_NodeId lwNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        UA_NodeId lwparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        UA_NodeId lwparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        UA_NodeId lwvariableType = UA_NODEID_NULL; /* no variable type defined */
        UA_QualifiedName lwbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, lwNodeId, lwparentNodeId, lwparentReferenceNodeId,
                                  lwbrowseName, lwvariableType, lwattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

    }
    else if(nodebuf[5]==DIANBIAO){
        strcat(nodeDisplayName,"DIANBIAO_");
        p = strstr(nodeDisplayName,"DIANBIAO_");
        if(p != NULL) {
            sprintf(p,"DIANBIAO_%d",nodebuf[4]);
        }
        strcat(nodeDisplayName,"_APOWER");
        UA_Float dbInteger = 0;
        UA_VariableAttributes dbattr;
        UA_VariableAttributes_init(&dbattr);
        UA_Variant_setScalar(&dbattr.value, &dbInteger, &UA_TYPES[UA_TYPES_FLOAT]);
        dbattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        //UA_NodeId dbNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        UA_NodeId dbNodeId= UA_NODEID_STRING(1,nodeDisplayName);
        UA_NodeId dbparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        UA_NodeId dbparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        UA_NodeId dbvariableType = UA_NODEID_NULL; /* no variable type defined */
        UA_QualifiedName dbbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, dbNodeId, dbparentNodeId, dbparentReferenceNodeId,
                                  dbbrowseName, dbvariableType, dbattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

        strcat(nodeDisplayName,"DIANBIAO_");
        p = strstr(nodeDisplayName,"DIANBIAO_");
        if(p != NULL) {
            sprintf(p,"DIANBIAO_%d",nodebuf[4]);
        }
        strcat(nodeDisplayName,"_RPOWER");
        dbattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        //UA_NodeId dbNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        dbNodeId= UA_NODEID_STRING(1,nodeDisplayName);
        dbparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        dbparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        dbvariableType = UA_NODEID_NULL; /* no variable type defined */
        dbbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, dbNodeId, dbparentNodeId, dbparentReferenceNodeId,
                                  dbbrowseName, dbvariableType, dbattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

        strcat(nodeDisplayName,"DIANBIAO_");
        p = strstr(nodeDisplayName,"DIANBIAO_");
        if(p != NULL) {
            sprintf(p,"DIANBIAO_%d",nodebuf[4]);
        }
        strcat(nodeDisplayName,"_AU");
        dbattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        //UA_NodeId dbNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        dbNodeId= UA_NODEID_STRING(1,nodeDisplayName);
        dbparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        dbparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        dbvariableType = UA_NODEID_NULL; /* no variable type defined */
        dbbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, dbNodeId, dbparentNodeId, dbparentReferenceNodeId,
                                  dbbrowseName, dbvariableType, dbattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

        strcat(nodeDisplayName,"DIANBIAO_");
        p = strstr(nodeDisplayName,"DIANBIAO_");
        if(p != NULL) {
            sprintf(p,"DIANBIAO_%d",nodebuf[4]);
        }
        strcat(nodeDisplayName,"_BU");
        dbattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        //UA_NodeId dbNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        dbNodeId= UA_NODEID_STRING(1,nodeDisplayName);
        dbparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        dbparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        dbvariableType = UA_NODEID_NULL; /* no variable type defined */
        dbbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, dbNodeId, dbparentNodeId, dbparentReferenceNodeId,
                                  dbbrowseName, dbvariableType, dbattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

        strcat(nodeDisplayName,"DIANBIAO_");
        p = strstr(nodeDisplayName,"DIANBIAO_");
        if(p != NULL) {
            sprintf(p,"DIANBIAO_%d",nodebuf[4]);
        }
        strcat(nodeDisplayName,"_CU");
        dbattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        //UA_NodeId dbNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        dbNodeId= UA_NODEID_STRING(1,nodeDisplayName);
        dbparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        dbparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        dbvariableType = UA_NODEID_NULL; /* no variable type defined */
        dbbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, dbNodeId, dbparentNodeId, dbparentReferenceNodeId,
                                  dbbrowseName, dbvariableType, dbattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

    }
    else if(nodebuf[5]==FLOW){
        strcat(nodeDisplayName,"FLOW_");
        p = strstr(nodeDisplayName,"FLOW_");
        if(p != NULL) {
            sprintf(p,"FLOW_%d",nodebuf[4]);
        }
        UA_UInt16 fwInteger = 123;
        UA_VariableAttributes fwattr;
        UA_VariableAttributes_init(&fwattr);
        UA_Variant_setScalar(&fwattr.value, &fwInteger, &UA_TYPES[UA_TYPES_UINT16]);
        fwattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        UA_NodeId fwNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        UA_NodeId fwparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        UA_NodeId fwparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        UA_NodeId fwvariableType = UA_NODEID_NULL; /* no variable type defined */
        UA_QualifiedName fwbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, fwNodeId, fwparentNodeId, fwparentReferenceNodeId,
                                  fwbrowseName, fwvariableType, fwattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));

    }
    else if(nodebuf[5]==ENCODER){
        strcat(nodeDisplayName,"ENCODER_");
        p = strstr(nodeDisplayName,"ENCODER_");
        if(p != NULL) {
            sprintf(p,"ENCODER_%d",nodebuf[4]);
        }
        UA_UInt16 enInteger = 123;
        UA_VariableAttributes enattr;
        UA_VariableAttributes_init(&enattr);
        UA_Variant_setScalar(&enattr.value, &enInteger, &UA_TYPES[UA_TYPES_UINT16]);
        enattr.displayName = UA_LOCALIZEDTEXT("en_US", nodeDisplayName);

        /* 2) define where the variable shall be added with which browsename */
        UA_NodeId enNodeId = UA_NODEID_NUMERIC(1, nodebuf[4]);
        UA_NodeId enparentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        UA_NodeId enparentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
        UA_NodeId envariableType = UA_NODEID_NULL; /* no variable type defined */
        UA_QualifiedName enbrowseName = UA_QUALIFIEDNAME(1, nodeDisplayName);

        /* 3) add the variable */
        UA_Server_addVariableNode(server, enNodeId,enparentNodeId, enparentReferenceNodeId,
                                  enbrowseName, envariableType,enattr, NULL, NULL);
        memset(nodeDisplayName, '\0', strlen(nodeDisplayName));
    }else {

    }

}


UA_Variant writevalue;
void  Change_Server_IntValue(UA_Server *server, UA_NodeId node,UA_UInt16 value)
{
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    writevalue.data=&(value);
    //printf("%f\n",value);
    writevalue.type = &UA_TYPES[UA_TYPES_UINT16];
    writevalue.storageType = UA_VARIANT_DATA;
    retval=UA_Server_writeValue(server,node,writevalue);
    printf("write %s retval %x\n",node.identifier.string.data,retval);
}
void  Change_Server_FloatValue(UA_Server *server, UA_NodeId node,UA_Float value)
{
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    writevalue.data=&(value);
    //printf("%f\n",value);
    writevalue.type = &UA_TYPES[UA_TYPES_FLOAT];
    writevalue.storageType = UA_VARIANT_DATA;
    retval=UA_Server_writeValue(server,node,writevalue);
    printf("write %s retval %x\n",node.identifier.string.data,retval);
}

void *Opcua_Server(void * arg)
{
    /* init the server */
    UA_ServerConfig config = UA_ServerConfig_standard;
    UA_ServerNetworkLayer nl = UA_ServerNetworkLayerTCP(UA_ConnectionConfig_standard, OPCUA_SERVER_PORT);
    config.networkLayers = &nl;
    config.networkLayersSize = 1;
    server = UA_Server_new(config);

    /* run the server loop */
    UA_StatusCode retval = UA_Server_run(server, &running);
    UA_Server_delete(server);
    nl.deleteMembers(&nl);

    return NULL;
}

void *Opcua_Server_Write(void * arg)
{
    char nodeId[10] = {0};
    char *p=NULL;
    sleep(5);//wait the opcua server start
    while(1) {
        for (int i = 0; i < opcuadbdatabuf.length; i++){
            strcat(nodeId,"DIANBIAO_");
            p = strstr(nodeId,"DIANBIAO_");
            if(p != NULL) {
                sprintf(p,"DIANBIAO_%d",opcuadbdatabuf.data[i].addr);
            }
            strcat(nodeId,"_APOWER");
            Change_Server_FloatValue(server, UA_NODEID_STRING(1, nodeId), opcuadbdatabuf.data[i].data[0]);
            memset(nodeId, '\0', strlen(nodeId));

            strcat(nodeId,"DIANBIAO_");
            p = strstr(nodeId,"DIANBIAO_");
            if(p != NULL) {
                sprintf(p,"DIANBIAO_%d",opcuadbdatabuf.data[i].addr);
            }
            strcat(nodeId,"_RPOWER");
            Change_Server_FloatValue(server, UA_NODEID_STRING(1, nodeId), opcuadbdatabuf.data[i].data[1]);
            memset(nodeId, '\0', strlen(nodeId));

            strcat(nodeId,"DIANBIAO_");
            p = strstr(nodeId,"DIANBIAO_");
            if(p != NULL) {
                sprintf(p,"DIANBIAO_%d",opcuadbdatabuf.data[i].addr);
            }
            strcat(nodeId,"_AU");
            Change_Server_FloatValue(server, UA_NODEID_STRING(1, nodeId), opcuadbdatabuf.data[i].data[2]);
            memset(nodeId, '\0', strlen(nodeId));

            strcat(nodeId,"DIANBIAO_");
            p = strstr(nodeId,"DIANBIAO_");
            if(p != NULL) {
                sprintf(p,"DIANBIAO_%d",opcuadbdatabuf.data[i].addr);
            }
            strcat(nodeId,"_BU");
            Change_Server_FloatValue(server, UA_NODEID_STRING(1, nodeId), opcuadbdatabuf.data[i].data[3]);
            memset(nodeId, '\0', strlen(nodeId));

            strcat(nodeId,"DIANBIAO_");
            p = strstr(nodeId,"DIANBIAO_");
            if(p != NULL) {
                sprintf(p,"DIANBIAO_%d",opcuadbdatabuf.data[i].addr);
            }
            strcat(nodeId,"_CU");
            Change_Server_FloatValue(server, UA_NODEID_STRING(1, nodeId), opcuadbdatabuf.data[i].data[4]);
            memset(nodeId, '\0', strlen(nodeId));
        }

        for (int i = 0; i < opcuadatabuf.length; i++)
            Change_Server_IntValue(server, UA_NODEID_NUMERIC(1, opcuadatabuf.data[i].addr), opcuadatabuf.data[i].data);
        sleep(2);
    }
}


