/*
 * tcp.h
 *
 *  Created on: 28 Eki 2022
 *      Author: wadwa a  wad aw
 */

#ifndef INC_TCP_H_
#define INC_TCP_H_



/******  TCP Client 3 Way Handshake Mode *****/

#define TCP_REQUEST_SEGMENT		0
#define TCP_PURE_ACKNOWLEDGEMENT	1

/**** TCP Server Response Modes *****/

#define TCP_REPLY_CLIENT	2
#define TCP_REPLY_SERVER	3
#define TCP_ACK_SERVER	4
#define TCP_FINISH_SERVER	5


/**** TCP Mode Status *****/
#define TCP_CNT_ESTB_MODE	6
#define TCP_SND_DATA_MODE	7
#define TCP_IDLE_MODE		8
#define TCP_FNSH_CMNCT_MODE 9
#define TCP_CLIENT_CLOSED_MODE	10


/* TCP Data Mode */
#define TCP_DATA_TRNS		11
#define TCP_DATA_ACK_TO_SRVR		12
#define TCP_DATA_FINISH		13

/***** STM32 Mcu TCP Mode *****/

#define TCP_MODE_IS_CLIENT	20
#define TCP_MODE_IS_SERVER	21

//static void getAndAddOneTcpSynNumber(uint8_t *sourceBuf,uint8_t * destBuf);


void tcpClientCnctEstblsh(uint8_t *packetBuf,uint16_t destPort,uint8_t responseMode );
void tcpSendData(uint8_t *packetBuf,char *dataBuf,uint32_t dataLength,uint16_t destPort,uint8_t dataMode);
void clearBuffer(uint8_t * buffer,uint32_t bufferLength);
void tcpStart(uint8_t * tcpBuf,uint16_t destPort,uint8_t tcpSrvrOrClnt);
uint8_t checkTcpResponsePacket(uint8_t * responseData);

#endif /* INC_TCP_H_ */
