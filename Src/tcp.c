
#include "ip_config.h"
#include <stdlib.h>
#include "enc28j60.h"
#include "tcp.h"
#include "net.h"
#include "ip_arp_udp_tcp.h"


extern uint8_t mymacaddr[6];
extern uint8_t myipaddr[4];

 extern uint8_t destIpaddr[4];
 extern uint8_t destMACaddr[6];

 uint8_t tcpFnsCounter ;

 static uint8_t responseSequenceNum[4];
 static uint8_t senderSeqNum[4];

 //These 2 array is used for observing responded and sent datagrams
 // In debug mode
 static uint8_t rspObsrArray[100];
 static uint8_t senderObsrArray[100];

 uint8_t  tcpIdleStateMode;
 uint16_t  destTcpPort;
 uint16_t  clientSrcPort;
 uint16_t tcpMode =TCP_CNT_ESTB_MODE;


 char buf[] ={"Hello World\n"};
 char * replyData;

 static uint16_t currentWinSize = 0xFAF0;
 //static uint32_t senderDataLength;


 uint32_t responseDataLength ;


  void clearBuffer(uint8_t * buffer,uint32_t bufferLength)
 {
 	 //clear net_buf array
 		  for(uint16_t m =0; m <bufferLength ; m++)
 		 {
 			  buffer[m] = 0;
 		  }

 }


 /*
  * brief: This function keep sequence or Acknowledge numbers
  *
  */
 static void getSeqOrAckNum(uint8_t *sourceBuf,uint8_t * destBuf)
 {
 	for(uint8_t k=0; k<4 ; k++)
 	{
 		destBuf[k] =sourceBuf[k] ;
 	}


 }

 /*
  * Brief : This function set Seq or Ack number according to data length
  */
 static void setSeqOrAckNum(uint8_t * sourceBuf,uint32_t dataLength)
 {
	 uint32_t AddDataLength = (uint32_t) (sourceBuf[0] << 24) |  (sourceBuf[1] << 16) |
							  (sourceBuf[2] << 8) | (sourceBuf[3]);

	 AddDataLength += dataLength ;

	 sourceBuf[0] = (uint8_t)(AddDataLength  >> 24);
	 sourceBuf[1] = (uint8_t)(AddDataLength  >> 16);
	 sourceBuf[2] = (uint8_t)(AddDataLength  >> 8);
	 sourceBuf[3] = (uint8_t)(AddDataLength);
 }

 static void setWindowsSize(uint8_t * sourceBuf,uint32_t dataLength)
  {

 	currentWinSize -=dataLength;

 	 sourceBuf[0] = (uint8_t)(currentWinSize  >> 8);
 	 sourceBuf[1] = (uint8_t)(currentWinSize);

  }
/*
 * brief : This function fills necessary constant values
 * for tcp datagram
 */
 static void makeConstFillingHeaderForTcp(uint8_t *packetBuf,uint16_t ipHeaderLength,uint16_t tcpHeaderLength,uint16_t destPort)
 {

		 uint8_t i=0;
		 //copy the destination mac from the source and fill my mac into src
			while(i<6)
			{
				packetBuf[ETH_DST_MAC +i]= destMACaddr[i];//buf[ETH_SRC_MAC +i];
				packetBuf[ETH_SRC_MAC +i]=mymacaddr[i];
				i++;
			}
			packetBuf[ETH_TYPE_H_P] = 0x08 ; //IPv4 protocol type

			i=0;



			 while(i<4){
				 packetBuf[IP_DST_P+i]=destIpaddr[i];
				 packetBuf[IP_SRC_P+i]=myipaddr[i];
					 i++;

			   	 }


				  packetBuf[TCP_DST_PORT_H_P]= destPort>>8;
				  packetBuf[TCP_DST_PORT_L_P]= destPort & 0xff;
				  packetBuf[TCP_SRC_PORT_H_P]= 0x00;
				  packetBuf[TCP_SRC_PORT_L_P]= 80;



		        	 // total length field in the IP header must be set:
					 // 20 bytes IP + 20 bytes (20tcp) + datagram length
					 uint16_t ipTotalLength = ipHeaderLength;
					 packetBuf[IP_TOTLEN_H_P]= (uint8_t)ipTotalLength >> 8;
					 packetBuf[IP_TOTLEN_L_P]=ipTotalLength & 0xFF;

					 fill_ip_hdr_checksum(packetBuf);


					 //Tcp header length implementation
					 packetBuf[TCP_HEADER_LEN_P] = tcpHeaderLength ;


 }


/*
 * brief : This function establishes a connection with server
 * via 3 way Handshake algorithm.That means, this stm32 behaviors as " client "
 * param : < packetBuf >  is an array which is filled inside with ethernet data format
 * param : < destPort > is a value which determines TCP port of the destination target
 * param : < responseMode > determines 3 way handshake algorithm state
 */
void tcpClientCnctEstblsh(uint8_t *packetBuf,uint16_t destPort,uint8_t responseMode )
{

	clearBuffer(packetBuf, 1400);
	 uint16_t ck =0;
	//Request Segment send to server
	 if(responseMode == TCP_REQUEST_SEGMENT || responseMode == TCP_REPLY_CLIENT)
	 {
		 makeConstFillingHeaderForTcp(packetBuf, IP_HEADER_LEN + TCP_HEADER_LEN_PLAIN + 4, 0x60,destPort);

		 // put an inital seq number
		 packetBuf[TCP_SEQ_H_P+0]= 0;
		 packetBuf[TCP_SEQ_H_P+1]= 0;
		// we step only the second byte, this allows us to send packts
		// with 255 bytes, 512  or 765 (step by 3) without generating
		// overlapping numbers.
		 packetBuf[TCP_SEQ_H_P+2]= 20;
		 packetBuf[TCP_SEQ_H_P+3]= 0;

		 //getSeqOrAckNum(&packetBuf[TCP_SEQ_H_P], senderSeqNum);
		 senderSeqNum[2] = 20;


		 //sequence number flag is set for initial sequence number.
		 if(responseMode == TCP_REPLY_CLIENT)
		 {
			 packetBuf[TCP_FLAGS_P] = TCP_FLAGS_SYNACK_V ;
			 // get the ack number from client and add 1 to last digit

				 packetBuf[TCP_ACK_P+0]= responseSequenceNum[0];
				 packetBuf[TCP_ACK_P+1]= responseSequenceNum[1];
				 packetBuf[TCP_ACK_P+2]= responseSequenceNum[2];
				 packetBuf[TCP_ACK_P+3]= responseSequenceNum[3] +1;

				 getSeqOrAckNum(&packetBuf[TCP_ACK_P], responseSequenceNum);

				 setSeqOrAckNum(senderSeqNum, 1);

		 }
		 else
		 {
				packetBuf[TCP_FLAGS_P] = 0x2 ;
		 }


		//add to Receiving Windows Size into Windows Size Field

		packetBuf[TCP_WINDOWSIZE_H_P] = 0xFA;
		packetBuf[TCP_WINDOWSIZE_L_P] = 0xF0;

		// add an mss(maximum segmet size )to options field with MSS to 1460:
		//1460 dec = 0x5B4 hex
		packetBuf[TCP_OPTIONS_P]=2;
		packetBuf[TCP_OPTIONS_P +1]=4;
		packetBuf[TCP_OPTIONS_P+2]=0x05;
		packetBuf[TCP_OPTIONS_P+3]=0xB4;


		// calculate the checksum, len=8 (start from ip.src) + TCP_HEADER_LEN_PLAIN + 4 (one option: mss)
		ck=checksum(&packetBuf[IP_SRC_P], 8+TCP_HEADER_LEN_PLAIN+4 ,2);
		packetBuf[TCP_CHECKSUM_H_P]=ck>>8;
		packetBuf[TCP_CHECKSUM_L_P]=ck& 0xff;

		//This loop for observing sender Data in debug mode
		//you can delete it
		for(uint8_t k=0; k<100 ; k++)
		{
			senderObsrArray[k] =packetBuf[k] ;
		}

		// add 4 for option mss:
		enc28j60PacketSend(IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+4+ETH_HEADER_LEN ,packetBuf);
	 }
	 else if(responseMode == TCP_PURE_ACKNOWLEDGEMENT)
	 {
		 makeConstFillingHeaderForTcp(packetBuf, IP_HEADER_LEN + TCP_HEADER_LEN_PLAIN, 0x50,destPort);

		 //acknowledge number flag is set for pure acknowledgement.
			packetBuf[TCP_FLAGS_P] = 0x10 ;


			// get the ack number from client and add 1 to last digit

			 packetBuf[TCP_ACK_P+0]= responseSequenceNum[0];
			 packetBuf[TCP_ACK_P+1]= responseSequenceNum[1];
			 packetBuf[TCP_ACK_P+2]= responseSequenceNum[2];
			 packetBuf[TCP_ACK_P+3]= responseSequenceNum[3] +1;

			 //add the seq number 1
			 packetBuf[TCP_SEQ_H_P+0]= senderSeqNum[0];
			 packetBuf[TCP_SEQ_H_P+1]= senderSeqNum[1];
			 packetBuf[TCP_SEQ_H_P+2]= senderSeqNum[2];
			 packetBuf[TCP_SEQ_H_P+3]= senderSeqNum[3] +1;

			 //Store Sequence and Acknowledgement numbers into arrays
			 getSeqOrAckNum(&packetBuf[TCP_ACK_P], responseSequenceNum);
			 getSeqOrAckNum(&packetBuf[TCP_SEQ_H_P], senderSeqNum);


			 //add to Receiving Windows Size into Windows Size Field

		     packetBuf[TCP_WINDOWSIZE_H_P] = 0xFA;
			 packetBuf[TCP_WINDOWSIZE_L_P] = 0xF0;

			// calculate the checksum, len=8 (start from ip.src) + TCP_HEADER_LEN_PLAIN
			ck=checksum(&packetBuf[IP_SRC_P], 8+TCP_HEADER_LEN_PLAIN ,2);
			packetBuf[TCP_CHECKSUM_H_P]=ck>>8;
			packetBuf[TCP_CHECKSUM_L_P]=ck& 0xff;

			//This loop for observing sender Data in debug mode
			//you can delete it
			for(uint8_t k=0; k<100 ; k++)
			{
				senderObsrArray[k] =packetBuf[k] ;
			}

			enc28j60PacketSend(IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+ETH_HEADER_LEN ,packetBuf);

	 }

}

void tcpSendData(uint8_t *packetBuf,char *dataBuf,uint32_t dataLength,uint16_t destPort,uint8_t dataMode)
{

    clearBuffer(packetBuf, 1400);
    uint16_t ck =0;

    makeConstFillingHeaderForTcp(packetBuf, IP_HEADER_LEN + TCP_HEADER_LEN_PLAIN + dataLength, 0x50,destPort);

    setWindowsSize(&packetBuf[TCP_WINDOWSIZE_H_P], 0);

      if(dataMode == TCP_DATA_TRNS)
	 {
		 //sequence number flag is set for initial sequence number.
		 packetBuf[TCP_FLAGS_P] = TCP_FLAGS_PSHACK_V ;

	 }
	 else if(dataMode == TCP_DATA_ACK_TO_SRVR)
	 {
		 packetBuf[TCP_FLAGS_P] = TCP_FLAGS_ACK_V ;
		 setWindowsSize(&packetBuf[TCP_WINDOWSIZE_H_P], responseDataLength);

	 }
	 else if(dataMode == TCP_DATA_FINISH)
	 {
		 packetBuf[TCP_FLAGS_P] = TCP_FLAGS_FIN_V|TCP_FLAGS_ACK_V ;
		 //setSeqOrAckNum(senderSeqNum, -1);
		 //We just need send FINISH Flag without data
		 //you should Finish communication After Datasets is sent
		 dataLength = 0;
	 }

      getSeqOrAckNum(senderSeqNum, &packetBuf[TCP_SEQ_P]);
      getSeqOrAckNum(responseSequenceNum, &packetBuf[TCP_ACK_P]);

    //send data to tcp server
	 {
		 for(uint32_t j=0; j < dataLength ; j++)
		 {
			 packetBuf[TCP_DATA_P + j] = dataBuf[j];
		 }
	 }

	 // calculate the checksum, len=8 (start from ip.src) + TCP_HEADER_LEN_PLAIN + datalength
		ck=checksum(&packetBuf[IP_SRC_P], 8+TCP_HEADER_LEN_PLAIN + dataLength ,2);
		packetBuf[TCP_CHECKSUM_H_P]=ck>>8;
		packetBuf[TCP_CHECKSUM_L_P]=ck& 0xff;

		enc28j60PacketSend(IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+dataLength+ETH_HEADER_LEN ,packetBuf);

		//This loop for observing sender Data in debug mode
		//you can delete it
		for(uint8_t k=0; k<100 ; k++)
		{
			senderObsrArray[k] =packetBuf[k] ;
		}


}


uint8_t checkTcpResponsePacket(uint8_t * responseData)
{
	uint16_t lengthOfDataSegment =  0;
	uint8_t checkTcpFlag =0;

	clearBuffer(responseData, 1400);

		enc28j60PacketReceive(1400, responseData);
	    lengthOfDataSegment =  (uint16_t)(responseData[IP_TOTLEN_H_P] << 8)|responseData[IP_TOTLEN_L_P];
	    //TCP Protocol number is 0x06
		if(lengthOfDataSegment != 0 && responseData[IP_PROTO_P] == 0x06)
		{

			// -12 value is eliminated rest of IP header values from "IP source Address " index
			uint16_t ckValueControl = checksum(&responseData[IP_SRC_IP_P], lengthOfDataSegment -12, 2);

			//That means receiver(server) assumes that no error occurred in the data receiving during the transmission.
			if(ckValueControl == 0)
			{

				checkTcpFlag = 0x3F & responseData[TCP_FLAGS_P];

				//Check value of Flag equals to SYN =1 ACK =1
				//That means "Reply Segment " mode in 3 Ways Handshake
				if(checkTcpFlag == TCP_FLAGS_SYNACK_V )
				{
					//keep response Sequence number from Server response
					getSeqOrAckNum(&responseData[TCP_SEQ_P ], responseSequenceNum);

					//For observation response of the server in debug mode
						for(uint8_t k=0; k<100 ; k++)
					 	{
					 		rspObsrArray[k] =responseData[k] ;
					 	}

					return TCP_REPLY_SERVER;
				}
				//This MCU is considered as SERVER
				else if(checkTcpFlag == TCP_FLAGS_SYN_V)
				{

					clientSrcPort = (uint16_t)(responseData[TCP_SRC_PORT_H_P] << 8 |  responseData[TCP_SRC_PORT_L_P]) ;

					getSeqOrAckNum(&responseData[TCP_SEQ_P ], responseSequenceNum);

					return TCP_REPLY_CLIENT;
				}
				//That means Data Transfer Acknowledgment bit is send to
				// Client in order to sure that data is delivered to the server correctly
				else if(checkTcpFlag == TCP_FLAGS_ACK_V || checkTcpFlag == TCP_FLAGS_PSHACK_V)
				{
					//If TCP header size is equeal to 20 byte and IP total length number is greater than 40
					//That mean, We take data from other side
					if(responseData[TCP_HEADER_LEN_P] == 0x50 && lengthOfDataSegment >TCP_HEADER_LEN_PLAIN + IP_HEADER_LEN)
					  {
						 responseDataLength = lengthOfDataSegment - (TCP_HEADER_LEN_PLAIN + IP_HEADER_LEN);
						//get the current receiver Sequence Number
						getSeqOrAckNum(&responseData[TCP_SEQ_H_P], responseSequenceNum);
						//get the current sender Sequence Number
						//getSeqOrAckNum(&responseData[TCP_ACK_P], senderSeqNum);

						//set the sender Sequence Number with datalength
						setSeqOrAckNum(responseSequenceNum, responseDataLength);

						//For observation response of the server in debug mode
						for(uint8_t k=0; k<100 ; k++)
						{
							rspObsrArray[k] =responseData[k] ;
						}
					}
				else
				{
					//get the current receiver Ack Number
					 getSeqOrAckNum(&responseData[TCP_ACK_P], senderSeqNum);

					 //For observation response of the server in debug mode
					 for(uint8_t k=0; k<100 ; k++)
						{
							rspObsrArray[k] =responseData[k] ;
						}

				}

				return TCP_ACK_SERVER;
			}
				//Server sends to client "FINISH" flag to close the communication
				else if(checkTcpFlag == TCP_FLAGS_FIN_V)
				{
					//get the current receiver Ack Number
					 getSeqOrAckNum(&responseData[TCP_ACK_P], senderSeqNum);

					 getSeqOrAckNum(&responseData[TCP_SEQ_P], responseSequenceNum);

					return TCP_FINISH_SERVER;
				}
				//If server sent RESET flag , It would met a problem and want to restart connection again
				/*else if(checkTcpFlag == TCP_FLAGS_RST_V)
				{
					return TCP_CNT_ESTB_MODE;
				}*/

			}

			else
			{
				//checksum value calculation isn't right cause of the data lose
				return 0;
			}


	}
	else
	{
		// data is invalid
		return 0;
	}
		return 0;
}

void tcpStart(uint8_t * tcpBuf,uint16_t destPort,uint8_t tcpSrvrOrClnt)
{
	if(tcpSrvrOrClnt == TCP_MODE_IS_CLIENT)
	{
		destTcpPort = destPort;
	}
	else
	{
		destTcpPort =  clientSrcPort;
	}
	 if(tcpMode == TCP_IDLE_MODE)
		  {
		   tcpIdleStateMode = checkTcpResponsePacket(tcpBuf);
			  //check If SPI Receiver Buf get any message from Server
			  if(tcpIdleStateMode == TCP_ACK_SERVER)
			  {
				  if(responseDataLength != 0)
				  {
					  //Maximum data length must be less than 1400 for per packet
					  if(responseDataLength < 1400)
					  {
						  replyData = (char *)realloc(replyData,responseDataLength);
					  }
					  else
					  {
						  replyData = (char *)realloc(replyData,1400);
					  }

					  for(uint16_t k =0; k < responseDataLength;k++)
					  {
						  replyData[k] = tcpBuf[TCP_DATA_P +k];
					  }
					  uint8_t l =2;
					  //I want to send ACK message 2 times because receiver may not get ack message at once.
					  //You may just send one time If server sends lots of data packets to client
					  //in order to avoid wasting time
					  while(l >0)
					  {
						 tcpSendData(tcpBuf, replyData, 0, destTcpPort,TCP_DATA_ACK_TO_SRVR);
						 l--;

					  }

				  }
			  }
			  else if(tcpIdleStateMode == TCP_FINISH_SERVER)
			  {
				  //We just send ack info
				tcpSendData(tcpBuf, buf, 0, destTcpPort,TCP_DATA_ACK_TO_SRVR);
				// We also send to finish ACK flag to server to terminate communication
				tcpMode = TCP_FNSH_CMNCT_MODE;
			  }
			  //If sender sends RST flag, we must reconnection to server.
			 /* else if(tcpIdleStateMode == TCP_CNT_ESTB_MODE)
			  {
				  tcpMode = TCP_CNT_ESTB_MODE;
			  }*/
		  }
			 else if(tcpMode == TCP_CNT_ESTB_MODE)
			{
				 if(tcpSrvrOrClnt == TCP_MODE_IS_CLIENT)
				 {
					 tcpClientCnctEstblsh(tcpBuf, destTcpPort,TCP_REQUEST_SEGMENT);

					 HAL_Delay(1);
					  if (checkTcpResponsePacket(tcpBuf) == TCP_REPLY_SERVER)
					  {

					  tcpClientCnctEstblsh(tcpBuf, destTcpPort,TCP_PURE_ACKNOWLEDGEMENT);
					  tcpMode = TCP_IDLE_MODE;

					  }
				 }
				 else
				 {

						 if(checkTcpResponsePacket(tcpBuf) == TCP_REPLY_CLIENT)
						 {
							if(destTcpPort != 0)
						   {
							 tcpClientCnctEstblsh((uint8_t *)tcpBuf, destTcpPort,TCP_REPLY_CLIENT);
							 HAL_Delay(1);
							 if(checkTcpResponsePacket(tcpBuf) == TCP_ACK_SERVER)
							 {
								 tcpMode = TCP_IDLE_MODE;
							 }
						    }

					 }

				 }

			}
			  else if( tcpMode == TCP_SND_DATA_MODE)
			  {

			  tcpSendData(tcpBuf, buf, 13, destTcpPort,TCP_DATA_TRNS);
			  HAL_Delay(1);
			  while(checkTcpResponsePacket(tcpBuf) != TCP_ACK_SERVER )
			  {

				  tcpSendData(tcpBuf, buf, 13, destTcpPort,TCP_DATA_TRNS);
				  HAL_Delay(1);

			  }
			  //This counter for sending data by user button
			  //You can check stm32l4xx.it.c
			  tcpFnsCounter++;

			  tcpMode = TCP_IDLE_MODE;

			  }
			  else if(tcpMode == TCP_FNSH_CMNCT_MODE)
			  {
				  //For stm32 user Button reaction I added 100 micro Second Delay
				  HAL_Delay(100);
				  tcpSendData(tcpBuf, buf, 0, destTcpPort,TCP_DATA_FINISH);
				  HAL_Delay(1);
				  while(checkTcpResponsePacket(tcpBuf) != TCP_ACK_SERVER )
				  {

					  tcpSendData(tcpBuf, buf, 0, destTcpPort,TCP_DATA_FINISH);
					  HAL_Delay(1);

				  }
				  tcpMode = TCP_CLIENT_CLOSED_MODE;
			  }

}

