# Making-TCP-communication-by-using-ENC28J60-cheap-ethernet-modelu-with-STM32-mcu-Nuc-L4R5ZI-

   In this project nucleo L4R5ZI board is used for TCP communication
   Fundamental codes of the enc28j60 ethernet module is taken
   by Dmitrii Okunev(github Account name = xaionaro)
   https://github.com/xaionaro/stm32-enc28j60
  
   He just tested UDP communication so I decided to add TCP protocol
   for this ethernet module. I separately created "tcp.c" and "tcp.h"
   and edited some functions in his created classes.
  
   NOTE!!: This project have been under development.It can be
   sent data without any problem but when responser repeatedly send
   data ethernet module may not receive datagrams.
  
   SPI Interface with speeds up to 10 Mb/s
   This mcu receives datagrams by polling method
   
   You need to change you header files and 
   SPI pins according to your setup and mcu type 
  
   It is used the B7 errata version of the ENC28J60

   SCENARIO
   
    In this project When user press to user button stm32 send "Hello World" message to remote host and it also receive data from across host(Across host is managed by HERCULES application). When stm32 send data 6 times,It terminates the communication with across host. It is valid both Client and Server.
