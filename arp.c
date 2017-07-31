#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    char *dev = argv[1];
    int i;

    dev = pcap_lookupdev(errbuf);

    if( dev == NULL )
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    if(argc !=2)
    {

        printf("usage : %s interface (e.g. 'rpcap://eth0')\n", argv[0]);
        return;
    }

    if ( (fp = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, 0, errbuf)) == NULL)
    {
        printf(stderr, "Unable to open the Adapter.%s is not supported by Libpcap ", argv[1]);
        return;
    }

    /* Supposing to be on ethernet, set mac destination to */
    packet[0] = 0xFF;
    packet[1] = 0xFF;
    packet[2] = 0xFF;
    packet[3] = 0xFF;
    packet[4] = 0xFF;
    packet[5] = 0xFF;

    /* set mac source to */
    packet[6] = 0x00;
    packet[7] = 0x0c;
    packet[8] = 0x29;
    packet[9] = 0x3e;
    packet[10] = 0x18;
    packet[11] = 0xc8;

    /* ARP */
    packet[12] = 0x08;
    packet[13] = 0x06;

    /* Hardware Type (ethernet) */
    packet[14] = 0x00;
    packet[15] = 0x01;

    /* protocol type(ip) */
    packet[16] = 0x08;
    packet[17] = 0x00;

    /* Hardware Length */
    packet[18] = 0x06;

    /* Protocol Length */
    packet[19] = 0x04;

    /* Operation (request :1, reply : 2) */
    packet[20] = 0x00;
    packet[21] = 0x01;

    /* Sender Hardware Address */
    packet[22] = 0x00;
    packet[23] = 0x0c;
    packet[24] = 0x29;
    packet[25] = 0x3e;
    packet[26] = 0x18;
    packet[27] = 0xc8;

    /* Sender Protocol Address */
    packet[28] = 0xac;
    packet[29] = 0x14;
    packet[30] = 0x0a;
    packet[31] = 0x04;

    /* Target Hardware Address (Empty) */
    packet[32] = 0x00;
    packet[33] = 0x00;
    packet[34] = 0x00;
    packet[35] = 0x00;
    packet[36] = 0x00;
    packet[37] = 0x00;  

    /* Target Protocol Address */
    packet[38] = 0xAA;
    packet[39] = 0x14;
    packet[40] = 0x0a;
    packet[41] = 0x01;

    /* file the rest of the packet */
    for( i=42 ; i<59 ; i++ )
    {
        packet[i] = 0x44;
    }


    if (pcap_sendpacket(fp, packet, 100 /* size */ ) != 0 )
    {
        printf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
        return 0;
    }



    return 0;
}