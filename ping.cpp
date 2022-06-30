/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2014 Marco Lavoie
    marco@marcolavoie.ca
*/
#include <iostream>
#include <cstdlib>        // sprintf, exit
#include <signal.h>       // Ctrl+C handling
#include <sys/time.h>     // gettimeofday
#include <unistd.h>       // sleep

#include "datagram.h"     // Datagram
#include "ippacket.h"     // IPPacket
#include "icmppacket.h"   // ICMPPacket
#include "exceptions.h"   // EBadTransportException

#include <libnet.h>       // libnet
#include <pcap.h>         // libpcap

using namespace std;

libnet_t    *libnet_ctx  = NULL;    // libnet session context.
pcap_t      *pcap_ctx    = NULL;    // libpcap session context
bpf_program  pcap_filter;           // libpcap filter for echo replies

// Function releasing all resources before ending program execution
void shutdown(int error_code) {
  // Free libnet session context
  if (libnet_ctx)
    libnet_destroy(libnet_ctx);

  // Free libpcap filter
  if (pcap_ctx)
    pcap_freecode(&pcap_filter);

  // Free libpcap session context
  if (pcap_ctx)
    pcap_close(pcap_ctx);

  exit(error_code); // we're done!
}

// Ctrl+C interrupt handler
void bypass_sigint(int sig_no) {
  cout << endl << "*** Interrupted by user..." << endl;

  shutdown(0); // we're done!
}

// Returns current time in milliseconds
unsigned long get_clock() {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Implementation of ping
int main(int argc, char *argv[]) {
  char       *device = NULL;             // device to sniff
  u_int32_t   ip_addr;                   // to manipulate IPv4 addresses
  u_int32_t   target_addr;               // IP of target host
  u_int32_t   host_addr;                 // IP of local host
  bpf_u_int32 netp,                      // network IP of local device
              maskp;                     // network IP mask of local device

  // We must make error buffer large enough to hold both libpcap and libnet messages
  char errbuf[PCAP_ERRBUF_SIZE > LIBNET_ERRBUF_SIZE? PCAP_ERRBUF_SIZE : LIBNET_ERRBUF_SIZE];

  // Make sure we have a target to ping
  if (argc < 2) {
    cerr << "error - no target to ping" << endl;
    shutdown(-1);    // Cleanup and quit
  }

  // Install Ctrl+C handler
  struct sigaction sa, osa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = &bypass_sigint;
  sigaction(SIGINT, &sa, &osa);

  // Identify device to use
  if ((device = pcap_lookupdev(errbuf)) == NULL) {
    cerr << "error - pcap_lookupdev() failed (" << errbuf << ")" << endl;
    shutdown(-2);    // Cleanup and quit
  }

  // Get libpcap session context and validate
  pcap_ctx = pcap_open_live(device, BUFSIZ, 1, 1 /* 50ms */, errbuf);
  if (pcap_ctx == NULL) {
    cerr << "error - pcap_open_live() failed (" << errbuf << ")" << endl;
    shutdown(-3);    // Cleanup and quit
  }


  // Get libnet session context and validate
  libnet_ctx = libnet_init(LIBNET_RAW4, device, errbuf);
  if (libnet_ctx == NULL) {
    cerr << "error - libnet_init() failed (" << errbuf << ")" << endl;
    shutdown(-4);    // Cleanup and quit
  }

  // Get network mask of local device
  if ((pcap_lookupnet(device, &netp, &maskp, errbuf)) == -1) {
    cerr << "error - libnet_lookupnet() failed (" << errbuf << ")" << endl;
    shutdown(-5);    // Cleanup and quit
  }

  // Get IPv4 address given to device
  ip_addr = libnet_get_ipaddr4(libnet_ctx);
  if (ip_addr == -1)
    cerr << "error - libnet_get_ipaddr4 failed (" << libnet_geterror(libnet_ctx) << ")" << endl;

  // Convert target IP into integer form (with DNS resolution if needed)
  if ((target_addr = libnet_name2addr4(libnet_ctx, argv[1], LIBNET_RESOLVE)) == -1) {
    cerr << "error - can't resolve " << argv[1] << endl;
    shutdown(-6);    // Cleanup and quit
  }
  // Build filter to capture only returned echo replies from target host with
  // this process' PID as identifier
  char filter[255];
  sprintf(filter, "icmp && icmp[0]=0 && icmp[4:2]=%d && src host %s",getpid(), libnet_addr2name4(target_addr, LIBNET_DONT_RESOLVE));
 // sprintf(filter, "src host %s", libnet_addr2name4(target_addr, LIBNET_DONT_RESOLVE));

  // Compile BPF filter expression into program if one provided
  if (pcap_compile(pcap_ctx, &pcap_filter, filter, 0x100, maskp) < 0) {
    cerr << "error - pcap_compile() failed (" << pcap_geterr(pcap_ctx) << ")" << endl;
    shutdown(-7);    // Cleanup and quit
  }

  // Install compiled filter
  if (pcap_setfilter(pcap_ctx, &pcap_filter) < 0)
  {
    cerr << "error - pcap_setfilter() failed (" << pcap_geterr(pcap_ctx) << ")" << endl;
    shutdown(-8);    // Cleanup and quit
  }

  // Display target info
  cout << "PING " << argv[1] << " (" << libnet_addr2name4(target_addr, LIBNET_DONT_RESOLVE) << ")" << endl;

  // Injection loop
  for (unsigned int cnt = 0; cnt < 4; cnt++) {
    // Tags for handling datagram building
    libnet_ptag_t icmp_ptag = LIBNET_PTAG_INITIALIZER;
    libnet_ptag_t ip_ptag   = LIBNET_PTAG_INITIALIZER;

    // Construct an ICMP echo request datagram
    icmp_ptag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, getpid(), cnt, NULL, 0, libnet_ctx, icmp_ptag);
    if (icmp_ptag == -1) {
      cerr << "error - can't build ICMP header (" << libnet_geterror(libnet_ctx) << ")" << endl;
      shutdown(-9);
    }

    // Construct an IP packet to encapsulate the ICMP datagram
    ip_ptag = libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, IPPROTO_ICMP, target_addr, libnet_ctx);
    if (ip_ptag == -1) {
      cerr << "error - can't build IP header (" << libnet_geterror(libnet_ctx) << ")" << endl;
      shutdown(-10);
    }

    struct pcap_pkthdr *hdr;
    const u_char * packet;
    int result = 0;

    // Inject the resulting datagram and make sure it worked
    int bytes = libnet_write(libnet_ctx);
    if (bytes == -1){
      cerr << "error - failed to inject (" << libnet_geterror(libnet_ctx) << ")" << endl;

      continue;  // proceed to next ping
    }

    unsigned int delay = get_clock();  // record time of packet departure

    // Capture upcoming echo reply.
    	do {
    	result = pcap_next_ex(pcap_ctx, &hdr, &packet);
    	} while(!result);


       delay = get_clock() - delay;       // calculate response delay
      // Make sure we got a response (we may have got a timeout)
    if (packet) {
      try {
        Datagram pkt(packet, hdr->caplen);    // initialized Datagram instance
        IPPacket ip = pkt.ethernet().ip4();  // get captured IP packet

        // Display ICMP echo reply information
        cout << pkt.length() << " bytes from " << ip.source_ip()
             << ": icmp_seq=" << ip.icmp().sequence_number()
             << " ttl=" << ip.ttl() << " time=" << delay << " ms" << endl;
      }
      catch (EBadTransportException) {
        cerr << "error - unexpected returned datagram!" << endl;
      }
    }

    libnet_clear_packet(libnet_ctx);   // clear datagram associated to context (optional)
    sleep(1);                          // delay one second to avoid flooding target

  }

  // Shutdown the application
  shutdown(0);
}

