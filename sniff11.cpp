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

#include <cstring>             // memset
#include <cstdlib>             // exit
#include <unistd.h>            // getopt()
#include <signal.h>            // Ctrl+C handling
#include <arpa/inet.h>         // struct in_addr
#include <string>              // string

#include <set>                 // STL set

#include <pcap.h>              // libpcap

#include "datagram.h"          // Datagram
#include "ethernetframe.h"     // EthernetFrame
#include "ippacket.h"          // IPPacket
#include "arppacket.h"         // ARPPacket
#include "icmppacket.h"        // ICMPPacket

using namespace std;

pcap_t        *pcap_session = NULL;   // libpcap session handle

char          *strfilter = NULL;      // textual BPF filter
bpf_program    binfilter;             // compiled BPF filter program

pcap_dumper_t *logfile = NULL;        // file descriptor for datagram logging

unsigned int capture_count = 0;       // count of captured datagrams

// Function releasing all resources before ending program execution
void shutdown(int error_code) {
  // Close log file
  if (logfile != NULL)
    pcap_dump_close(logfile);

  // Destroy compiled BPF filter if need be
  if (strfilter != NULL)
      pcap_freecode(&binfilter);

  // Close libpcap session
  if (pcap_session != NULL)
    pcap_close(pcap_session);

  // Display the total number of datagrams captured
  cout << "*** " << capture_count << " datagrams captured" << endl;

  exit(error_code); // we're done!
}

// Ctrl+C interrupt handler
void bypass_sigint(int sig_no) {
  cout << endl << "*** Capture process interrupted by user..." << endl;

  shutdown(0); // we're done!
}

bool show_raw   = false;          // deactivate raw display of data captured
bool quiet_mode = false;          // controls whether the callback display captured datagrams or not
int  security_tool = 0;           // security tool to apply

#define ARPSPOOF 1

// Macro replacing cout to apply conditional display in callback
#define COUT if (!quiet_mode) cout

// Callback given to pcap_loop() for processing captured datagrams
void process_packet(u_char *user, const struct pcap_pkthdr * h, const u_char * packet) {
  static set<IPAddress> arpRequests;
  IPPacket ip;
  ARPPacket arp;
  ICMPPacket icmp;

  COUT << "Grabbed " << h->caplen << " bytes (" << static_cast<int>(100.0 * h->caplen / h->len)
       << "%) of datagram received on " << ctime((const time_t*)&h->ts.tv_sec);

  Datagram pkt(packet, h->caplen);        // initialized Datagram instance
  if (show_raw) COUT << "---------------- Raw data -----------------" << pkt << endl;

  EthernetFrame ether = pkt.ethernet();   // get EthernetFrame instance from transported data
  COUT << "---------- Ethernet frame header ----------" << endl << ether;

  // Display payload content according to EtherType
  switch (ether.ether_type()) {
    case EthernetFrame::et_IPv4 :         // get IPPacket instance from transported data
      ip = ether.ip4();
      COUT << "-------- IP packet header --------" << endl << ip;

      // If it's an ICMP packet, displat its attributes
      if (ip.protocol() == IPPacket::ipp_icmp) {
        icmp = ip.icmp();
        COUT << "------ ICMP packet header ------" << endl << icmp;
      }

      break;

    case EthernetFrame::et_ARP :          // get ARPPacket instance from transported data
      arp = ether.arp();
      COUT << "-------- ARP packet header --------" << endl << arp;

      // Check if we must apply ARP spoofing detection
      if (security_tool == ARPSPOOF) {
        switch (arp.operation()) {
          case ARPPacket::akt_ArpRequest:
            // Add target's IP to the set to log there was a request for its MAC
            arpRequests.insert(arp.destination_ip());
            break;

          case ARPPacket::akt_ArpReply:
            // Make sure the source respond to a legitimate request
            set<IPAddress>::iterator it = arpRequests.find(arp.source_ip());
            if (it == arpRequests.end())
              // This reply is gratuitous (no corresponding request)
              cout << endl << "**** ALERT - Potential ARP spoofing detected ****" << endl
                           << "     unsollicited ARP reply to " << arp.destination_mac()
                           << "     originating from " << arp.source_mac() << endl << endl;
            else
              arpRequests.erase(it);  // remove from set to indicate the request was replied

            break;
        }
      }

      break;
  }

  COUT << endl << flush;

  // Log datagram if required
  if (user != NULL)
    pcap_dump(user, h, packet);

  // Count the capture
  capture_count++;
}

// Sniffer's main program: add ICMP packet capture
int main(int argc, char *argv[]) {
  char *device = NULL;            // device to sniff
  char  argch;                    // to manage command line arguments
  char  errbuf[PCAP_ERRBUF_SIZE]; // to handle libpcap error messages
  int   siz     = 1518,           // max number of bytes captured for each datagram
        promisc = 0,              // deactive promiscuous mode
        cnt     = -1;             // capture indefinitely
  char *wlogfname = NULL,         // filename where to log captured datagrams
       *rlogfname = NULL;         // filename from which to read logged datagrams

  // Install Ctrl+C handler
  struct sigaction sa, osa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = &bypass_sigint;
  sigaction(SIGINT, &sa, &osa);

  // Process command line arguments
  while ((argch = getopt(argc, argv, "hpqrd:f:i:l:n:s:")) != EOF)
    switch (argch) {
      case 'd':           // device name
        device = optarg;
        break;

      case 'f':           // BPF filter
        strfilter = optarg;
        break;

      case 'h':           // show help info
        cout << "Usage: sniff [-d XXX -h]" << endl;
        cout << " -d XXX : device to capture from, where XXX is device name (ex: eth0)." << endl;
        cout << " -f 'filter' : filter captures according to BPF expression (ex: 'ip or arp')." << endl;
        cout << " -h : show this information." << endl;
        cout << " -i file : read datagrams from given file instead of a device." << endl;
        cout << " -l file : log captured datagrams in given file." << endl;
        cout << " -n : number of datagrams to capture." << endl;
        cout << " -p : activate promiscuous capture mode." << endl;
        cout << " -q : activate quiet mode." << endl;
        cout << " -r : activate raw display of captured data." << endl;
        cout << " -s : apply specified security application" << endl
             << "      available applications: arpspoof." << endl;

        // Exit if only argument is -h
        if (argc == 2) return 0;
        break;

      case 'i':           // filename from which to read logged datagrams
        rlogfname = optarg;
        break;

      case 'l':           // filename where to log captured datagrams
        wlogfname = optarg;
        break;

      case 'n':           // number of datagrams to capture
        cnt = atoi(optarg);
        break;

      case 'p':           // active promiscuous mode
        promisc = 1;
        break;

      case 'q':           // active quiet mode
        quiet_mode = 1;
        break;

      case 'r':           // active raw display of captured data
        show_raw = 1;
        break;

      case 's':           // apply specified security tool
        if (string(optarg) == "arpspoof")
          security_tool = ARPSPOOF;
        else {
          cerr << "error - unknow security tool specified (" << optarg << ")" << endl;
          return -10;
        }

        break;
    }

  // Options -d and -i are mutually exclusives
  if (device != NULL && rlogfname != NULL) {
      cerr << "error - options -d and -i are mutually exclusives" << endl;
      return -7;
  }

  // Identify device to use
  if (rlogfname == NULL && device == NULL)
    if ((device = pcap_lookupdev(errbuf)) == NULL) {
      cerr << "error - " << errbuf << endl;
      return -2;
    }

  if (rlogfname != NULL)
    cout << "input file = " << rlogfname << endl;
  else
    cout << "device = " << device << (promisc ? " (promiscuous)" : "") << endl;

  // Extract IP information for network connected to device
  bpf_u_int32 netp,  // ip address of network
              maskp; // network mask

  // If capturing from device, display its attributes
  if (rlogfname == NULL) {
    if ((pcap_lookupnet(device, &netp, &maskp, errbuf)) == -1) {
      cerr << "error - " << errbuf << endl;
      return -3;
    }

    // Translate ip address into textual form for display
    struct  in_addr addr;
    char   *net;
    addr.s_addr = netp;
    if ((net = inet_ntoa(addr)) == NULL)
      cerr << "error - inet_ntoa() failed" << endl;
    else
      cout << "network ip = " << net << endl;

    // Translate network mask into textual form for display
    char *mask;
    addr.s_addr = maskp;
    if ((mask = inet_ntoa(addr)) == NULL)
      cerr << "error - inet_ntoa() failed" << endl;
    else
      cout << "network mask = " << mask << endl;
  }

  // Open a libpcap capture session
  if (rlogfname == NULL) {
    // Session linked to the device
    pcap_session = pcap_open_live(device, siz, promisc, 1000, errbuf);
    if (pcap_session == NULL) {
      cerr << "error - pcap_open_live() failed (" << errbuf << ")" << endl;
      return -4;
    }
  }
  else {
    // Session linked to the log file
    pcap_session = pcap_open_offline(rlogfname, errbuf);
    if (pcap_session == NULL) {
      cerr << "error - pcap_open_offline() failed (" << errbuf << ")" << endl;
      return -8;
    }
  }

  // Compile BPF filter expression into program if one provided
  if (strfilter != NULL) {
    // Compile filter expression
    if (pcap_compile(pcap_session, &binfilter, strfilter, 1, maskp) < 0) {
      cerr << "error - pcap_compile() failed (" << pcap_geterr(pcap_session) << ")" << endl;
      shutdown(-5);    // Cleanup and quit
    }

    // Install compiled filter
    if (pcap_setfilter(pcap_session, &binfilter) < 0) {
      cerr << "error - pcap_setfilter() failed (" << pcap_geterr(pcap_session) << ")" << endl;
      shutdown(-6);    // Cleanup and quit
    }

    cout << "BPF filter = " << strfilter << endl;    // display applied filter
  }

  // If need be, open file where captured datagrams are to be logged
  if (wlogfname != NULL)
    if ((logfile = pcap_dump_open(pcap_session, wlogfname)) == NULL) {
      cerr << "error - pcap_dump_open() failed (" << pcap_geterr(pcap_session) << ")" << endl;
      shutdown(-9);    // Cleanup and quit
  }

  // Display any security application enabled
  switch (security_tool) {
    case ARPSPOOF: cout << "arp spoofing detection enabled..." << endl;
                   break;
  }

  // Start capturing...
  pcap_loop(pcap_session, cnt, process_packet, (u_char *)logfile);

  // Shutdown the application
  shutdown(0);
}
