#include <iostream>

#include <cstring>     // memset
#include <cstdlib>     // exit
#include <unistd.h>    // getopt()
#include <signal.h>    // Ctrl+C handling
#include <arpa/inet.h> // struct in_addr

#include <pcap.h>      // libpcap

using namespace std;

pcap_t *pcap_session = NULL; // libpcap session handle

// Ctrl+C interrupt handler
void bypass_sigint(int sig_no) {
  cout << endl << "*** Capture process interrupted by user..." << endl;

  // Close libpcap session
  if (pcap_session != NULL)
    pcap_close(pcap_session);

  exit(0); // we're done!
}

// Callback given to pcap_loop() for processing captured datagrams
void process_packet(u_char *user, const struct pcap_pkthdr * h, const u_char * packet) {
  cout << "Grabbed " << h->caplen << " bytes (" << static_cast<int>(100.0 * h->caplen / h->len)
       << "%) of datagram received on " << ctime((const time_t*)&h->ts.tv_sec);
}

// First libpcap program : device selection
int main(int argc, char *argv[]) {
  char *device = NULL;            // device to sniff
  char  argch;                    // to manage command line arguments
  char  errbuf[PCAP_ERRBUF_SIZE]; // to handle libpcap error messages
  int   siz     = 1518,           // max number of bytes captured for each datagram
        promisc = 0,              // deactive promiscuous mode
        cnt     = -1;             // capture indefinitely

  // Install Ctrl+C handler
  struct sigaction sa, osa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = &bypass_sigint;
  sigaction(SIGINT, &sa, &osa);

  // Process command line arguments
  while ((argch = getopt(argc, argv, "hpd:n:")) != EOF)
    switch (argch) {
      case 'd':           // device name
        device = optarg;
        break;

      case 'h':           // show help info
        cout << "Usage: sniff [-d XXX -h]" << endl;
        cout << " -d XXX : device to capture from, where XXX is device name (ex: eth0)." << endl;
        cout << " -h : show this information." << endl;
        cout << " -n : number of datagrams to capture." << endl;
        cout << " -p : activate promiscuous capture mode." << endl;

        // Exit if only argument is -h
        if (argc == 2) return 0;
        break;

      case 'n':           // number of datagrams to capture
        cnt = atoi(optarg);
        break;

      case 'p':           // active promiscuous mode
        promisc = 1;
        break;
    }

  // Identify device to use
  if (device == NULL && (device = pcap_lookupdev(errbuf)) == NULL) {
    cerr << "error - " << errbuf << endl;
    return -2;
  }
  else
    cout << "device = " << device << (promisc ? " (promiscuous)" : "") << endl;

  // Extract IP information for network connected to device
  bpf_u_int32 netp,  // ip address of network
              maskp; // network mask
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

  // Open a libpcap capture session
  pcap_session = pcap_open_live(device, siz, promisc, 1000, errbuf);
  if (pcap_session == NULL) {
    cerr << "error - pcap_open_live() failed (" << errbuf << ")" << endl;
    return -4;
  }

  // Start capturing...
  pcap_loop(pcap_session, cnt, process_packet, NULL);

  // Close libpcap session
  pcap_close(pcap_session);

  return 0;
}
