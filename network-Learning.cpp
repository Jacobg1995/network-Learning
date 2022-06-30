#include <iostream>

#include <cstring>     // memset
#include <cstdlib>     // exit
#include <unistd.h>    // getopt()
#include <signal.h>    // Ctrl+C handling

#include <pcap/pcap.h>      // libpcap

using namespace std;

// Ctrl+C interrupt handler
void bypass_sigint(int sig_no) {
  cout << endl << "*** Capture process interrupted by user..." << endl;

  exit(0); // we're done!
}

// First libpcap program: device selection
int main(int argc, char *argv[]) {
  pcap_if_t *alldevs;
  pcap_if_t *device = NULL;             // device to sniff
  char argch;                      // to manage command line arguments
  char errbuf[PCAP_ERRBUF_SIZE];   // to handle libpcap error messages

  // Install Ctrl+C handler
  struct sigaction sa, osa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = &bypass_sigint;
  sigaction(SIGINT, &sa, &osa);

  // Process command line arguments
  while ((argch = getopt(argc, argv, "hd:")) != EOF)
    switch (argch) {
      case 'd':           // device name
       // device = optarg;
        break;

      case 'h':           // show help info
        cout << "Usage: sniff [-d XXX -h]" << endl;
        cout << " -d XXX : device to capture from, where XXX is device name (ex: eth0)." << endl;
        cout << " -h : show this information." << endl;

        // Exit if only argument is -h
        if (argc == 2) return 0;
        break;
    }
/*
  // Identify device to use
  if (device == NULL && (pcap_findalldevs(&alldevs, errbuf)) == NULL) {
    cerr << "error - " << errbuf << endl;
    return -2;
  }
  else
    cout << "device = " << device << endl;
*/

  if(device == NULL)
  {
	  if(pcap_findalldevs(&alldevs, errbuf) == -1)
	  {
		  printf("error in pcap_findalldevs:%s\n", errbuf);

		  return -1;
	  }

		printf("Enabled Network Devices:\n");
		printf("1 - %s\n", alldevs->name);
		printf("2 - %s\n", alldevs->next->name);
		printf("3 - %s\n", alldevs->next->next->name);
  }
  return 0;
}
