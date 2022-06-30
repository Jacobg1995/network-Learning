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
#ifndef UDPSEGMENT_CPP
#define UDPSEGMENT_CPP

#include "udpsegment.h"

// Default constructor
UDPSegment::UDPSegment(bool owned) : DatagramFragment(owned) {
}

// Parameterized constructor
UDPSegment::UDPSegment(bool owned, unsigned char * s, unsigned int l) : DatagramFragment(owned, s, l) {
}

// Returns the UDP segment header length in bytes
unsigned int UDPSegment::header_length() const {
  return 8;
}

// Returns source port
unsigned int UDPSegment::source_port() const {
  return char2word(p_data);
}

// Returns destination port
unsigned int UDPSegment::destination_port() const {
  return char2word(p_data+2);
}

// Returns the length field
unsigned int UDPSegment::len() const {
  return char2word(p_data+4);
}

// Returns the checksum field
unsigned int UDPSegment::checksum() const {
  return char2word(p_data+6);
}

// Returns TFTP datagram transported in payload
TFTPDatagram UDPSegment::tftp() {
  return TFTPDatagram(false, data(), length() - header_length());
}

// Returns a string textually identifying most popular standard ports
const char * UDPSegment::port_name(unsigned int num) const {
  switch (num) {
    case  20:
    case  21: return "FTP";
    case  22: return "SSH";
    case  23: return "telnet";
    case  25: return "SMTP";
    case  53: return "DNS";
    case  67:
    case  68: return "DHCP";
    case  69: return "TFTP";
    case  80: return "HTTP";
    case 110: return "POP3";
    case 137:
    case 150: return "NetBIOS";
    case 389: return "LDAP";
    case 546:
    case 547: return "DHCP";
  }

  // Distinguish assigned ports from ephemerals
  if (num < 1024)
    return "unknown";
  else
    return "ephemeral";
}

// Returns a string textually identifying some common standard ports
ostream & operator<<(ostream & ostr, const UDPSegment & udp) {
  if (udp.p_data) {
    char outstr[8];

    ostr << "source port = " << udp.source_port();
    ostr << " [" << udp.port_name(udp.source_port()) << "]" << endl;

    ostr << "destination port = " << udp.destination_port();
    ostr << " [" << udp.port_name(udp.destination_port()) << "]" << endl;

    ostr << "length = " << udp.len()  << endl;

    sprintf(outstr, "0x%.4x", udp.checksum());
    ostr << "checksum = " << outstr << endl;
  }

  ostr << flush;

  return ostr;
}

#endif
