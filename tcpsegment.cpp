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
#ifndef TCPSEGMENT_CPP
#define TCPSEGMENT_CPP

#include "tcpsegment.h"

// Default constructor
TCPSegment::TCPSegment(bool owned) : DatagramFragment(owned) {
}

// Parameterized constructor
TCPSegment::TCPSegment(bool owned, unsigned char * s, unsigned int l) : DatagramFragment(owned, s, l) {
}

// Returns the TCP segment header length in bytes
unsigned int TCPSegment::header_length() const {
  return offset() * 4;        // take into account possible options
}

// Returns source port
unsigned int TCPSegment::source_port() const {
  return char2word(p_data);
}

// Returns destination port
unsigned int TCPSegment::destination_port() const {
  return char2word(p_data+2);
}

// Returns the sequence number field
unsigned int TCPSegment::sequence_nb() const {
  return char4word(p_data+4);
}

// Returns the acknowledgment number field
unsigned int TCPSegment::ack_nb() const {
  return char4word(p_data+8);
}

// Returns the data offset field (header length in 4-bytes words)
unsigned int TCPSegment::offset() const {
  return p_data[12] >> 4;
}

// Returns the reserved field
unsigned int TCPSegment::reserved() const {
  return (char2word(p_data+12) & 0x0FC0) >> 6;
}

// Returns the NS flag value
bool TCPSegment::flag_ns() const {
  return p_data[12] & 0x01	;
}

// Returns the CWR flag value
bool TCPSegment::flag_cwr() const {
  return p_data[13] & 0x80;
}

// Returns the ECE flag value
bool TCPSegment::flag_ece() const {
  return p_data[13] & 0x40;
}

// Returns the URG flag value
bool TCPSegment::flag_urg() const {
  return p_data[13] & 0x20;
}

// Returns the ACK flag value
bool TCPSegment::flag_ack() const {
  return p_data[13] & 0x10;
}

// Returns the PSH flag value
bool TCPSegment::flag_psh() const {
  return p_data[13] & 0x08;
}

// Returns the RST flag value
bool TCPSegment::flag_rst() const {
  return p_data[13] & 0x04;
}

// Returns the SYN flag value
bool TCPSegment::flag_syn() const {
  return p_data[13] & 0x02;
}

// Returns the FIN flag value
bool TCPSegment::flag_fin() const {
  return p_data[13] & 0x01;
}

// Returns the window size field
unsigned int TCPSegment::window_size() const {
  return char2word(p_data+14);
}

// Returns the checksum field
unsigned int TCPSegment::checksum() const {
  return char2word(p_data+16);
}

// Returns the urgent pointer field
unsigned int TCPSegment::pointer_urg() const {
  return char2word(p_data+18);
}

// Returns a string textually identifying most popular standard ports
const char * TCPSegment::port_name(unsigned int num) const {
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

// Output operator displaying the IP packet header fields in human readable
// form
ostream & operator<<(ostream & ostr, const TCPSegment & tcp) {
  if (tcp.p_data) {
    char outstr[16];

    ostr << "source port = " << tcp.source_port();
    ostr << " [" << tcp.port_name(tcp.source_port()) << "]" << endl;

    ostr << "destination port = " << tcp.destination_port();
    ostr << " [" << tcp.port_name(tcp.destination_port()) << "]" << endl;

    ostr << "sequence number = " << tcp.sequence_nb() << endl;
    ostr << "ack number = " << tcp.ack_nb() << endl;

    ostr << "offset = " << tcp.offset() << endl;
    ostr << "reserved = " << tcp.reserved() << endl;

    ostr << "NS  flag = " << tcp.flag_ns()  << endl;
    ostr << "CWR flag = " << tcp.flag_cwr() << endl;
    ostr << "ECE flag = " << tcp.flag_ece() << endl;
    ostr << "URG flag = " << tcp.flag_urg() << endl;
    ostr << "ACK flag = " << tcp.flag_ack() << endl;
    ostr << "PSH flag = " << tcp.flag_psh() << endl;
    ostr << "RST flag = " << tcp.flag_rst() << endl;
    ostr << "SYN flag = " << tcp.flag_syn() << endl;
    ostr << "FIN flag = " << tcp.flag_fin() << endl;

    ostr << "window size = " << tcp.window_size() << endl;
    ostr << "urgent pointer = " << tcp.pointer_urg() << endl;

    sprintf(outstr, "0x%.4x", tcp.checksum());
    ostr << "checksum = " << outstr << endl;
  }

  ostr << flush;

  return ostr;
}

#endif
