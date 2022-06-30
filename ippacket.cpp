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
#ifndef IPPACKET_CPP
#define IPPACKET_CPP

#include "ippacket.h"
#include "exceptions.h"

// Default constructor
IPPacket::IPPacket(bool owned) : DatagramFragment(owned) {
}

// Parameterized constructor
IPPacket::IPPacket(bool owned, unsigned char * s, unsigned int l) : DatagramFragment(owned, s, l) {
}

// Returns the IP header length in bytes
unsigned int IPPacket::header_length() const {
  if (!p_data)
    return 0;
  else
    return 4 * ihl();
}

// Returns the content of the header's Version field
unsigned int IPPacket::version() const {
  return p_data[0] >> 4;
}

// Returns the content of the header's IHL (Internet Header Length) field
unsigned int IPPacket::ihl() const {
  return p_data[0] & 0x0F;
}

// Returns the content of the header's Type Of Service field
unsigned int IPPacket::tos() const {
  return p_data[1];
}

// Returns the content of the header's Total Length field
unsigned int IPPacket::total_length() const {
  return char2word(p_data+2);
}

// Returns the content of the header's Fragmentation ID field
unsigned int IPPacket::fragment_id() const {
  return char2word(p_data+4);
}

// Returns the content of the header's Fragmentation flags
unsigned int IPPacket::fragment_flags() const {
  return p_data[6] >> 5;
}

// Returns the content of the header's Fragmentation position field
unsigned int IPPacket::fragment_pos() const {
  unsigned int i = p_data[6] & 0x1F;
  return i << 8 | p_data[7];
}

// Indicates if the packet is fragmented, and if so, if it's the first
// and/or last fragment
bool IPPacket::fragmented(bool &first, bool &last) const {
  first = fragment_pos() == 0;
  last  = (fragment_flags() & 0x1) == 0;

  return !(first && last);
}

// Returns the content of the header's Time To Live field
unsigned int IPPacket::ttl() const {
  return p_data[8];
}

// Returns the content of the header's Checksum field
unsigned int IPPacket::checksum() const {
  return char2word(p_data+10);
}

// Returns the content of the header's Protocol field
unsigned int IPPacket::protocol_id() const {
  return p_data[9];
}

// Indicates which protocol is encapsulated within the packet's
// payload
IPPacket::IPProtocol IPPacket::protocol() const {
  switch (protocol_id()) {
    case  1 : return ipp_icmp;
    case  2 : return ipp_igmp;
    case  6 : return ipp_tcp;
    case 17 : return ipp_udp;
    default : return ipp_other;
  }
}

// Returns the packet's destination IP address (i.e. where it's
// going)
IPAddress IPPacket::destination_ip() const {
  if (version() == 4) {
    IPAddress adr(false, p_data + 16);
    return adr;
  }
  else
    throw EBadTransportException("Internet protocol not IPv4");
}

// Returns the packet's source IP address (i.e. where it's
// coming from)
IPAddress IPPacket::source_ip() const {
  if (version() == 4) {
    IPAddress adr(false, p_data + 12);
    return adr;
  }
  else
    throw EBadTransportException("Internet protocol not IPv4");
}

// Counts the number of options within the header
unsigned int IPPacket::count_options() const {
  unsigned int cnt = 0;

  // Are there options?
  if (header_length() == 20)
    return cnt;

  unsigned char *p = p_data+20;
  unsigned int optclass, optnumber;
  while ((p - p_data) < header_length() && *p != 0) {
    optclass  = (*p & 0x60) >> 5;
    optnumber = *p & 0x1F;

    if (optnumber < 2)
      p++;
    else
      p += p[1] + 2;

    cnt++;
  }

  return cnt;
}

// Extract attributes of given option index
bool IPPacket::option_header(unsigned int idx, unsigned int &optclass,
                             unsigned int &optnumber, unsigned int &optlen) const {
  if (idx < 0 || idx >= count_options())
    return false;

  unsigned char *p = p_data+20;

  do {
    optclass  = (*p & 0x60) >> 5;
    optnumber = *p & 0x1F;
    if (optnumber < 2) {
      optlen = 0;
      p++;
    }
    else {
      optlen = p[1];
      p += optlen + 2;
    }
  } while (idx--);

  return true;
}

// Returns ICMP packet transported in payload
ICMPPacket IPPacket::icmp() {
    if (protocol() != ipp_icmp)
        throw EBadTransportException("IP packet not transporting ICMP traffic");

    return ICMPPacket(false, data(), length() - header_length());
}

// Returns TCP segment transported in payload
TCPSegment IPPacket::tcp() {
    if (protocol() != ipp_tcp)
        throw EBadTransportException("IP packet not transporting TCP traffic");

    return TCPSegment(false, data(), length() - header_length());
}

// Returns UDP segment transported in payload
UDPSegment IPPacket::udp() {
    if (protocol() != ipp_udp)
        throw EBadTransportException("IP packet not transporting UDP traffic");

    return UDPSegment(false, data(), length() - header_length());
}

// Output operator displaying the IP packet header fields in human readable
// form
ostream & operator<<(ostream & ostr, const IPPacket & ip) {
  if (ip.p_data) {
    char outstr[8];

    ostr << "version = ";
    switch (ip.version()) {
      case 4:  ostr << "IPv4" << endl; break;
      case 6:  ostr << "IPv6" << endl; break;
      default: ostr << "unknown [" << ip.version() << "]" << endl; break;
    }

    ostr << "header length = " << ip.header_length() << " (IHL = " << ip.ihl() << ")" << endl;

    ostr << "type of service = " << ip.tos() << ":" << endl;
    if (ip.tos() > 0) {
      switch (ip.tos() >> 5) {
        case 0: ostr << "  precedence = routine" << endl; break;
        case 1: ostr << "  precedence = priority" << endl; break;
        case 2: ostr << "  precedence = immediate" << endl; break;
        case 3: ostr << "  precedence = flash" << endl; break;
        case 4: ostr << "  precedence = flash override" << endl; break;
        case 5: ostr << "  precedence = critical" << endl; break;
        case 6: ostr << "  precedence = internetwork control" << endl; break;
        case 7: ostr << "  precedence = network control" << endl; break;
      }

      // Type of service in textual form
      if (ip.tos() & 0x10)
        ostr << "  delay = low" << endl;
      else
        ostr << "  delay = normal" << endl;

      if (ip.tos() & 0x08)
        ostr << "  throughput = high" << endl;
      else
        ostr << "  throughput = normal" << endl;

      if (ip.tos() & 0x04)
        ostr << "  reliability = high" << endl;
      else
        ostr << "  reliability = normal" << endl;

      if (ip.tos() & 0x02)
        ostr << "  cost = low" << endl;
      else
        ostr << "  cost = normal" << endl;
    }

    ostr << "total length = " << ip.total_length() << endl;

    sprintf(outstr, "0x%.4x", ip.fragment_id());
    ostr << "fragment ID = " << outstr << endl;
    ostr << "  don't fragment = " << (ip.fragment_flags() & 0x2) << endl;
    ostr << "  more fragments = " << (ip.fragment_flags() & 0x1) << endl;
    ostr << "  fragment position = " << ip.fragment_pos() << endl;

    ostr << "protocol = ";
    switch (ip.protocol()) {
      case IPPacket::ipp_icmp: ostr << "ICMP ["; break;
      case IPPacket::ipp_igmp: ostr << "IGMP ["; break;
      case IPPacket::ipp_tcp:  ostr << "TCP ["; break;
      case IPPacket::ipp_udp:  ostr << "UDP ["; break;
      default:                 ostr << "unknown ["; break;
    }
    sprintf(outstr, "0x%.2x", ip.protocol_id());
    ostr << outstr << "]" << endl;

    ostr << "time to live = " << ip.ttl() << endl;

    sprintf(outstr, "0x%.4x", ip.checksum());
    ostr << "checksum = " << outstr << endl;

    // Display IP addresses
    ostr << "destination IP address = " << ip.destination_ip() << endl;
    ostr << "source IP address = " << ip.source_ip() << endl;

    if (ip.count_options() > 0) {
      ostr << ip.count_options() << " options: " << endl;

      // Display each option
      for (int i = 0; i < ip.count_options(); i++) {
        unsigned int optclass, optnumber, optlen;
        if (ip.option_header(i, optclass, optnumber, optlen))
          ostr << "  option #" << i << ": class = "  << optclass
                        << ", number = " << optnumber;
          switch (optnumber) {
            case 1: ostr << " (nop)"; break;
            case 2: ostr << " (security)"; break;
            case 3: ostr << " (loose source routing)"; break;
            case 4: ostr << " (internet timestamp)"; break;
            case 7: ostr << " (record route)"; break;
            case 8: ostr << " (stream id)"; break;
            case 9: ostr << " (strict source routing)"; break;
          }
          ostr << ", length = " << optlen << endl;
      }
    }
  }

  ostr << flush;

  return ostr;
}

#endif
