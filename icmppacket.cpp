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
#ifndef ICMPPACKET_CPP
#define ICMPPACKET_CPP

#include "icmppacket.h"  // ICMPPacket
#include "exceptions.h"  // EBadTransportException

// Default constructor
ICMPPacket::ICMPPacket(bool owned) : DatagramFragment(owned) {
}

// Parameterized constructor
ICMPPacket::ICMPPacket(bool owned, unsigned char * s, unsigned int l) : DatagramFragment(owned, s, l) {
}

// Returns the ICMP header length in bytes
unsigned int ICMPPacket::header_length() const {
  if (!p_data)
    return 0;
  else
    return 8;
}

// Returns a textual description of the packet according to its type and code fields
const char * ICMPPacket::description() const {
  unsigned int msg_id = type() << 8 + code();

  switch (msg_id) {
    case 0x0000 : return "echo reply";
    case 0x0300 : return "network unreachable";
    case 0x0301 : return "host unreachable";
    case 0x0302 : return "protocol unreachable";
    case 0x0303 : return "port unreachable";
    case 0x0304 : return "fragmentation needed and Don't Fragment flag set";
    case 0x0305 : return "source route failed";
    case 0x0306 : return "destination network unknown";
    case 0x0307 : return "destination host unknown";
    case 0x0308 : return "source host isolated";
    case 0x0309 : return "communication with destination network is administratively prohibited";
    case 0x030A : return "communication with destination host is administratively prohibited";
    case 0x030B : return "destination network unreachable for type of service";
    case 0x030C : return "destination host unreachable for type of service";
    case 0x030D : return "communication administratively prohibited ";
    case 0x030E : return "host precedence violation";
    case 0x030F : return "precedence cutoff in effect";
    case 0x0400 : return "source quench";
    case 0x0500 : return "redirect datagram for the network (or subnet)";
    case 0x0501 : return "redirect datagram for the host";
    case 0x0502 : return "redirect datagram for the type of service and network";
    case 0x0503 : return "redirect datagram for the type of service and host";
    case 0x0600 : return "alternate address for host";
    case 0x0800 : return "echo request";
    case 0x0900 : return "normal router advertisement";
    case 0x0910 : return "does not route common traffic";
    case 0x0A00 : return "router selection";
    case 0x0B00 : return "time to live exceeded in transit";
    case 0x0B01 : return "fragment reassembly time exceeded";
    case 0x0C00 : return "pointer indicates the error";
    case 0x0C01 : return "missing a required option";
    case 0x0C02 : return "bad length";
    case 0x0D00 : return "timestamp";
    case 0x0E00 : return "timestamp reply";
    case 0x0F00 : return "information request";
    case 0x1000 : return "information reply";
    case 0x1100 : return "address mask request";
    case 0x1200 : return "address mask reply";
    case 0x1300 : return "reserved (for security)";
    case 0x1E00 : return "traceroute";
    case 0x1F00 : return "datagram conversion error";
    default     : return "unknown ICMP packet";
  }
}

// Returns content of type header field
unsigned int ICMPPacket::type() const {
  return p_data[0];
}

// Returns content of code header field
unsigned int ICMPPacket::code() const {
  return p_data[1];
}

// Returns content of checksum header field
unsigned int ICMPPacket::checksum() const {
  return char2word(p_data+2);
}

// Returns content of identifier header field for type 13, 14, 17 or 18 ICMP packets
unsigned int ICMPPacket::identifier() const {
  if (code() == 0 || (type() == 13 || type() == 14 || type() == 17 || type() == 18))
    return char2word(p_data+4);
  else
    throw EBadTransportException("ICMP packet does not hold identifier field");
}

// Returns content of sequence number header field for 13, 14, 17 or 18 ICMP packets
unsigned int ICMPPacket::sequence_number() const {
  if (code() == 0 || (type() == 13 || type() == 14 || type() == 17 || type() == 18))
    return char2word(p_data+6);
  else
    throw EBadTransportException("ICMP packet does not hold sequence number field");
}

// Returns content of next-hop MTU header field for type 3 ICMP packets
unsigned int ICMPPacket::next_hop_MTU() const {
  if (type() == 3)
    return char2word(p_data+6);
  else
    throw EBadTransportException("ICMP packet does not hold next-hop MTU field");
}

// Returns content of originate timestamp header field for type 13 or 14 ICMP packets
unsigned int ICMPPacket::originate_timestamp() const {
  if (code() == 0 && (type() == 13 || type() == 14))
    return char4word(p_data+8);
  else
    throw EBadTransportException("ICMP packet does not hold originate timestamp field");
}

// Returns content of receive timestamp header field for type 14 ICMP packets
unsigned int ICMPPacket::receive_timestamp() const {
  if (code() == 0 && type() == 14)
    return char4word(p_data+12);
  else
    throw EBadTransportException("ICMP packet does not hold receive timestamp field");
}

// Returns content of transmit timestamp header field for type 14 ICMP packets
unsigned int ICMPPacket::transmit_timestamp() const {
  if (code() == 0 && type() == 14)
    return char4word(p_data+16);
  else
    throw EBadTransportException("ICMP packet does not hold transmit timestamp field");
}

// Returns content of IP address header field for type 5 ICMP packets
IPAddress ICMPPacket::ipaddress() const {
  if (type() == 5)
    return IPAddress(false, p_data + 4);
  else
    throw EBadTransportException("ICMP packet does not hold IP address field");
}

// Returns content of address mask header field for type 17 or 18 ICMP packets
IPAddress ICMPPacket::address_mask() const {
  if (code() == 0 && (type() == 17 || type() == 18))
    return IPAddress(false, p_data + 8);
  else
    throw EBadTransportException("ICMP packet does not hold address mask field");
}

// Output operator displaying the ICMP packet header fields in human readable
// form
ostream & operator<<(ostream & ostr, const ICMPPacket & icmp) {
  if (icmp.p_data) {
    char outstr[8];

    // Display common header fields
    ostr << "type/code = " << icmp.type() << "/" << icmp.code() << " ("
         << icmp.description() << ")" << endl;

    sprintf(outstr, "0x%.4x", icmp.checksum());
    ostr << "checksum = " << outstr << endl;

    // Display specialized header fields which depend on type and code values
    // We catch any thrown exceptions

    // Display identifier and sequence number fields for packets of type 13,
    // 14, 17 or 18
    try {
      unsigned int identif = icmp.identifier();
      unsigned int seqnum  = icmp.sequence_number();

      sprintf(outstr, "0x%.4x", identif);
      ostr << "identifier = " << outstr << endl;
      ostr << "sequence number = " << seqnum << endl;
    }
    catch (EBadTransportException) {
    }

    // Display next-hop MTU field for packets of type 3
    try {
      unsigned int nexthop = icmp.next_hop_MTU();
      ostr << "sequence number = " << nexthop << endl;
    }
    catch (EBadTransportException) {
    }

    // Display IP address field for packets of type 5
    try {
      IPAddress addr = icmp.ipaddress();
      ostr << "IP address = " << addr << endl;
    }
    catch (EBadTransportException) {
    }
  }

  ostr << flush;

  return ostr;
}

#endif
