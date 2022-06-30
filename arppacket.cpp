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
#ifndef ARPPACKET_CPP
#define ARPPACKET_CPP

#include "arppacket.h"   // ARPPacket
#include "exceptions.h"  // EBadTransportException

// Default constructor
ARPPacket::ARPPacket(bool owned) : DatagramFragment(owned) {
}

// Parameterized constructor
ARPPacket::ARPPacket(bool owned, unsigned char * s, unsigned int l) : DatagramFragment(owned, s, l) {
}

// Returns the IP header length in bytes
unsigned int ARPPacket::header_length() const {
  if (!p_data)
    return 0;
  else
    return hardware_adr_length() * 2 + protocol_adr_length() * 2 + 8;
}

// Returns the destination hardware address field's content
MacAddress ARPPacket::destination_mac() const {
  if (hardware_type() == ARPPacket::aht_Ethernet)
    return MacAddress(false, p_data + 8 + hardware_adr_length() + protocol_adr_length());
  else
    throw EBadHardwareException("Hardware layer not Ethernet based");
}

// Returns the source hardware address field's content
MacAddress ARPPacket::source_mac() const {
  if (hardware_type() == ARPPacket::aht_Ethernet)
    return MacAddress(false, p_data + 8);
  else
    throw EBadHardwareException("Hardware layer not Ethernet based");
}

// Returns the destination protocol address field's content
IPAddress ARPPacket::destination_ip() const {
  if (protocol_type() == ARPPacket::apt_IPv4)
    return IPAddress(false, p_data + 8 + hardware_adr_length() * 2 + protocol_adr_length());
  else
    throw EBadTransportException("Protocol layer not IPv4 based");
}

// Returns the source protocol address field's content
IPAddress ARPPacket::source_ip() const {
  if (protocol_type() == ARPPacket::apt_IPv4)
    return IPAddress(false, p_data + 8 + hardware_adr_length());
  else
    throw EBadTransportException("Protocol layer not IPv4 based");
}

// Indicates what ARP operation the packet transports
ARPPacket::ARPPacketType ARPPacket::operation() const {
  switch (operation_code()) {
    case 0x0001 : return akt_ArpRequest;
    case 0x0002 : return akt_ArpReply;
    case 0x0003 : return akt_RarpRequest;
    case 0x0004 : return akt_RarpReply;
    default     : return akt_unknown;
  }
}

// Indicates what ARP operation the packet transports
unsigned int ARPPacket::operation_code() const {
  if (p_data)
    return char2word(p_data+6);    // operation code stored in two bytes
  else
    return 0;
}

// Indicates the hardware layer type
ARPPacket::ARPHardwareType ARPPacket::hardware_type() const {
  switch (hardware_type_code()) {
    case 0x0001 : return aht_Ethernet;
    case 0x000F : return aht_FrameRelay;
    case 0x0010 :
    case 0x0013 :
    case 0x0015 : return aht_ATM;
    case 0x001F : return aht_IPSec;
    default     : return aht_unknown;
  }
}

// Indicates the hardware layer type
unsigned int ARPPacket::hardware_type_code() const {
  if (p_data)
    return char2word(p_data+0);    // hardware layer type stored in two bytes
  else
    return 0;
}

// Indicates the protocol layer type
ARPPacket::ARPProtocolType ARPPacket::protocol_type() const {
  switch (protocol_type_code()) {
    case 0x0800 : return apt_IPv4;
    case 0x8037 : return apt_IPX;
    case 0x8100 : return apt_802_1Q;
    case 0x86DD : return apt_IPv6;
    default     : return apt_unknown;
  }
}

// Indicates the protocol layer type
unsigned int ARPPacket::protocol_type_code() const {
  if (p_data)
    return char2word(p_data+2);    // protocol layer type stored in two bytes
  else
    return 0;
}

// Returns hardware addresses length in bytes
unsigned int ARPPacket::hardware_adr_length() const {
  if (p_data)
    return p_data[4];
  else
    return 0;
}

// Returns protocol addresses length in bytes
unsigned int ARPPacket::protocol_adr_length() const {
  if (p_data)
    return p_data[5];
  else
    return 0;
}

// Output operator displaying the ARP packet header fields in human readable
// form
ostream & operator<<(ostream & ostr, const ARPPacket & arp) {
  if (arp.p_data) {
    char outstr[7];

    // Get operation code
    sprintf(outstr, "0x%.4x", arp.operation_code());

    // Display operation textually along its corresponding code
    ostr << "packet type = ";
    switch (arp.operation()) {
      case ARPPacket::akt_ArpRequest  : ostr << "ARP request ["  << outstr << "]" << endl; break;
      case ARPPacket::akt_ArpReply    : ostr << "ARP reply ["    << outstr << "]" << endl; break;
      case ARPPacket::akt_RarpRequest : ostr << "RARP request [" << outstr << "]" << endl; break;
      case ARPPacket::akt_RarpReply   : ostr << "RARP reply ["   << outstr << "]" << endl; break;
      default                         : ostr << "unknown ["      << outstr << "]" << endl; break;
    }

    // Display hardware addresses
    ostr << "destination MAC address = " << arp.destination_mac() << endl;
    ostr << "source MAC address = " << arp.source_mac() << endl;

    // Display protocol addresses
    ostr << "destination IP address = " << arp.destination_ip() << endl;
    ostr << "source IP address = " << arp.source_ip() << endl;

    // Get hardware type
    sprintf(outstr, "0x%.4x", arp.hardware_type_code());

    // Display hardware type textually along ints corresponding code
    ostr << "hardware type = ";
    switch (arp.hardware_type()) {
      case ARPPacket::aht_Ethernet   : ostr << "Ethernet ["                             << outstr << "]" << endl; break;
      case ARPPacket::aht_FrameRelay : ostr << "Frame Relay ["                          << outstr << "]" << endl; break;
      case ARPPacket::aht_ATM        : ostr << "Asynchronous Transmission Mode (ATM) [" << outstr << "]" << endl; break;
      case ARPPacket::aht_IPSec      : ostr << "IPSec tunnel ["                         << outstr << "]" << endl; break;
      default                        : ostr << "unknown ["                              << outstr << "]" << endl; break;
    }

    // Get protocol type
    sprintf(outstr, "0x%.4x", arp.protocol_type_code());

    // Display protocol type textually along ints corresponding code
    ostr << "protocol type = ";
    switch (arp.protocol_type()) {
      case ARPPacket::apt_IPv4   : ostr << "IPv4 ["         << outstr << "]" << endl; break;
      case ARPPacket::apt_IPX    : ostr << "IPX ["          << outstr << "]" << endl; break;
      case ARPPacket::apt_802_1Q : ostr << "IEEE 802.1Q) [" << outstr << "]" << endl; break;
      case ARPPacket::apt_IPv6   : ostr << "IPv6 ["         << outstr << "]" << endl; break;
      default                    : ostr << "unknown ["      << outstr << "]" << endl; break;
    }
  }

  ostr << flush;

  return ostr;
}

#endif
