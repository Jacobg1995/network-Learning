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
#ifndef ETHERNETFRAME_CPP
#define ETHERNETFRAME_CPP

#include "ethernetframe.h"
#include "exceptions.h"    // EBadTransportException

// Default constructor
EthernetFrame::EthernetFrame(bool owned)
  : DatagramFragment(owned) {}

// Parameterized constructor
EthernetFrame::EthernetFrame(bool owned, unsigned char * s, unsigned int l)
  : DatagramFragment(owned, s, l) {}

// Extracts from Ethernet header what protocol this transports in its data
unsigned int EthernetFrame::ether_code() const {
  if (p_data)
    return char2word(p_data+12);    // code stored in two bytes
  else
    return 0;
}

// Extracts from Ethernet header the priority code point (PCP) when this transports
// a 802.1Q frame. This code is stored in the 3 most significant bits of the header's
// 14th byte
unsigned int EthernetFrame::PCP_8021Q() const {
  // Make sure the frame transports 802.1Q
  if (ether_type() != EthernetFrame::et_802_1Q)
    throw EBadTransportException("ethernet frame is not 802.1Q");

  return p_data[14] >> 5;
}

// Extracts from Ethernet header the drop eligible indicator (DEI) when this transports
// a 802.1Q frame. This code is stored in the 4th most significant bit of the header's
// 14th byte
unsigned int EthernetFrame::DEI_8021Q() const {
  // Make sure the frame transports 802.1Q
  if (ether_type() != EthernetFrame::et_802_1Q)
    throw EBadTransportException("ethernet frame is not 802.1Q");

  return (p_data[14] >> 4) & 0x01;
}

// Extracts from Ethernet header the vlan identifier (VID) when this transports
// a 802.1Q frame. This code is stored in the 12 least significant bits of the header's
// 14th and 15th bytes
unsigned int EthernetFrame::VID_8021Q() const {
  // Make sure the frame transports 802.1Q
  if (ether_type() != EthernetFrame::et_802_1Q)
    throw EBadTransportException("ethernet frame is not 802.1Q");

  return (char2word(p_data+14)) & 0x0FFF;
}

// Returns an enum value corresponding to what this transports. Only the most frequent
// layer two protocols arew listed - there are more than one hundred of them in reality!
EthernetFrame::EtherType EthernetFrame::ether_type() const {
  if (ether_code() <= 0x05DC)
    return et_Length;
  else
    switch (ether_code()) {
      case 0x6000 : return et_DEC;
      case 0x0609 : return et_DEC;
      case 0x0600 : return et_XNS;
      case 0x0800 : return et_IPv4;
      case 0x0806 : return et_ARP;
      case 0x8019 : return et_Domain;
      case 0x8035 : return et_RARP;
      case 0x8037 : return et_IPX;
      case 0x809B : return et_AppleTalk;
      case 0x8100 : return et_802_1Q;
      case 0x86DD : return et_IPv6;
      case 0x9000 : return et_loopback;
      default     : return et_other;
  }
}

// Returns the Ethernet header length, which depends on the type of frame
unsigned int EthernetFrame::header_length() const {
  if (!p_data)
    return 0;
  else if (ether_type() == et_802_1Q)
    return 18;
  else
    return 14;
}

// Extracts the destination Mac address from the Ethernet header
MacAddress EthernetFrame::destination_mac() const {
  return MacAddress(false, p_data);
}

// Extracts the source Mac address from the Ethernet header
MacAddress EthernetFrame::source_mac() const {
  return MacAddress(false, p_data+6);
}

// Returns an instance of the IPv4 datagram transported as payload
IPPacket EthernetFrame::ip4() {
    if (ether_type() != et_IPv4)   // make sure it transports IPv4
        throw EBadTransportException("Ethernet frame not transporting IPv4 traffic");

    return IPPacket(false, data(), length() - header_length());
}

// Returns an instance of the ARP datagram transported as payload
ARPPacket EthernetFrame::arp() {
    if (ether_type() != et_ARP)   // make sure it transports ARP
        throw EBadTransportException("Ethernet frame not transporting ARP traffic");

    return ARPPacket(false, data(), length() - header_length());
}

// Output operator displaying the Ethernet header fields in human readable
// form
ostream & operator<<(ostream & ostr, const EthernetFrame & ether) {
  if (ether.p_data) {
    char outstr[8];

    // Display Mac addresses
    ostr << "destination MAC address = " << ether.destination_mac() << endl;
    ostr << "source MAC address = "      << ether.source_mac() << endl;

    // Display the hexadecimal value of the Ethernet code field (i.e. what the frame
    // transports)
    sprintf(outstr, "0x%.4x", ether.ether_code());

    // Display the Ethernet code field in textual form. If it's 802.1Q type, the
    // code identifier is dsiplayed later on
    ostr << "ether type = ";
    switch (ether.ether_type()) {
      case EthernetFrame::et_Length    : ostr << "Length field [" << outstr << "]" << endl; break;
      case EthernetFrame::et_DEC       : ostr << "DEC ["          << outstr << "]" << endl; break;
      case EthernetFrame::et_XNS       : ostr << "XNS ["          << outstr << "]" << endl; break;
      case EthernetFrame::et_IPv4      : ostr << "IPv4 ["         << outstr << "]" << endl; break;
      case EthernetFrame::et_ARP       : ostr << "ARP ["          << outstr << "]" << endl; break;
      case EthernetFrame::et_Domain    : ostr << "Domain ["       << outstr << "]" << endl; break;
      case EthernetFrame::et_RARP      : ostr << "RARP ["         << outstr << "]" << endl; break;
      case EthernetFrame::et_IPX       : ostr << "IPX ["          << outstr << "]" << endl; break;
      case EthernetFrame::et_AppleTalk : ostr << "AppleTalk ["    << outstr << "]" << endl; break;
      case EthernetFrame::et_IPv6      : ostr << "IPv6 ["         << outstr << "]" << endl; break;
      case EthernetFrame::et_loopback  : ostr << "loopback ["     << outstr << "]" << endl; break;
      default                          : ostr << "unknown ["      << outstr << "]" << endl; break;
    }

    // If the frame is 802.1Q, the header contains 4 more bytes (18 instead of 14).
    // We therefore display the extended fields
    if (ether.ether_type() == EthernetFrame::et_802_1Q) {
      sprintf(outstr, "0x%.4x", char2word(ether.p_data+12));
      ostr << "ether type = 802.1Q [" << outstr << "]" << endl;

      ostr << "802.1Q priority code point (PCP) = "     << ether.PCP_8021Q() << endl;
      ostr << "802.1Q drop eligible indicator (DEI) = " << ether.DEI_8021Q() << endl;
      ostr << "802.1Q vlan identifier (VID) = "         << ether.VID_8021Q() << endl;
    }
  }

  ostr << flush;

  return ostr;
}

#endif
