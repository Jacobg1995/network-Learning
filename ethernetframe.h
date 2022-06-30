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
#ifndef ETHERNETFRAME_H
#define ETHERNETFRAME_H

#include <iostream>

#include "datagramfragment.h"   // DatagramFragment
#include "macaddress.h"         // MacAddress
#include "ippacket.h"           // IPPacket
#include "arppacket.h"          // ARPPacket

using namespace std;

/* EthernetFrame: class mapping the inherited data block as an Ethernet frame.
 *
 * Attributes
 *   p_data (inherited) : array of bytes
 *   p_len (inherited)  : size of p_data
 *
 * Notes
 *   1. the data block referenced by p_data may not be owned by the instance
 *      but instead owned by a Datagram instance which shares its data with
 *      instances of classes derived from DatagramFragment, including this
 *      class.
 */
class EthernetFrame : public DatagramFragment {
public:
  // Enumeration of major higher layer protocols which may be transported
  // by the instance
  typedef enum {
    et_Length, et_DEC, et_XNS, et_IPv4, et_ARP, et_Domain, et_RARP, et_IPX,
    et_AppleTalk, et_802_1Q, et_IPv6, et_loopback, et_other, et_none
  } EtherType;

  EthernetFrame(bool = false);                            // default constructor
  EthernetFrame(bool, unsigned char *, unsigned int);     // parameterized constructor

  // Returns Mac adresses within the frame header
  MacAddress destination_mac() const;
  MacAddress source_mac() const;

  // Returns ethernet header fields content
  EtherType ether_type() const;
  unsigned int ether_code() const;

  // Returns 802.1Q fields (if any)
  unsigned int PCP_8021Q() const;
  unsigned int DEI_8021Q() const;
  unsigned int VID_8021Q() const;

  unsigned int header_length() const;        // number of bytes making the datagram's header

  IPPacket ip4();                            // returns IP packet transported in payload
  ARPPacket arp();                           // returns ARP packet transported in payload

  // Operator overloading
  friend ostream & operator<<(ostream &, const EthernetFrame &);
};

#endif
