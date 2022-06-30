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
#ifndef ARPPACKET_H
#define ARPPACKET_H

#include <iostream>
#include <stdio.h>

#include "datagramfragment.h"   // DatagramFragment
#include "macaddress.h"         // Mac
#include "ipaddress.h"          // IPAddress

using namespace std;

/* ARPPacket: class mapping the inherited data block as an ARP packet.
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
class ARPPacket : public DatagramFragment {
  public:
    // Enumeration of hardware address types
    typedef enum {
      aht_Ethernet, aht_FrameRelay, aht_ATM, aht_IPSec, aht_unknown
    } ARPHardwareType;

    // Enumeration of protocol address types
    typedef enum {
      apt_IPv4, apt_IPX, apt_802_1Q, apt_IPv6, apt_unknown
    } ARPProtocolType;

    // Enumeration of ARP operations
    typedef enum {
      akt_ArpRequest, akt_ArpReply, akt_RarpRequest, akt_RarpReply, akt_unknown
    } ARPPacketType;

    ARPPacket(bool = false);                              // constructor
    ARPPacket(bool, unsigned char *, unsigned int);       // parameterized constructor

    unsigned int header_length() const;                   // length of ARP packet header in bytes

    // Routines returning header field values
    ARPPacketType operation() const;
    unsigned int operation_code() const;

    ARPHardwareType hardware_type() const;
    unsigned int hardware_type_code() const;

    ARPProtocolType protocol_type() const;
    unsigned int protocol_type_code() const;

    unsigned int hardware_adr_length() const;
    unsigned int protocol_adr_length() const;

    // Returns hardware addresses found in the header
    MacAddress destination_mac() const;
    MacAddress source_mac() const;

    // Returns protocol addresses found in the header
    IPAddress destination_ip() const;
    IPAddress source_ip() const;

    // Operator overloads
    friend ostream & operator<<(ostream &, const ARPPacket &);

    protected:
};

#endif
