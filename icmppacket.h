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
#ifndef ICMPPACKET_H
#define ICMPPACKET_H

#include <iostream>

#include "datagramfragment.h"   // DatagramFragment
#include "ipaddress.h"          // IPAddress

using namespace std;

/* ICMPPacket: class mapping the inherited data block as an ICMP packet.
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
class ICMPPacket : public DatagramFragment {
  public:
    ICMPPacket(bool = false);                             // constructor
    ICMPPacket(bool, unsigned char *, unsigned int);      // parameterized constructor

    unsigned int header_length() const;                   // length of ARP packet header in bytes

    const char * description() const;                     // returns a textual description of ICMP packet

    // Routines returning common header field values
    unsigned int type() const;
    unsigned int code() const;
    unsigned int checksum() const;

    // Routines returning header field values depending on packet type
    unsigned int identifier() const;
    unsigned int sequence_number() const;

    unsigned int originate_timestamp() const;
    unsigned int receive_timestamp() const;
    unsigned int transmit_timestamp() const;

    unsigned int next_hop_MTU() const;

    IPAddress    ipaddress() const;
    IPAddress    address_mask() const;

    // Operator overloads
    friend ostream & operator<<(ostream &, const ICMPPacket &);

  protected:
};

#endif
