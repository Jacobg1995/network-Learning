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
#ifndef IPPACKET_H
#define IPPACKET_H

#include <iostream>

#include "datagramfragment.h"   // DatagramFragment
#include "ipaddress.h"          // IPAddress
#include "icmppacket.h"         // ICMPPacket
#include "tcpsegment.h"         // TCPSegment
#include "udpsegment.h"         // UDPSegment

using namespace std;

/* IPPacket: class mapping the inherited data block as an IP packet.
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
class IPPacket : public DatagramFragment {
  public:
    // Enumeration of most commonly transported protocols
    typedef enum {
      ipp_icmp, ipp_igmp, ipp_udp, ipp_tcp, ipp_other, ipp_none
    } IPProtocol;

    IPPacket(bool = false);                            // default constructor
    IPPacket(bool, unsigned char *, unsigned int);     // parameterized constructor

    unsigned int header_length() const;                // length of IP packet header in bytes

    // Routines returning header field values
    unsigned int version() const;                      // access to Version field
    unsigned int ihl() const;                          // access to IHL field
    unsigned int tos() const;                          // access to Type Of Service field
    unsigned int total_length() const;                 // access to Total Length field

    unsigned int fragment_id() const;                  // access to Fragmentation ID field
    unsigned int fragment_flags() const;               // access to Fragmentation flags
    unsigned int fragment_pos() const;                 // access to Fragmentation position field

    bool fragmented(bool &, bool &) const;             // indicates if datagram is fragmented

    unsigned int ttl() const;                          // access to Time To Live field
    unsigned int checksum() const;                     // access to Checksum field

    unsigned int protocol_id() const;                  // access to Protocol field
    IPProtocol protocol() const;                       // protocol transported in payload

    // Access to IP header options, if any
    unsigned int count_options() const;
    bool option_header(unsigned int, unsigned int &, unsigned int &, unsigned int &) const;

    // Return IP addresses within the header
    IPAddress destination_ip() const;
    IPAddress source_ip() const;

    ICMPPacket icmp();                                 // returns ICMP packet transported in payload
    TCPSegment tcp();                                  // returns TCP segment transported in payload
    UDPSegment udp();                                  // returns UDP segment transported in payload

    // Operator overloads
    friend ostream & operator<<(ostream &, const IPPacket &);

  protected:
};

#endif
