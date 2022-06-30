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
#ifndef UDPSEGMENT_H
#define UDPSEGMENT_H

#include <iostream>

#include "datagramfragment.h"   // DatagramFragment
#include "tftp.h"               // TFTPDatagram

using namespace std;

/* UDPSegment: class mapping the inherited data block as an UDP segment.
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
class UDPSegment : public DatagramFragment {
  public:
    UDPSegment(bool = false);                             // default constructor
    UDPSegment(bool, unsigned char *, unsigned int);      // parameterized constructor

    unsigned int header_length() const;                   // length of UDP segment header in bytes

    unsigned int source_port() const;                     // source port
    unsigned int destination_port() const;                // destination port

    unsigned int len() const;                             // access to length field
    unsigned int checksum() const;                        // access to checksum field

    TFTPDatagram tftp();                                  // returns TFTP datagram transported in payload

    // Operator overloads
    friend ostream & operator<<(ostream &, const UDPSegment &);

  protected:

    // Returns a string textually identifying standard ports
    const char * port_name(unsigned int) const;
};

#endif
