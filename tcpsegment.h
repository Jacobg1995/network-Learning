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
#ifndef TCPSEGMENT_H
#define TCPSEGMENT_H

#include <iostream>

#include "datagramfragment.h"   // DatagramFragment

using namespace std;

/* TCPSegment: class mapping the inherited data block as an TCP segment.
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
class TCPSegment : public DatagramFragment {
  public:
    TCPSegment(bool = false);                             // default constructor
    TCPSegment(bool, unsigned char *, unsigned int);      // parameterized constructor

    unsigned int header_length() const;                   // length of TCP segment header in bytes

    unsigned int source_port() const;                     // source port
    unsigned int destination_port() const;                // destination port

    unsigned int sequence_nb() const;                     // access to sequence number field
    unsigned int ack_nb() const;                          // access to acknowledgment number field

    unsigned int offset() const;                          // access to data offset field
    unsigned int reserved() const;                        // access to reserve field

    bool flag_ns() const;                                 // access to NS flag
    bool flag_cwr() const;                                // access to CWR flag
    bool flag_ece() const;                                // access to ECE flag
    bool flag_urg() const;                                // access to URG flag
    bool flag_ack() const;                                // access to ACK flag
    bool flag_psh() const;                                // access to PSH flag
    bool flag_rst() const;                                // access to RST flag
    bool flag_syn() const;                                // access to SYN flag
    bool flag_fin() const;                                // access to FIN flag

    unsigned int window_size() const;                     // access to window size field
    unsigned int checksum() const;                        // access to checksum field
    unsigned int pointer_urg() const;                     // access to urgent pointer field

    // Operator overloads
    friend ostream & operator<<(ostream &, const TCPSegment &);

  protected:

    // Returns a string textually identifying standard ports
    const char * port_name(unsigned int) const;
};

#endif
