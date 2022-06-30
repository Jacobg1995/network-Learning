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
#ifndef DATAGRAM_H
#define DATAGRAM_H

#include <iostream>
#include <pcap.h>              // libpcap (to get bpf_u_int32)

#include "ethernetframe.h"     // EthernetFrame

using namespace std;

/* Datagram: class managing a datagram as an array of bytes.
 *
 * Attributes
 *   p_data : array of bytes
 *   p_len  : size of p_data
 *
 * Notes
 *   1. memory block referenced by p_data is owned by the instance.
 *   2. memory block p_data is often shared with instances of classes derived from
 *      DatagramSegment. So when you destroy an instance of Datagram, make sure
 *      no instance of another class shares its p_data block, otherwise you
 *      may get segmentation faults.
 */
class Datagram {
public:
  Datagram();                                    // default constructor
  Datagram(const u_char *, const bpf_u_int32);   // parameterized constructor
  ~Datagram();                                   // destructor

  unsigned int length();                         // length of p_data in bytes

  // Operator overloading
  Datagram & operator=(const unsigned char *);
  friend ostream & operator<<(ostream &, const Datagram &);

  EthernetFrame ethernet() const;                // returns transported Ethernet datagram *** ML ***

protected:
  unsigned char * p_data;                        // memory block holding datagram bytes
  unsigned int    p_len;                         // length of p_data in bytes
};

#endif

