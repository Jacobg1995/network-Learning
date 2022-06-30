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
#ifndef IPADDRESS_H
#define IPADDRESS_H

#include <iostream>

#include "datagramfragment.h"

using namespace std;

/* IPAddress: class mapping the inherited data block as an IP address.
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
class IPAddress : public DatagramFragment {
  public:
    IPAddress(bool = false);               // default constructor
    IPAddress(bool, unsigned char *);      // parameterized constructor

    unsigned int header_length() const;    // length of IP address in bytes

    bool valid() const;                    // indicates if it's a valid IP address

    // Operator overloads
    friend ostream & operator<<(ostream &, const IPAddress &);

    bool operator==(const IPAddress &) const;
    bool operator<(const IPAddress &) const;

  protected:
};

#endif
