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
#ifndef MACADDRESS_H
#define MACADDRESS_H

#include <iostream>

#include "datagramfragment.h"   // DatagramFragment

using namespace std;

/* MacAddress: class mapping the inherited data block as a MAC address.
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
class MacAddress : public DatagramFragment {
  public:
    MacAddress(bool = false);                  // default constructor
    MacAddress(bool, unsigned char *);         // parameterized constructor

    unsigned int header_length() const;        // length of MAC address in bytes

    bool valid() const;                        // indicates if it's a valid device address

    // Operator overloads
    friend ostream & operator<<(ostream &, const MacAddress &);

    bool operator==(const MacAddress &) const;
    bool operator<(const MacAddress &) const;
};

#endif
