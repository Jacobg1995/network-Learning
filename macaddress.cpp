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
#ifndef MACADDRESS_CPP
#define MACADDRESS_CPP

#include "macaddress.h"

#define MAC_LEN 6        // length of MAC address in bytes

// Default constructor
MacAddress::MacAddress(bool owned)
  : DatagramFragment(owned) {}

// Parameterized constructor
MacAddress::MacAddress(bool owned, unsigned char * s)
  : DatagramFragment(owned, s, MAC_LEN) {}

// Returns length of MAC address (6 bytes)
unsigned int MacAddress::header_length() const {
  return MAC_LEN;
}

// Returns true if this is a device MAC address (i.e. not 0 of broadcast)
bool MacAddress::valid() const {
  for (unsigned int i = 0; i < this->length(); i++)
    if (this->p_data[i] == 0x00 || this->p_data[i] == 0xFF)
      return false;

  return true;
}

// Output operator displaying the MAC address in dot form (XX.XX.XX.XX.XX.XX)
ostream & operator<<(ostream & ostr, const MacAddress & mac) {
  char outstr[3];

  for (unsigned int i = 0; i < mac.length(); i++) {
    sprintf(outstr, "%.2x", mac.p_data[i]);
    ostr << outstr;
    if (i < mac.length()-1) ostr << '.';
  }

  return ostr;
}

// Relational operator comparing MAC addresses at byte level
bool MacAddress::operator==(const MacAddress &mac) const {
  if (this->length() != mac.length())
    return false;
  else {
    for (unsigned int i = 0; i < this->length(); i++)
       if (this->p_data[i] != mac.p_data[i])
          return false;

    return true;
  }
}

// Relational operator comparing MAC addresses at byte level
bool MacAddress::operator<(const MacAddress &mac) const {
  unsigned int len = (mac.length() < this->length() ? mac.length() : this->length());

  for (unsigned int i = 0; i < len; i++)
    if (this->p_data[i] < mac.p_data[i])
      return true;
    else if (this->p_data[i] > mac.p_data[i])
      return false;

  return this->length() < mac.length();
}

#endif
