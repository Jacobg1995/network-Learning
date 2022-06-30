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
#ifndef IPADDRESS_CPP
#define IPADDRESS_CPP

#include "ipaddress.h"

#define IPADR_LEN 4    // length of IP address in bytes

// Default constructor
IPAddress::IPAddress(bool owned) : DatagramFragment(owned) {
}

// Parameterized constructor
IPAddress::IPAddress(bool owned, unsigned char * s) : DatagramFragment(owned, s, IPADR_LEN) {
}

// Returns length of MAC address (4 bytes)
unsigned int IPAddress::header_length() const {
  return IPADR_LEN;
}

// Returns true if this is a device IP address (i.e. not 0 of broadcast)
bool IPAddress::valid() const {
  for (unsigned int i = 0; i < this->length(); i++)
    if (this->p_data[i] != 0x00 && this->p_data[i] != 0xFF)
      return true;

  return false;
}

// Output operator displaying the IP address in dot form  (X.X.X.X)
ostream & operator<<(ostream & ostr, const IPAddress & adr) {
  char outstr[4];

  for (unsigned int i = 0; i < adr.length(); i++) {
    sprintf(outstr, "%d", adr.p_data[i]);
    ostr << outstr;

    if (i < adr.length()-1) ostr << '.';
  }

  return ostr;
}

// Relational operator comparing IP addresses at byte level
bool IPAddress::operator==(const IPAddress &adr) const {
  if (this->length() != adr.length())
    return false;
  else {
    for (unsigned int i = 0; i < this->length(); i++)
      if (this->p_data[i] != adr.p_data[i])
        return false;

    return true;
  }
}

// Relational operator comparing IP addresses at byte level
bool IPAddress::operator<(const IPAddress &adr) const {
  unsigned int len = (adr.length() < this->length() ? adr.length() : this->length());

  for (unsigned int i = 0; i < len; i++)
    if (this->p_data[i] < adr.p_data[i])
      return true;
    else if (this->p_data[i] > adr.p_data[i])
      return false;

  return this->length() < adr.length();
}

#endif
