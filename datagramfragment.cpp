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
#ifndef DATAGRAMFRAGMENT_CPP
#define DATAGRAMFRAGMENT_CPP

#include "datagramfragment.h"

// Default constructor
DatagramFragment::DatagramFragment(bool owned)
  : p_data(NULL), p_len(0), p_owned(owned) {}

// Copy constructor
DatagramFragment::DatagramFragment(const DatagramFragment & d)
  : p_data(NULL), p_len(0), p_owned(d.p_owned) {
  *this = d;
}

// Parameterized constructor
DatagramFragment::DatagramFragment(bool owned, unsigned char * s, unsigned int l)
  : p_len(l) {
  p_owned = owned;

  // Check if this owns its data block
  if (p_owned) {
    // If so, copy s into a new data block
    p_data = new unsigned char[l];
    memcpy(p_data, s, l);
  }
  else
    p_data = s;  // this shares the given data block
}

// Destructor - required because this may owns its data block
DatagramFragment::~DatagramFragment() {
    if (p_owned && p_data)
        delete [] p_data;
}

// Returns number of bytes in datagram
unsigned int DatagramFragment::length() const {
    return p_len;
}

// Returns a pointer to beginning of transported data (passed the header)
unsigned char * DatagramFragment::data() {
    if (header_length() < length())        // make sure the datagram has data bytes
        return p_data + header_length();
    else
        return NULL;
}

// Returns a pointer to beginning of datagram header
unsigned char * DatagramFragment::header() {
    return p_data;
}

// Assignment operator receiving datagram bytes through an array of chars
DatagramFragment & DatagramFragment::operator=(const unsigned char * s) {
    if (p_data)
        memcpy(p_data, s, p_len);

    return *this;
}

// Assignment operator receiving datagram bytes from another instance
DatagramFragment & DatagramFragment::operator=(const DatagramFragment & d) {
    // Prevent self assignment
    if (this == &d)
        return *this;

    // If the given instance owns its data block, this will also do
    if (d.p_owned) {
        // Free this' data block if need be
        if (p_owned && p_data)
            delete [] p_data;

        // this will own its data block
        p_owned = true;

        // Copy data block from given instance to this
        if (d.p_data && d.p_len) {
            p_len  = d.p_len;
            p_data = new unsigned char[p_len];

            memcpy(p_data, d.p_data, p_len);
        }
        else {
            p_data = NULL;
            p_len  = 0;
        }
    }
    else  {                  // otherwise this will share the given instance's data block
        p_data  = d.p_data;
        p_len   = d.p_len;
        p_owned = false;
    }

    return *this;
}

// Relational equality operator
bool DatagramFragment::operator==(const DatagramFragment & d) {
    // Are equals if same length and same byte values
    if (p_len == d.p_len) {
        for (unsigned int i = 0; i < p_len; i++)
            if (p_data[i] != d.p_data[i]) return false;

        return true;
    }
    else
        return false;
}

// Output operator displaying bytes of datagram in hexadecimal form. This operator
// will usually be overloaded in derived classes to interpret datagram headers
ostream & operator<<(ostream & ostr, const DatagramFragment & d) {
    char outstr[4];

    // Display datagram bytes in a single line
    for (unsigned int i = 0; i < d.length(); i++) {
        sprintf(outstr, "%.2x ", (unsigned char)d.p_data[i]);
        ostr << outstr;
    }

    return ostr;
}

// Utility function to extract an unsigned int from 2 bytes
unsigned int char2word(const unsigned char *p) {
    unsigned int i = p[0];
    return i << 8 | p[1];
}

// Utility function to extract an unsigned int from 4 bytes
unsigned int char4word(const unsigned char *p) {
    unsigned int res = p[0];

    res = res << 8 | p[1];
    res = res << 8 | p[2];
    res = res << 8 | p[3];

    return res;
}

#endif
