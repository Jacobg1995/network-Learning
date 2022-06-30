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
#ifndef DATAGRAM_CPP
#define DATAGRAM_CPP

#include <cstring>      // copy
#include "datagram.h"

// Default constructor
Datagram::Datagram() {
  p_data = NULL;
  p_len  = 0;
}

// Parameterized constructor
Datagram::Datagram(const u_char *pkt, const bpf_u_int32 l) {
  p_data = new unsigned char[l];

  // Copy memory block
  std::copy(pkt, pkt+l, p_data);
  p_len = l;
}

// Destructor
Datagram::~Datagram() {
  delete [] p_data;
}

// Returns number of bytes in datagram.
unsigned int Datagram::length() {
  return p_len;
}

// Assignment operator accepting a char array as source.
Datagram & Datagram::operator=(const unsigned char * s) {
  if (p_data)
    memcpy(p_data, s, length());

  return *this;
}

// Output operator displaying bytes of datagram in hexadecimal and textual forms.
ostream & operator<<(ostream & ostr, const Datagram & pkt) {
  const int LEN = 16;            // number of bytes to display per line
  char      outstr[8],           // for output formatting purposes
            ascii[LEN];          // holds textual bytes for a line

  // Display all bytes in hexadecimal and textual forms
  for (unsigned int i = 0; i < pkt.p_len; i++) {
    // Do we need to change line?
    if (i%LEN == 0) {
      // Before moving to the next line, display accumulated bytes in character form
      if (i > 0) {
        ostr << "  ";
        for (int j = 0; j < LEN; j++) ostr << ascii[j];
      }

      // Change line and display position of next byte in p_data
      sprintf(outstr, "%.4d: ", i);
      ostr << endl << outstr;
    }

    // Display byte in hexadecimal
    sprintf(outstr, "%.2x ", (unsigned char)pkt.p_data[i]);
    ostr << outstr;

    // Format byte for textual form
    ascii[i%LEN] = ((pkt.p_data[i] >= 32 && pkt.p_data[i] <= 126) ? pkt.p_data[i] : '.');
  }

  // Display last line of bytes in textual form
  for (int i = LEN - pkt.p_len % LEN; i > 0; i--) ostr << "   ";
  ostr << "  ";
  for (unsigned int j = 0; j < pkt.p_len % LEN; j++) ostr << ascii[j];

  return ostr;
}

// Returns an EthernetFrame instance mapped onto the transported data *** ML ***
EthernetFrame Datagram::ethernet() const {
  return EthernetFrame(false, p_data, p_len);
}

#endif
