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
#ifndef DATAGRAMFRAGMENT_H
#define DATAGRAMFRAGMENT_H

#include <iostream>
#include <cstring>
#include <cstdio>

using namespace std;

/* DatagramFragment: abstract class serving as base class for other classes
 *   implementing TCP/IP protocol headers. The instances of these classes
 *   usually share their data block with a Datagram instance which actually
 *   owns the data block.
 *
 * Attributes
 *   p_data : array of bytes
 *   p_len  : size of p_data
 *
 * Notes
 *   1. the data block referenced by p_data may not be owned by the instance
 *      but instead owned by a Datagram instance which shares its data with
 *      instances of classes derived from DatagramFragment.
 */
class DatagramFragment {
  public:
    DatagramFragment(bool = false);                            // default constructor
    DatagramFragment(const DatagramFragment &);                // copy constructor
    DatagramFragment(bool, unsigned char *, unsigned int);     // parameterized constructor
    ~DatagramFragment();                                       // destructor

    virtual unsigned int length() const;                       // length of p_data in bytes
    virtual unsigned int header_length() const = 0;            // number of bytes making the datagram's header

    // Various getters
    virtual unsigned char * data();
    virtual unsigned char * header();

    // Operator overloading
    DatagramFragment & operator=(const unsigned char *);
    DatagramFragment & operator=(const DatagramFragment &);

    bool operator==(const DatagramFragment &);

    friend ostream & operator<<(ostream &, const DatagramFragment &);

  protected:
    unsigned char * p_data;        // memory block holding datagram bytes
    unsigned int    p_len;         // length of p_data in bytes

  private:
    bool p_owned;                  // indicates if the p_data block is owned by the instance
};

unsigned int char2word(const unsigned char *p);    // utility function to extract an unsigned int from 2 bytes
unsigned int char4word(const unsigned char *p);    // utility function to extract an unsigned int from 4 bytes

#endif
