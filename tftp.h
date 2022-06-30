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
#ifndef TFTP_H
#define TFTP_H

#include <iostream>

#include "datagramfragment.h"   // DatagramFragment

using namespace std;

// Definition de classe representant un datagramme TFTP
class TFTPDatagram : public DatagramFragment {
  public:
    // enumeration des codes d'operation du protocole TFTP
    typedef enum {
      tftp_wrq, tftp_rrq, tftp_data, tftp_ack, tftp_error, tftp_none
    }   TFTPOperation;

    TFTPDatagram(bool = false);                          // default constructor
    TFTPDatagram(bool, unsigned char *, unsigned int);   // parameterized constructor

    unsigned int header_length() const;                  // length of TFTP datagram header in bytes

    TFTPOperation operation() const;                     // operation code

    char * filename() const;                             // filename field in RRQ and WRQ datagrams
    char * mode() const;                                 // mode field in RRQ and WRQ datagrams

    unsigned int error_code() const;                     // error code in ERROR datagrams
    char * error_msg() const;                            // error message in ERROR datagrams

    unsigned int block() const;                          // block number in DATA datagrams
    unsigned int data_length() const;                    // bytes of data in DATA datagrams

    // Operator overloads
    friend ostream & operator<<(ostream &, const TFTPDatagram &);

  protected:
};

#endif
