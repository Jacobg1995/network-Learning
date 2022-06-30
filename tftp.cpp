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
#ifndef TFTP_CPP
#define TFTP_CPP

#include "tftp.h"
#include "exceptions.h"

// Default constructor
TFTPDatagram::TFTPDatagram(bool owned) : DatagramFragment(owned) {
}

// Parameterized constructor
TFTPDatagram::TFTPDatagram(bool owned, unsigned char * s, unsigned int l) : DatagramFragment(owned, s, l) {
}

// Returns the UDP segment header length in bytes
unsigned int TFTPDatagram::header_length() const {
  return 2;
}

// Returns TFTP datagram type according to the opcode field
TFTPDatagram::TFTPOperation TFTPDatagram::operation() const {
  switch (char2word(p_data)) {
    case 1  : return tftp_rrq;
    case 2  : return tftp_wrq;
    case 3  : return tftp_data;
    case 4  : return tftp_ack;
    default : return tftp_none;
  }
}

// Returns the ASCII mode transported by RRQ and WRQ datagrams
char * TFTPDatagram::filename() const {
  if (operation() == tftp_rrq || operation() == tftp_wrq)
    return ((char *)p_data + header_length());
  else
    throw EBadTransportException("TFTP datagram does not contain filename field");
}

// Returns the filename transported by RRQ and WRQ datagrams
char * TFTPDatagram::mode() const {
  if (operation() == tftp_rrq || operation() == tftp_wrq)
    return ((char *)p_data + header_length() + strlen(filename()) + 1);
  else
    throw EBadTransportException("TFTP datagram does not contain filename field");
}

// Returns the error code contained in ERROR datagrams
unsigned int TFTPDatagram::error_code() const {
  if (operation() == tftp_error)
    return (char2word(p_data + header_length()));
  else
    throw EBadTransportException("TFTP datagram does not contain error code field");
}

// Returns the error message contained in ERROR datagrams
char * TFTPDatagram::error_msg() const {
  if (operation() == tftp_error)
    return ((char *)p_data + header_length() + 2);
  else
    throw EBadTransportException("TFTP datagram does not contain error message field");
}

// Returns the block number transported in DATA and ACK datagrams
unsigned int TFTPDatagram::block() const {
  if (operation() == tftp_data || operation() == tftp_ack)
    return (char2word(p_data + header_length()));
  else
    throw EBadTransportException("TFTP datagram does not contain block field");
}

// Returns the size (in bytes) of data transported by DATA datagrams
unsigned int TFTPDatagram::data_length() const {
  if (operation() == tftp_data)
    return (p_len - 4);
  else
    throw EBadTransportException("TFTP datagram does not contain data");
}

// Returns a string textually identifying some common standard ports
ostream & operator<<(ostream & ostr, const TFTPDatagram & tftp) {
  if (tftp.p_data) {
    ostr << "operation = ";
    switch (tftp.operation()) {
      case TFTPDatagram::tftp_rrq  : ostr << "READ" << endl;
                                     break;
      case TFTPDatagram::tftp_wrq  : ostr << "WRITE" << endl;
                                     break;
      case TFTPDatagram::tftp_data : ostr << "DATA" << endl;
                                     break;
      case TFTPDatagram::tftp_ack  : ostr << "ACK" << endl;
                                     break;
      case TFTPDatagram::tftp_error: ostr << "ERROR" << endl;
                                     break;
      default                      : ostr << "unknown" << endl;
                                     break;
    }
  }

  if (tftp.operation() == TFTPDatagram::tftp_rrq || tftp.operation() == TFTPDatagram::tftp_wrq) {
    ostr << "filename = " << tftp.filename() << endl;
    ostr << "mode = "     << tftp.mode() << endl;
  }

  if (tftp.operation() == TFTPDatagram::tftp_data || tftp.operation() == TFTPDatagram::tftp_ack)
    ostr << "block number = " << tftp.block() << endl;

  if (tftp.operation() == TFTPDatagram::tftp_data)
    ostr << "data size = " << tftp.data_length() << endl;

  if (tftp.operation() == TFTPDatagram::tftp_error) {
    ostr << "error code = " << tftp.error_code() << endl;
    ostr << "error message = "     << tftp.error_msg() << endl;
  }

  ostr << flush;

  return ostr;
}

#endif
