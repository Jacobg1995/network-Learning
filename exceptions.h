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
#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <iostream>
#include <exception>

using namespace std;

/* EPacketAnalysisException: base class for all exceptions defined for app.
 *
 * Attributes
 *   message: message to be displayed when catched
 */
class EPacketAnalysisException : public exception {
  private:
    const char * message;    // what message associated to exception

  public:
    // Parameterized constructor
    EPacketAnalysisException(const char * msg) : message(msg) {}

    // Returns message associated with the exception
    virtual const char* what() const throw() {
      return message;
    }
};

/* EBadTransportException: derived exception class to be thrown when a datagram
 *   does not transport expected information.
 *
 * Attributes
 *   message (inherited): message to be displayed when catched
 */
class EBadTransportException : public EPacketAnalysisException {
  public:
    EBadTransportException(const char * msg)
      : EPacketAnalysisException(msg) {}
};

/* EBadHardwareException: derived exception class to be thrown when a datagram
 *   does not correspond to expected hardware format.
 *
 * Attributes
 *   message (inherited): message to be displayed when catched
 */
class EBadHardwareException: public EPacketAnalysisException {
  public:
    EBadHardwareException(const char * msg)
      : EPacketAnalysisException(msg) {}
};

#endif

