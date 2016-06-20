/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 *  This is an api between jabberite, a simple console based XMPP
 *  protocol and EchoChamber, the test aparatus for testing multiparty chat
 *  protocols.
 *
 *  Authors: Vmon, 2016-06
 */

#ifndef EC_API_H
#define EC_API_H

#include <string>
#include <json/json.h>

namespace EchoChamberAPI
{
  //these all need to go inside a class, but I'm a lazy basterd or something, hmmm, I guess I don't have time :-(
  /**
   *  is called by ec_api_io_callback to handle requests from EchoChamber
   * 
   *  @param ec_message the request written in the socket by EchoChamber
   *  @param user_state the np1sec UserState object which manage np1sec 
   *                    protocol for current user
   */
  void message_handler(const std::string& ec_message, np1sec::UserState* user_state);

  /**
    Get called back whenever EchoChamber write into EC-Jabberite unix socket
   */
  gboolean ec_api_io_callback(GIOChannel* io, GIOCondition condition, gpointer p);

  /**
   * processes a request from echo chamber to send a message to a room 
   *
   *  @param prompt_request json object which contains the jsonized request
   *  @param user_state the np1sec UserState object which manage np1sec 
   *                    protocol for current user
   */
  void prompt_message(Json::Value& prompt_request, np1sec::UserState* user_state);
} // namespace EchoChamberAPI

#endif
