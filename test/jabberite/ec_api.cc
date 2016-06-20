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

extern "C" {
#include <glib.h>
#include <signal.h>
#include <unistd.h>
}

#include <string>
#include <json/json.h>

#include "userstate.h"
#include "ec_api.h"
//#include "common.h"
//#include "jabberite_np1sec_plugin.h"
//#include "interface.h"


namespace EchoChamberAPI
{

  //these all need to go inside a class, but I'm a lazy basterd, hmmm, I guess I don't have time :-(
  gboolean ec_api_io_callback(GIOChannel* io, GIOCondition condition, gpointer p)
  {
    UNUSED(condition);
    //we don't need the account we have sent it as send_bare_data before
    // PurpleAccount* account = (static_cast<pair<PurpleAccount*, np1sec::UserState*>*>(p))->first;
    // np1sec::UserState* user_state = (static_cast<pair<PurpleAccount*, np1sec::UserState*>*>(p))->second;
    np1sec::UserState* user_state = reinterpret_cast<np1sec::UserState*>(p);
    
    GError* error = NULL;
    gchar* raw_message;
    gsize message_len;

    //PurpleConversation* conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, name, account);
    auto read_status = g_io_channel_read_line (io, &raw_message, &message_len, NULL, &error);
    switch (read_status) {
    case G_IO_STATUS_NORMAL:
      {
        std::string ec_message(raw_message);
        EchoChamberAPI::message_handler(ec_message, user_state);
      }
      return TRUE;
    case G_IO_STATUS_ERROR:
        g_printerr("IO error: %s\n", error->message);
        g_error_free(error);
        return FALSE;
    case G_IO_STATUS_EOF:
    case G_IO_STATUS_AGAIN:
        return TRUE;
        break;
    }

    return FALSE;
  }

  void message_handler(const std::string& ec_message, np1sec::UserState* user_state) {
    //first we need to parse the json object

    Json::Value root;
    Json::Reader reader;

    bool parsingSuccessful = reader.parse( ec_message.c_str(), root);

    if ( !parsingSuccessful ) {
      std::cerr << "Failed to parse"
                << reader.getFormattedErrorMessages();
      
      return;
      
    }
    
    /* folowing structure
       {
       "request": "request 1",
       "param1": "param 1 value",
       "param2": "param 2 value" 
       }
       }
    */
    std::string request = root.get("request", "nop").asString();
    
    if (request  == "prompt") {
      prompt_message(root, user_state);
      
    } else {
      Json::FastWriter fastWriter;
      std::string request_str = fastWriter.write(root);
      std::cerr << "unrecognized request: " << request_str << std::endl;
      
    }
    
    std::cerr << "Invalid request" << std::endl;
  }

  void prompt_message(Json::Value& prompt_request, np1sec::UserState* user_state) {
    /* folowing structure
       {
       "request": "prompt",
       "to": "room/receipient",
       "message": "Nice to meet you" 
       }
       }
    */
    std::string destination = prompt_request.get("to", "").asString();
    std::string message_to_send =  prompt_request.get("request", "").asString();

    if (destination == "") {
      std::cerr << "can't send message to an unspecified destination." << std::endl;
      return;
    }

    user_state->send_handler(destination, message_to_send);
    
  }
    
}
  
