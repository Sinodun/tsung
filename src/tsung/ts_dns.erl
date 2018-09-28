%%%  Copyright (C) 2018 Sinodun
%%%
%%%  This program is free software; you can redistribute it and/or modify
%%%  it under the terms of the GNU General Public License as published by
%%%  the Free Software Foundation; either version 2 of the License, or
%%%  (at your option) any later version.
%%%
%%%  This program is distributed in the hope that it will be useful,
%%%  but WITHOUT ANY WARRANTY; without even the implied warranty of
%%%  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%%  GNU General Public License for more details.
%%%
%%%  You should have received a copy of the GNU General Public License
%%%  along with this program; if not, write to the Free Software
%%%  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
%%%

%%% In addition, as a special exception, you have the permission to
%%% link the code of this program with any library released under
%%% the EPL license and distribute linked combinations including
%%% the two.

-module(ts_dns).
-author('jim@sinodun.com').

-behavior(ts_plugin).

-include("ts_macros.hrl").
-include("ts_profile.hrl").
-include("ts_dns.hrl").

-export([add_dynparams/4,
         get_message/2,
         session_defaults/0,
         parse/2,
         parse_bidi/2,
         dump/2,
         parse_config/2,
         decode_buffer/2,
         new_session/0]).

%%
%% Creating DNS messages.
%%
%% Over time I expect this to get more comprehensive. At present it's
%% only sufficient to construct basic queries.
%%

encode_qtype(Qtype) ->
    case string:casefold(Qtype) of
        "a" -> 1;
        "ns" -> 2;
        "cname" -> 5;
        "soa" -> 6;
        "ptr" -> 12;
        "mx" -> 15;
        "txt" -> 16;
        "aaaa" -> 28;
        Qtype when is_list(Qtype) -> list_to_integer(Qtype)
    end.

encode_qclass(Qclass) ->
    case string:casefold(Qclass) of
        "in" -> 1;
        "chaos" -> 3;
        "hesiod" -> 4;
        "none" -> 254;
        "any" -> 255;
        Qclass when is_list(Qclass) -> list_to_integer(Qclass)
    end.

%% Don't bother with label compression. And note the complete lack of
%% error checking in label conversion.
encode_name(Qname) ->
    Labels = string:tokens(Qname, "."),
    LabelSizeList = [[string:len(L), L] || L <- Labels],
    list_to_binary(LabelSizeList++[0]).

encode_query(#dns_request{qtype=Qtype, qclass=Qclass, qname=Qname}) ->
    Type = encode_qtype(Qtype),
    Class = encode_qclass(Qclass),
    Name = encode_name(Qname),
    Id = rand:uniform(65535),

    Header = <<Id:16,    %% Query ID
               0:1,      %% Query/Response flag, 0 = Query
               0:4,      %% Opcode, 0 = QUERY
               0:1,      %% AA
               0:1,      %% TC
               1:1,      %% RD
               0:1,      %% RA
               0:1,      %% Z
               1:1,      %% AD
               0:1,      %% CD
               0:4,      %% RCODE
               1:16,     %% QDCOUNT
               0:16,     %% ANCOUNT
               0:16,     %% NSCOUNT
               0:16>>,   %% ARCOUNT
    <<Header/binary, Name/binary, Type:16, Class:16>>.

%%----------------------------------------------------------------------
%% Function: session_default/0
%% Purpose: default parameters for session
%% Returns: {ok, persistent = true|false}
%%----------------------------------------------------------------------
session_defaults() ->
    {ok,true}.

%% @spec decode_buffer(Buffer::binary(),Session::record(dns)) ->  NewBuffer::binary()
%% @doc We need to decode buffer (remove chunks, decompress ...) for
%%      matching or dyn_variables
%% @end
decode_buffer(Buffer,#dns_session{}) ->
    Buffer.

%%----------------------------------------------------------------------
%% Function: new_session/0
%% Purpose: initialize session information
%% Returns: record or []
%%----------------------------------------------------------------------
new_session() ->
    #dns_session{}.

%%----------------------------------------------------------------------
%% Function: get_message/2
%% Purpose: Build a message/request ,
%% Args:    record
%% Returns: binary
%%----------------------------------------------------------------------
get_message(#dns_request{} = Request, StateRcv) ->
    { encode_query(Request), StateRcv }.

%%----------------------------------------------------------------------
%% Function: parse/2
%% Purpose: parse the response from the server and keep information
%%          about the response in State#state_rcv.session
%% Args:    Data (binary), State (#state_rcv)
%% Returns: {NewState, Options for socket (list), Close = true|false}
%%----------------------------------------------------------------------
parse(_Data, State) ->
    State.

parse_bidi(Data, State) ->
    ts_plugin:parse_bidi(Data,State).

dump(A,B) ->
    ts_plugin:dump(A,B).

%%----------------------------------------------------------------------
%% Function: parse_config/2
%% Purpose:  parse tags in the XML config file related to the protocol
%% Returns:  List
%%----------------------------------------------------------------------
parse_config(Element, Conf) ->
    ts_config_dns:parse_config(Element, Conf).

%%----------------------------------------------------------------------
%% Function: add_dynparams/4
%% Purpose: add dynamic parameters to build the message
%%          (this is used for ex. for Cookies in HTTP)
%% Args: Subst (true|false), DynData = #dyndata, Param = #myproto_request
%%                                               Host  = String
%% Returns: #myproto_request
%%----------------------------------------------------------------------
add_dynparams(_Subst, _DynData, Param, _HostData) ->
    Param.

%%----------------------------------------------------------------------
%% Function: subst/2
%% Purpose: Replace on the fly dynamic element of the request.
%% Returns: #myproto_request
%%----------------------------------------------------------------------
%%subst(Req=#myproto_request, DynData) ->
%%    todo.
