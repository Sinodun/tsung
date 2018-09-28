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

%%%  In addition, as a special exception, you have the permission to
%%%  link the code of this program with any library released under
%%%  the EPL license and distribute linked combinations including
%%%  the two; the MPL (Mozilla Public License), which EPL (Erlang
%%%  Public License) is based on, is included in this exception.

%%% common functions used by http clients to parse config

-module(ts_config_dns).
-author('jim@sinodun.com').

-export([parse_config/2]).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_dns.hrl").

-include("xmerl.hrl").

%%----------------------------------------------------------------------
%% Func: parse_config/2
%% Args: Element, Config
%% Returns: List
%% Purpose: parse a request defined in the XML config file
%%----------------------------------------------------------------------
%% Parsing other elements
parse_config(Element = #xmlElement{name=dyn_variable}, Conf = #config{}) ->
    ts_config:parse(Element,Conf);
parse_config(Element = #xmlElement{name=dns, attributes=Attrs},
             Config=#config{curid = Id, session_tab = Tab,
                            sessions = [CurS | _], dynvar=DynVar,
                            subst    = SubstFlag, match=MatchRegExp}) ->
    Qtype  = ts_config:getAttr(string, Attrs, qtype, "a"),
    Qclass  = ts_config:getAttr(string, Attrs, qclass, "in"),
    Qname  = ts_config:getAttr(string, Attrs, qname, "example.com"),
    Request = #dns_request{qtype=Qtype, qclass=Qclass, qname=Qname},
    Msg=#ts_request{ack     = local,
                    endpage = true,
                    dynvar_specs = DynVar,
                    subst   = SubstFlag,
                    match   = MatchRegExp,
                    param   = Request},
    ts_config:mark_prev_req(Id-1, Tab, CurS),
    ets:insert(Tab,{{CurS#session.id, Id},Msg }),
    lists:foldl( fun(A,B)->ts_config:parse(A,B) end,
                 Config#config{dynvar=undefined},
                 Element#xmlElement.content);
%% Parsing other elements
parse_config(Element = #xmlElement{}, Conf = #config{}) ->
    ts_config:parse(Element,Conf);
%% Parsing non #xmlElement elements
parse_config(_, Conf = #config{}) ->
    Conf.
