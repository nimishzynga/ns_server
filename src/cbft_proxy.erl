%% @author Couchbase <info@couchbase.com>
%% @copyright 2015 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(cbft_proxy).

-export([cbft_forward_request/4]).

-include("ns_common.hrl").

-define(TIMEOUT, ns_config:get_timeout(index_rest_request, 10000)).

-import(menelaus_util,
        [redirect_permanently/2,
         bin_concat_path/1,
         bin_concat_path/2,
         reply/2,
         reply/3,
         reply_text/3,
         reply_text/4,
         reply_ok/3,
         reply_ok/4,
         reply_json/2,
         reply_json/3,
         reply_json/4,
         reply_not_found/1,
         get_option/2,
         parse_validate_number/3,
         is_valid_positive_integer/1,
         is_valid_positive_integer_in_range/3,
         validate_boolean/2,
         validate_dir/2,
         validate_integer/2,
         validate_range/4,
         validate_range/5,
         validate_unsupported_params/1,
         validate_has_params/1,
         validate_memory_quota/2,
         validate_any_value/2,
         execute_if_validated/3]).

cbft_forward_request(Method, P, Body, Req) ->
    Port = ns_config:read_key_fast({node, node(), cbft}, 9200),
    Path1 = hd(P),
    Path2 = string:sub_string(Path1, 6),
    URL = lists:flatten(io_lib:format("http://127.0.0.1:~B/~s", [Port, Path2])),

    User = ns_config_auth:get_user(special),
    Pwd = ns_config_auth:get_password(special),

    Headers = menelaus_rest:add_basic_auth([], User, Pwd),

    RV = rest_utils:request(cbft_proxy, URL, Method, Headers, Body, ?TIMEOUT),

    case RV of
    {ok, {{200, _}, Headers1, BodyRaw1}} ->
        Bd = re:replace(BodyRaw1, "/static", "/cbft&", [{return,list}, global]),
        %?log_error("Got response xxx ~p", [Bd]),
        reply_ok(Req, "text/html", Bd);
    {ok, {{302, _}, Headers2, BodyRaw2}} ->
        % currently this is hack.need to change it.
        NewT = {"Location","/cbft/staticx/"},
        Headers3 = lists:keyreplace("Location", 1, Headers2, NewT),
        %Headers3 = re:replace(Headers2, "staticx", "/cbft/&", [{return,list}]),
        reply(Req, 302, Headers3);
    _ ->
        ?log_error("Request to ~s failed: ~p", [URL, RV]),
        {error, RV}
    end.
