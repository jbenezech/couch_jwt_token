%   Copyright 2016 Jerome Benezech
%
%   Licensed under the Apache License, Version 2.0 (the "License");
%   you may not use this file except in compliance with the License.
%   You may obtain a copy of the License at
%
%       http://www.apache.org/licenses/LICENSE-2.0
%
%   Unless required by applicable law or agreed to in writing, software
%   distributed under the License is distributed on an "AS IS" BASIS,
%   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%   See the License for the specific language governing permissions and
%   limitations under the License.

-module(couch_jwt_token).
-export([handle_session_req/1]).
-export([encode/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("couch/include/couch_db.hrl").

-import(couch_httpd, [header_value/2, send_json/2,send_json/4, send_method_not_allowed/2]).
-import(couch_httpd_auth, [authentication_warning/2]).

% token handlers
% Login handler with user db that generates a JSON Web Token
handle_session_req(#httpd{method='POST', mochi_req=MochiReq}=Req) ->
    ReqBody = MochiReq:recv_body(),
    Form = case MochiReq:get_primary_header_value("content-type") of
        % content type should be json
        "application/x-www-form-urlencoded" ++ _ ->
            mochiweb_util:parse_qs(ReqBody);
        "application/json" ++ _ ->
            {Pairs} = ?JSON_DECODE(ReqBody),
            lists:map(fun({Key, Value}) ->
              {?b2l(Key), ?b2l(Value)}
            end, Pairs);
        _ ->
            []
    end,
    UserName = ?l2b(couch_util:get_value("name", Form, "")),
    Password = ?l2b(couch_util:get_value("password", Form, "")),
    ?LOG_DEBUG("Attempt Login: ~s",[UserName]),
    UserProps = case couch_auth_cache:get_user_creds(UserName) of
        nil -> [];
        Result -> Result
    end,
    case authenticate(Password, UserProps) of
        true ->
            UserProps2 = maybe_upgrade_password_hash(UserName, Password, UserProps),
            % setup the session cookie
            Token = encode(UserProps2),
            % TODO document the "next" feature in Futon
            {Code, Headers} = case couch_httpd:qs_value(Req, "next", nil) of
                nil ->
                    {200, []};
                Redirect ->
                    {302, [{"Location", couch_httpd:absolute_uri(Req, Redirect)}]}
            end,
            send_json(Req#httpd{req_body=ReqBody}, Code, Headers,
                {[
                    {ok, true},
                    {id_token, Token}
                ]});
        _Else ->
            % clear the session
            {Code, Headers} = case couch_httpd:qs_value(Req, "fail", nil) of
                nil ->
                    {401, []};
                Redirect ->
                    {302, [{"Location", couch_httpd:absolute_uri(Req, Redirect)}]}
            end,
            send_json(Req, Code, Headers, {[{error, <<"unauthorized">>},{reason, <<"Name or password is incorrect.">>}]})
    end.

maybe_upgrade_password_hash(UserName, Password, UserProps) ->
    IsAdmin = lists:member(<<"_admin">>, couch_util:get_value(<<"roles">>, UserProps, [])),
    case {IsAdmin, couch_util:get_value(<<"password_scheme">>, UserProps, <<"simple">>)} of
    {false, <<"simple">>} ->
        DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db", "_users")),
        couch_util:with_db(DbName, fun(UserDb) ->
            UserProps2 = proplists:delete(<<"password_sha">>, UserProps),
            UserProps3 = [{<<"password">>, Password} | UserProps2],
            NewUserDoc = couch_doc:from_json_obj({UserProps3}),
            {ok, _NewRev} = couch_db:update_doc(UserDb, NewUserDoc, []),
            couch_auth_cache:get_user_creds(UserName)
        end);
    _ ->
        UserProps
    end.

authenticate(Pass, UserProps) ->
    UserSalt = couch_util:get_value(<<"salt">>, UserProps, <<>>),
    {PasswordHash, ExpectedHash} =
        case couch_util:get_value(<<"password_scheme">>, UserProps, <<"simple">>) of
        <<"simple">> ->
            {couch_passwords:simple(Pass, UserSalt),
            couch_util:get_value(<<"password_sha">>, UserProps, nil)};
        <<"pbkdf2">> ->
            Iterations = couch_util:get_value(<<"iterations">>, UserProps, 10000),
            verify_iterations(Iterations),
            {couch_passwords:pbkdf2(Pass, UserSalt, Iterations),
             couch_util:get_value(<<"derived_key">>, UserProps, nil)}
    end,
    couch_log:debug("Password ~s|~s,", [PasswordHash, ExpectedHash]),
    couch_passwords:verify(PasswordHash, ExpectedHash).


verify_iterations(Iterations) when is_integer(Iterations) ->
    Min = list_to_integer(couch_config:get("couch_httpd_auth", "min_iterations", "1")),
    Max = list_to_integer(couch_config:get("couch_httpd_auth", "max_iterations", "1000000000")),
    case Iterations < Min of
        true ->
            throw({forbidden, <<"Iteration count is too low for this server">>});
        false ->
            ok
    end,
    case Iterations > Max of
        true ->
            throw({forbidden, <<"Iteration count is too high for this server">>});
        false ->
            ok
    end.

%% @doc encode JWT using CouchDB config
-spec encode(UserProps :: list()) -> binary().
encode(UserProps) ->
  encode(UserProps, couch_config:get("jwt_auth")).

% Config is list of key value pairs:
% [{"hs_secret","..."},{"roles_claim","roles"},{"username_claim","sub"}]
-spec encode(UserProps :: list(), Config :: list()) -> binary().
encode(UserProps, Config) ->
  couch_log:debug("Config ~s", [couch_util:get_value("hs_secret", Config)]),
  Secret = base64url:decode(couch_util:get_value("hs_secret", Config)),
  couch_log:debug("Secret ~s", [Secret]),
  ejwt:encode(UserProps, Secret).

% UNIT TESTS
-ifdef(TEST).

-define (EmptyConfig, [{"hs_secret",""}]).
-define (BasicConfig, [{"hs_secret","c2VjcmV0"}]).
-define (BasicTokenInfo, [{"sub",<<"1234567890">>},{"name",<<"John Doe">>},{"admin",true}]).
-endif.
