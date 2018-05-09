-module(ecrecover).

-export([
    sign/3,
    recover/4
    ]).

-type hash() :: binary().
-type nonce() :: binary().
-type pub_key() :: binary().
-type priv_key() :: binary().
-type r() :: binary().
-type s() :: binary().
-type v() :: binary().
-type signature() :: {r(),s(),v()}.
-type error_reason() :: lib_signing_error | port_time_out | send_command_failed | parsing_signature | recovering_pubkey . 

-spec sign(hash(), nonce(), priv_key()) -> signature() | {error, error_reason()}.

sign(Digest, PrivKey, Random) ->
 gen_server:call(ecrecover_server, {sign, Digest, PrivKey, Random}).

-spec recover(hash(), r(), s(), v()) -> pub_key() | {error, error_reason()}.

recover(Digest, R, S, V) ->
 gen_server:call(ecrecover_server, {recover, Digest, R, S, V}).


