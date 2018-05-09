-module(ecrecover_server).

-behaviour(gen_server).

-export([start_link/0]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
 port % port handle
}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
   %% open port 
    Path = code:priv_dir(ecrecover),
    PortOpts = [{cd, Path}, {packet, 4}, binary],
    Port = erlang:open_port({spawn_executable, Path ++ "/ecrecover_server"}, PortOpts),
%    Port = erlang:open_port({spawn_executable, Path ++ "/log"}, PortOpts),
    {ok, #state{port = Port}}.

handle_call({sign, Digest, PrivKey, Random}, _From, #state{port = Port} = State) ->
%             1  +   32 bytes,  +   32 bytes    +   32 bytes = 97Bytes
 Request = <<1:8, Digest/binary, PrivKey/binary, Random/binary>>,
 erlang:port_command(Port, Request),
 Result = receive 
    {Port, {data, <<1:8>>}} -> {error, lib_signing_error};
    {Port, {data, <<0:8, R:32/binary, S:32/binary, V:8>> }} -> {R,S,V}
    after 2000 -> {error, port_time_out}
 end,
{reply, Result, State};

handle_call({recover, Digest, R, S, V}, _From, #state{port = Port} = State) ->
%            1 +    32 bytes  +   32 bytes + 32 bytes + 1  = 98Bytes
 Request = <<2:8, Digest/binary, R/binary, S/binary, V:8 >>,
 erlang:port_command(Port, Request),
 Result = receive
    {Port, {data, <<0:8, _:8, P:64/binary>> }} -> P;
    {Port, {data, <<1:8>>}} -> {error, parsing_signature};
    {Port, {data, <<2:8>>}} -> {error, recovering_pubkey}
     after 2000 -> {error, port_time_out}
 end,
 {reply, Result, State};

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

