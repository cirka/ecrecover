%%%-------------------------------------------------------------------
%% @doc ecrecover top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(ecrecover_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
Server = {ecrecover, {ecrecover_server, start_link, []}, permanent, 5000, worker, [ecrecover_server]},
    {ok, { {one_for_all, 0, 1}, [Server]} }.

%%====================================================================
%% Internal functions
%%====================================================================
