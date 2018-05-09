%%%-------------------------------------------------------------------
%% @doc ecrecover public API
%% @end
%%%-------------------------------------------------------------------

-module(ecrecover_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    ecrecover_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================