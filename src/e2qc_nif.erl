%%
%% e2qc erlang cache
%%
%% Copyright 2014 Alex Wilson <alex@uq.edu.au>, The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(e2qc_nif).

-export([get/2, put/3, put/5, create/3, destroy/1, destroy/2, stats/1]).

-on_load(init/0).

%% @private
init() ->
	SoName = case code:priv_dir(e2qc) of
	    {error, bad_name} ->
	        case filelib:is_dir(filename:join(["..", priv])) of
	        true ->
	            filename:join(["..", priv, ?MODULE]);
	        false ->
	            filename:join([priv, ?MODULE])
	        end;
	    Dir ->
	        filename:join(Dir, ?MODULE)
    end,
	ok = erlang:load_nif(SoName, 0).

%% @private
-spec get(Cache :: atom(), Key :: binary()) -> notfound | binary().
get(_Cache, _Key) ->
	error(badnif).

%% @private
-spec put(Cache :: atom(), Key :: binary(), Val :: binary()) -> ok.
put(_Cache, _Key, _Val) ->
	error(badnif).

%% @private
-spec put(Cache :: atom(), Key :: binary(), Val :: binary(), MaxSize :: integer(), MinQ1Size :: integer()) -> ok.
put(_Cache, _Key, _Val, _MaxSize, _MinQ1Size) ->
	error(badnif).

%% @private
-spec create(Cache :: atom(), MaxSize :: integer(), MinQ1Size :: integer()) -> already_exists | ok.
create(_Cache, _MaxSize, _MinQ1Size) ->
	error(badnif).

%% @private
-spec destroy(Cache :: atom()) -> notfound | ok.
destroy(_Cache) ->
	error(badnif).

%% @private
-spec destroy(Cache :: atom(), Key :: binary()) -> notfound | ok.
destroy(_Cache, _Key) ->
	error(badnif).

%% @private
-spec stats(Cache :: atom()) -> notfound | {Hits :: integer(), Misses :: integer(), Q1Size :: integer(), Q2Size :: integer()}.
stats(_Cache) ->
	error(badnif).
