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

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([get/2, put/3, put/5, put/6, create/3, destroy/1, destroy/2, stats/1]).

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
	erlang:nif_error(badnif).

%% @private
%% for tests only
put(Cache, Key, Val) ->
	put(Cache, Key, Val, 0, 0).

%% @private
-spec put(Cache :: atom(), Key :: binary(), Val :: binary(), MaxSize :: integer(), MinQ1Size :: integer()) -> ok.
put(_Cache, _Key, _Val, _MaxSize, _MinQ1Size) ->
	erlang:nif_error(badnif).

%% @private
-spec put(Cache :: atom(), Key :: binary(), Val :: binary(), MaxSize :: integer(), MinQ1Size :: integer(), Lifetime :: integer()) -> ok.
put(_Cache, _Key, _Val, _MaxSize, _MinQ1Size, _Lifetime) ->
	erlang:nif_error(badnif).

%% @private
-spec create(Cache :: atom(), MaxSize :: integer(), MinQ1Size :: integer()) -> already_exists | ok.
create(_Cache, _MaxSize, _MinQ1Size) ->
	erlang:nif_error(badnif).

%% @private
-spec destroy(Cache :: atom()) -> notfound | ok.
destroy(_Cache) ->
	erlang:nif_error(badnif).

%% @private
-spec destroy(Cache :: atom(), Key :: binary()) -> notfound | ok.
destroy(_Cache, _Key) ->
	erlang:nif_error(badnif).

%% @private
-spec stats(Cache :: atom()) -> notfound | {Hits :: integer(), Misses :: integer(), Q1Size :: integer(), Q2Size :: integer(), IncrQSize :: integer()}.
stats(_Cache) ->
	erlang:nif_error(badnif).

-ifdef(TEST).

get_cache_notfound_test() ->
	?assertMatch(notfound, get(invalid_cache, <<"foo">>)).
get_key_notfound_test() ->
	ok = create(get_key_test, 1024, 512),
	?assertMatch(notfound, get(get_key_test, <<"foo">>)).
put_implicit_create_test() ->
	?assertMatch(notfound, stats(put_implicit_create)),
	?assertMatch(ok, put(put_implicit_create, <<"foo">>, <<"bar">>)),
	?assertMatch(T when is_tuple(T), stats(put_implicit_create)).
put_then_get_test() ->
	?assertMatch(ok, put(put_then_get, <<"foo">>, <<"bar">>, 1024, 512)),
	?assertMatch(<<"bar">>, get(put_then_get, <<"foo">>)).

put_evict_q1_test() ->
	ok = create(put_evict_q1, 20, 10),
	[ok = put(put_evict_q1, <<N>>, <<N>>) || N <- lists:seq(1,10)],
	% these gets will promote 1 and 10 to q2, so <<2>> will be first
	% to be evicted
	?assertMatch(<<1>>, get(put_evict_q1, <<1>>)),
	?assertMatch(<<10>>, get(put_evict_q1, <<10>>)),
	ok = put(put_evict_q1, <<11>>, <<11>>),
	% 1s should always be enough for the bg_thread to wake up
	% (usually happens within 1ms or so)
	timer:sleep(2000),
	ok = put(put_evict_q1, <<12>>, <<12>>),
	timer:sleep(2000),
	?assertMatch(notfound, get(put_evict_q1, <<2>>)),
	?assertMatch(<<1>>, get(put_evict_q1, <<1>>)),
	?assertMatch(<<10>>, get(put_evict_q1, <<10>>)),
	?assertMatch(<<11>>, get(put_evict_q1, <<11>>)).
put_evict_q2_test() ->
	ok = create(put_evict_q2, 20, 10),
	% fill q1 with entries
	[ok = put(put_evict_q2, <<N>>, <<N>>) || N <- lists:seq(1,10)],
	% promote them all to q2
	[<<N>> = get(put_evict_q2, <<N>>) || N <- lists:seq(1,10)],
	% now add an extra to q1 (q1 will be < min_q1_size)
	ok = put(put_evict_q2, <<11>>, <<11>>),
	timer:sleep(2000),
	ok = put(put_evict_q2, <<12>>, <<12>>),
	timer:sleep(2000),
	% we should have evicted the least recently used thing on q2,
	% which will be <<1>>
	?assertMatch(notfound, get(put_evict_q2, <<1>>)),
	?assertMatch(<<3>>, get(put_evict_q2, <<3>>)),
	?assertMatch(<<11>>, get(put_evict_q2, <<11>>)).

expand_test() ->
	ok = create(expand, 20, 10),
	[ok = put(expand, <<N>>, <<N>>) || N <- lists:seq(1,10)],
	% these gets will promote 1 and 10 to q2, so <<2>> will be first
	% to be evicted
	?assertMatch(<<1>>, get(expand, <<1>>)),
	?assertMatch(<<10>>, get(expand, <<10>>)),
	ok = create(expand, 50, 20),
	ok = put(expand, <<11>>, <<11>>),
	% 1s should always be enough for the bg_thread to wake up
	% (usually happens within 1ms or so)
	timer:sleep(2000),
	ok = put(expand, <<12>>, <<12>>),
	timer:sleep(2000),
	?assertMatch(<<2>>, get(expand, <<2>>)),
	?assertMatch(<<1>>, get(expand, <<1>>)),
	?assertMatch(<<10>>, get(expand, <<10>>)),
	?assertMatch(<<11>>, get(expand, <<11>>)).

destroy_key_test() ->
	ok = create(destroy_key, 20, 10),
	?assertMatch(notfound, destroy(destroy_key, <<"foo">>)),
	ok = put(destroy_key, <<"foo">>, <<"bar">>),
	?assertMatch(<<"bar">>, get(destroy_key, <<"foo">>)),
	?assertMatch(ok, destroy(destroy_key, <<"foo">>)),
	?assertMatch(notfound, get(destroy_key, <<"foo">>)).

put_overwrite_test() ->
	ok = create(put_overwrite, 20, 10),
	ok = put(put_overwrite, <<"foo">>, <<"bar">>),
	?assertMatch(<<"bar">>, get(put_overwrite, <<"foo">>)),
	ok = put(put_overwrite, <<"foo">>, <<"foobar">>),
	?assertMatch(<<"foobar">>, get(put_overwrite, <<"foo">>)).

destroy_cache_test() ->
	ok = create(destroy_cache, 20, 10),
	ok = put(destroy_cache, <<"foo">>, <<"bar">>),
	?assertMatch(ok, destroy(destroy_cache)),
	?assertMatch(notfound, get(destroy_cache, <<"foo">>)),
	?assertMatch(ok, create(destroy_cache, 20, 10)).

timed_expiry_test() ->
	ok = create(timed_expiry, 20, 10),
	ok = put(timed_expiry, <<"foo">>, <<"bar">>, 20, 10, 1),
	?assertMatch(<<"bar">>, get(timed_expiry, <<"foo">>)),
	timer:sleep(2000),
	?assertMatch(notfound, get(timed_expiry, <<"foo">>)),
	ok = put(timed_expiry, <<1>>, <<1>>),
	timer:sleep(2000),
	?assertMatch({_, _, Q1, Q2, _, _, _} when (Q1 >= 2) and (Q2 < 1), stats(timed_expiry)).

-endif.
