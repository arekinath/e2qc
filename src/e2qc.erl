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

%% @author Alex Wilson <alex@uq.edu.au>
%% @doc e2qc public API
-module(e2qc).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([cache/3, setup/2, stats/1, evict/2, teardown/1]).

-define(DEFAULT_MAX_SIZE, 4*1024*1024).
-define(DEFAULT_Q1_MIN_SIZE, round(0.3 * ?DEFAULT_MAX_SIZE)).

%% @doc Cache an operation using the given key.
%%
%% ValFun is a zero-argument fun that computes some expensive operation
%% and returns any term. The call to cache/3 will return that term, either
%% by running the fun, or consulting the named Cache for Key.
-spec cache(Cache :: atom(), Key :: term(), ValFun :: function()) -> term().
cache(Cache, Key, ValFun) ->
	KeyBin = key_to_bin(Key),
	case e2qc_nif:get(Cache, KeyBin) of
		notfound ->
			Val = ValFun(),
			ValBin = if 
				is_binary(Val) ->
					<<1, Val/binary>>;
				true ->
					V = term_to_binary(Val),
					<<2, V/binary>>
			end,
			ok = e2qc_nif:put(Cache, KeyBin, ValBin,
				?DEFAULT_MAX_SIZE, ?DEFAULT_Q1_MIN_SIZE),
			Val;
		<<1, Val/binary>> -> Val;
		<<2, ValBin/binary>> -> binary_to_term(ValBin);
		_ -> error(badcache)
	end.

%% @doc Remove an entry from a cache.
-spec evict(Cache :: atom(), Key :: term()) -> ok | notfound.
evict(Cache, Key) ->
	KeyBin = key_to_bin(Key),
	e2qc_nif:destroy(Cache, KeyBin).

%% @doc Tear-down a cache, destroying all entries and settings.
-spec teardown(Cache :: atom()) -> ok | notfound.
teardown(Cache) ->
	e2qc_nif:destroy(Cache).

-type max_size_setting() :: {size | max_size, Bytes :: integer()}.
-type q1_size_setting() :: {ratio, Ratio :: float()} | {min_q1_size, Bytes :: integer()}.
-type setting() :: max_size_setting() | q1_size_setting().

%% @doc Configure a cache with given settings.
-spec setup(Cache :: atom(), Config :: [setting()]) -> ok.
setup(Cache, Config) ->
	MaxSize = proplists:get_value(max_size, Config, 
		proplists:get_value(size, Config, ?DEFAULT_MAX_SIZE)),
	MinQ1Size = case proplists:get_value(min_q1_size, Config) of
		undefined ->
			R = proplists:get_value(ratio, Config, 0.3),
			round(R * MaxSize);
		V when is_integer(V) -> V;
		V when is_float(V) -> round(V)
	end,
	case e2qc_nif:create(Cache, MaxSize, MinQ1Size) of
		already_exists -> error(already_exists);
		ok -> ok
	end.

-type cache_stat() :: {hits | misses | q1size | q2size, Value :: integer()}.

%% @doc Gather some basic statistics about a cache.
-spec stats(Cache :: atom()) -> [cache_stat()].
stats(Cache) ->
	case e2qc_nif:stats(Cache) of
		notfound -> [{hits, 0}, {misses, 0}, {q1size, 0}, {q2size, 0}];
		{Hits, Misses, Q1Size, Q2Size} ->
			[{hits, Hits}, {misses, Misses}, {q1size, Q1Size}, {q2size, Q2Size}]
	end.

%% @private
-spec key_to_bin(term()) -> binary().
key_to_bin(Key) when is_binary(Key) ->
	Key;
key_to_bin(Key) when is_integer(Key) and (Key >= 0) ->
	binary:encode_unsigned(Key);
key_to_bin(Key) ->
	term_to_binary(Key).

-ifdef(TEST).
-endif.