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

-module(e2qc).

-export([cache/3, setup/2, stats/1]).

-define(DEFAULT_MAX_SIZE, 1*1024*1024).
-define(DEFAULT_Q1_MIN_SIZE, round(?DEFAULT_MAX_SIZE / 2)).

-spec cache(Cache :: atom(), Key :: term(), ValFun :: function()) -> term().
cache(Cache, Key, ValFun) ->
	KeyBin = if is_binary(Key) -> Key; is_integer(Key) -> binary:encode_unsigned(Key); true -> term_to_binary(Key) end,
	case e2qc_nif:get(Cache, KeyBin) of
		notfound ->
			Val = ValFun(),
			ValBin = if is_binary(Val) ->
				<<1, Val/binary>>;
			true -> V = term_to_binary(Val), <<2, V/binary>> end,
			ok = e2qc_nif:put(Cache, KeyBin, ValBin,
				?DEFAULT_MAX_SIZE, ?DEFAULT_Q1_MIN_SIZE),
			Val;
		<<1, Val/binary>> -> Val;
		<<2, ValBin/binary>> -> binary_to_term(ValBin);
		_ -> error(badcache)
	end.

-spec setup(Cache :: atom(), Config :: [{K :: atom(), V :: term()}]) -> ok.
setup(Cache, Config) ->
	MaxSize = proplists:get_value(max_size, Config, ?DEFAULT_MAX_SIZE),
	MinQ1Size = case proplists:get_value(min_q1_size, Config) of
		undefined ->
			R = proplists:get_value(ratio, Config, 0.5),
			round(R * MaxSize);
		V when is_integer(V) -> V;
		V when is_float(V) -> round(V)
	end,
	case e2qc_nif:create(Cache, MaxSize, MinQ1Size) of
		already_exists -> error(already_exists);
		ok -> ok
	end.

-spec stats(Cache :: atom()) -> [{K :: atom(), V :: term()}].
stats(Cache) ->
	case e2qc_nif:stats(Cache) of
		notfound -> [];
		{Hits, Misses, Q1Size, Q2Size} ->
			[{hits, Hits}, {misses, Misses}, {q1size, Q1Size}, {q2size, Q2Size}]
	end.
