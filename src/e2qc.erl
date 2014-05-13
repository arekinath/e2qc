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

-export([cache/3, cache/4, setup/2, stats/1, evict/2, teardown/1]).

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
		B when is_binary(B) -> bin_to_val(B);
		notfound ->
			Val = ValFun(),
			ValBin = val_to_bin(Val),
			ok = e2qc_nif:put(Cache, KeyBin, ValBin,
				?DEFAULT_MAX_SIZE, ?DEFAULT_Q1_MIN_SIZE),
			Val
	end.

%% @doc Cache an operation using the given key with a timeout.
%%
%% As for e2qc:cache/3, but the Lifetime argument contains a number of seconds for
%% which this cache entry should remain valid. After Lifetime seconds have elapsed,
%% the entry is automatically evicted and will be recalculated if a miss occurs.
-spec cache(Cache :: atom(), Key :: term(), Lifetime :: integer(), ValFun :: function()) -> term().
cache(Cache, Key, Lifetime, ValFun) ->
	KeyBin = key_to_bin(Key),
	case e2qc_nif:get(Cache, KeyBin) of
		B when is_binary(B) -> bin_to_val(B);
		notfound ->
			Val = ValFun(),
			ValBin = val_to_bin(Val),
			ok = e2qc_nif:put(Cache, KeyBin, ValBin,
				?DEFAULT_MAX_SIZE, ?DEFAULT_Q1_MIN_SIZE, Lifetime),
			Val
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
	{MaxSize, MinQ1Size} = process_settings(Config),
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
-spec process_settings([setting()]) -> {MaxSize :: integer(), MinQ1Size :: integer()}.
process_settings(Config) ->
	MaxSize = proplists:get_value(max_size, Config,
		proplists:get_value(size, Config, ?DEFAULT_MAX_SIZE)),
	MinQ1Size = case proplists:get_value(min_q1_size, Config) of
		undefined ->
			R = proplists:get_value(ratio, Config, 0.3),
			round(R * MaxSize);
		V when is_integer(V) -> V;
		V when is_float(V) -> round(V)
	end,
	{MaxSize, MinQ1Size}.

%% @private
-spec key_to_bin(term()) -> binary().
key_to_bin(Key) when is_binary(Key) ->
	Key;
key_to_bin(Key) when is_integer(Key) and (Key >= 0) ->
	binary:encode_unsigned(Key);
key_to_bin(Key) ->
	term_to_binary(Key).

%% @private
-spec val_to_bin(term()) -> binary().
val_to_bin(V) when is_binary(V) ->
	<<1, V/binary>>;
val_to_bin(V) ->
	VBin = term_to_binary(V),
	<<2, VBin/binary>>.

%% @private
-spec bin_to_val(binary()) -> term().
bin_to_val(<<1, V/binary>>) ->
	V;
bin_to_val(<<2, V/binary>>) ->
	binary_to_term(V).

-ifdef(TEST).

settings_test() ->
	?assertMatch({100, A} when is_integer(A), process_settings([{size, 100}])),
	?assertMatch({100, A} when is_integer(A), process_settings([{max_size, 100}])),
	?assertMatch({100, 30}, process_settings([{size, 100}, {ratio, 0.3}])),
	?assertMatch({100, 41}, process_settings([{size, 100}, {min_q1_size, 41}])).

cache_miss_test() ->
	?assertMatch(notfound, e2qc_nif:get(cache_miss, key_to_bin(1500))),
	?assertMatch({foo, bar}, cache(cache_miss, 1500, fun() -> {foo, bar} end)),
	?assertMatch(B when is_binary(B), e2qc_nif:get(cache_miss, key_to_bin(1500))).

cache_hit_test() ->
	?assertMatch({foo, bar}, cache(cache_hit, 1500, fun() -> {foo, bar} end)),
	?assertMatch({foo, bar}, cache(cache_hit, 1500, fun() -> {notfoo, notbar} end)).

factorial(1) -> 1;
factorial(N) when is_integer(N) and (N > 1) -> N * factorial(N-1).

slow_func(K) ->
	[math:sqrt(factorial(K)) || _ <- lists:seq(1,200)].
cache_slow_func(K) ->
	e2qc:cache(slow_func, K, fun() ->
		slow_func(K)
	end).
mean(List) -> lists:sum(List) / length(List).
dev(List) -> U = mean(List), mean([(N-U)*(N-U) || N <- List]).
bench(Nums) ->
	e2qc_nif:destroy(slow_func),
	T1 = os:timestamp(),
	[slow_func(N) || N <- Nums],
	T2 = os:timestamp(),
	[cache_slow_func(N) || N <- Nums],
	T3 = os:timestamp(),
	{timer:now_diff(T2, T1) / length(Nums),
		timer:now_diff(T3, T2) / length(Nums)}.
bench_t_tester() ->
	% generate 100 +ve ints to be keys that are vaguely normally distributed
	% (we just add some uniform random numbers together, it will have enough
	% of a hump for our purposes, see central limit theorem)
	Nums = [100 + round(4*lists:sum(
			[crypto:rand_uniform(1,1000) / 1000 || _ <- lists:seq(1,15)]))
		|| _ <- lists:seq(1, 70)],
	TimesZip = [bench(Nums) || _ <- lists:seq(1,50)],
	{NoCacheTimes, CacheTimes} = lists:unzip(TimesZip),

	N = length(CacheTimes),
	S1 = dev(CacheTimes),
	S2 = dev(NoCacheTimes),
	U1 = mean(CacheTimes),
	U2 = mean(NoCacheTimes),

	% compute t-value
	T = (U1 - U2) / math:sqrt(S1/N + S2/N),
	DF = math:pow(S1/N + S2/N, 2) / ((S1/N)*(S1/N) / (N-1) + (S2/N)*(S2/N) / (N-1)),
	io:format("N = ~p, S1 = ~p, S2 = ~p, U1 = ~p, U2 = ~p, T = ~p, DF = ~p",
		[N, S1, S2, U1, U2, T, DF]),

	?assertMatch(Df when (Df >= 40), DF),
	?assertMatch(Tt when (Tt > 3.307), abs(T)), % t-value threshold for 99.9% confidence
	?assert(T < 0).

is_fast_test_() ->
	{timeout, 60,
	fun() -> bench_t_tester() end}.

-endif.
