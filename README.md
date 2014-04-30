Erlang 2Q NIF cache.

This is an implementation of the 2Q Cache Management algorithm (http://www.inf.fu-berlin.de/lehre/WS10/DBS-Tech/Reader/2QBufferManagement.pdf) as an Erlang NIF.

Its primary goals are:
 * a *very* simple to use API, easy to integrate into your project
 * high performance when having high hit rate (ie, hits being fast is preferred over misses being fast)

Cache hits are zero-copy (using resource binaries) and the updates to the cache structure are deferred to a background thread to avoid blocking the Erlang VM. Benchmarks welcome!

## How to add e2qc to your project

1. Add e2qc as a `rebar.config` dependency in your project:

    ```
    {deps, [
        {e2qc, ".*", {git, "git://github.com/arekinath/e2qc.git", "HEAD"}}
    ]}
    ```

2. Use it! Wrap your slow processing that you want to cache in a call to `e2qc:cache`:

    ```
    some_function(Input) ->
        do_slow_thing(Input).

    becomes

    some_function(Input) ->
        e2qc:cache(slow_thing, Input, fun() ->
            do_slow_thing(Input)
        end).
    ```

It's really that simple. Each "cache" is named by a unique atom (in this case we've used a cache called `slow_thing`). You don't need to explicitly create or configure the cache before using it -- it will be created on the first use. The default configuration will cache up to 4MB of data.

## Changing settings

If you want to adjust the size of the cache, or set a different Q1:Q2 ratio (see the paper on the 2Q algorithm for details; the default is 0.3 or 30%), use the `e2qc:setup` function:

    ok = e2qc:setup(slow_thing, [{size, 16*1024*1024}]).

Put this in your startup procedure somewhere and it will configure the `slow_thing` cache with an 16MB size instead of the default 4MB.

Currently, the call to `e2qc:setup` has to happen before the cache is used for the first time (this will be fixed later).

## Statistics

The `e2qc:stats/1` function is useful if you want to know how your cache is doing:

    => e2qc:stats(slow_thing).
    [{hits,5674},{misses,11},{q1size,280},{q2size,735}]

## Deleting or deliberately expiring entries

Yeah this isn't done yet. Will be there shortly.
