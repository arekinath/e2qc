Erlang 2Q NIF cache.

This is an implementation of the 2Q Cache Management algorithm (http://www.inf.fu-berlin.de/lehre/WS10/DBS-Tech/Reader/2QBufferManagement.pdf) as an Erlang NIF.

2Q is a refinement of the classic LRU (Least-Recently-Used) cache management algorithm that achieves better hit rates with many common workloads -- especially those that benefit from rejection of sequential scans. In the worst case, it performs no worse than plain LRU and still retains much of its simplicity.

This implementation's primary goals are:
 * a *very* simple to use API, easy to integrate into your project
 * high performance when having high hit rate (ie, hits being fast is preferred over misses being fast)

Cache hits can be zero-copy (using resource binaries) and the updates to the cache structure are deferred to a background thread to avoid blocking the Erlang VM. Benchmarks welcome!

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

You can use the same cache from any number of Erlang processes at once on the same node (and it will be just one shared cache). No passing around handles or pids for the cache, and no extra setup required.

## Changing settings

If you want to adjust the `size` of the cache, or set a different Q1 `ratio` (see the paper on the 2Q algorithm for details; the default is 0.3 or 30%), use the `e2qc:setup` function:

    ok = e2qc:setup(slow_thing, [{size, 16*1024*1024}, {ratio, 0.4}]).

Put this in your startup procedure somewhere and it will configure the `slow_thing` cache with a 16MB size instead of the default 4MB, and a Q1 ratio of 0.4 (the value for the target size of Q1 during eviction will be 6.4MB).

Currently, the call to `e2qc:setup/2` has to happen before the cache is used for the first time (this will be fixed later).

## Statistics

The `e2qc:stats/1` function is useful if you want to know how your cache is doing:

    => e2qc:stats(slow_thing).
    [{hits,5674},{misses,11},{q1size,280},{q2size,735}]

## Deleting or deliberately expiring entries

If you know that an entry in the cache is stale or needs to be evicted, you can use the `e2qc:evict/2` function to clear it out:

    e2qc:evict(slow_thing, OldInput)

Now the next attempt to look for `OldInput` will miss and be re-calculated.

You can also destroy an entire cache if you wish, using `e2qc:teardown/1`. This will destroy the cache and all of its entries entirely (but note that if another call attempts to use it afterwards, it will be re-created implicitly with default settings).

## TODO

 * Calls to `e2qc:setup/2` after cache has already started
 * Timed eviction (expiry)
