/*
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
*/

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <math.h>

#include "queue.h"
#include "tree.h"

/* use paul hsieh's hash function */
#define HASH_FUNCTION	HASH_SFH
#include "uthash.h"

#include "erl_nif.h"

/*
   * 2q cache made using TAILQs
   * uthash table for lookup of key -> queue node
   * keys and values are binaries
   * values are in TAILQ node (they are resource binaries)
     uthash nodes only have pointer to TAILQ node

   * global RB tree to find a cache (2q+hash) by atom name
   * background thread per cache to handle promotion and eviction
   * per-cache "promotion increment queue" that gets handled by bg thread
   * always do promotion before eviction
   * waitcond to wake up the bg thread upon insertion to queue or cache

   * can either explicitly create a cache with its atom name and settings
     or implicitly create on first use (gets settings from application:get_env
     or falls back to hard-coded defaults)
   * config: max total size (excl. overheads)     	default 8M
             2q fill ratio  					  	default 1:1

   * rwlock around the global RB tree
   * rwlock on each cache covering hash + queues
   * mutex on each cache's promotion increment queue
*/

struct cache_node {
	TAILQ_ENTRY(cache_node) entry;
	RB_ENTRY(cache_node) expiry_entry;
	UT_hash_handle hh;
	char *key;			/* key buffer, from enif_alloc */
	char *val;			/* value buffer, from enif_alloc_resource */
	int size;			/* total size (bytes) = vsize + ksize */
	int vsize;			/* size of value in bytes */
	int ksize;			/* size of key in bytes */
	struct timespec expiry;  /* expiry time */
	struct cache *c;	/* the cache we belong to */
	struct cache_queue *q;	/* the cache_queue we are currently on */
};

/* deferred promotion operations are queued up on the "incr_queue" of the cache
   this is a node on that queue */
struct cache_incr_node {
	TAILQ_ENTRY(cache_incr_node) entry;
	struct cache_node *node;
};

struct cache_queue {
	TAILQ_HEAD(cache_q, cache_node) head;
	ErlNifUInt64 size;		/* sum of node->size for all nodes in the queue */
};

#define FL_DYING		1

struct atom_node;

#define N_INCR_BKT		8

/* lock ordering: cache_lock then lookup_lock then ctrl_lock */
struct cache {
	ErlNifUInt64 max_size;		/* these are only set at construction */
	ErlNifUInt64 min_q1_size;
	struct atom_node *atom_node;

	ErlNifUInt64 hit;			/* protected by ctrl_lock */
	ErlNifUInt64 miss;
	ErlNifUInt64 wakeups, dud_wakeups;
	int flags;

	TAILQ_HEAD(cache_incr_q, cache_incr_node) incr_head[N_INCR_BKT];
	ErlNifMutex *incr_lock[N_INCR_BKT];

	int incr_count;
	ErlNifMutex *ctrl_lock;
	ErlNifCond *check_cond;
	ErlNifTid bg_thread;

	struct cache_queue q1; /* protected by cache_lock */
	struct cache_queue q2;
	RB_HEAD(expiry_tree, cache_node) expiry_head;
	ErlNifRWLock *cache_lock;

	struct cache_node *lookup; /* a uthash, protected by lookup_lock */
	ErlNifRWLock *lookup_lock;
};

/* a node in the RB tree of atom -> struct cache */
struct atom_node {
	RB_ENTRY(atom_node) entry;
	ERL_NIF_TERM atom;					/* inside atom_env */
	struct cache *cache;
};

struct nif_globals {
	RB_HEAD(atom_tree, atom_node) atom_head;
	int atom_count;
	ErlNifRWLock *atom_lock;
	ErlNifEnv *atom_env;
};

/* the resource type used for struct cache_node -> val */
static ErlNifResourceType *value_type;

static struct nif_globals *gbl;

/* comparison operator for the atom -> cache RB tree */
static int
atom_tree_cmp(struct atom_node *a1, struct atom_node *a2)
{
	return enif_compare(a1->atom, a2->atom);
}

RB_GENERATE(atom_tree, atom_node, entry, atom_tree_cmp);

static int
expiry_tree_cmp(struct cache_node *n1, struct cache_node *n2)
{
	if (n1->expiry.tv_sec < n2->expiry.tv_sec)
		return -1;
	if (n1->expiry.tv_sec > n2->expiry.tv_sec)
		return 1;
	if (n1->expiry.tv_nsec < n2->expiry.tv_nsec)
		return -1;
	if (n1->expiry.tv_nsec > n2->expiry.tv_nsec)
		return 1;
	return 0;
}

RB_GENERATE(expiry_tree, cache_node, expiry_entry, expiry_tree_cmp);

/* platform wrapper around clock_gettime (even though it's POSIX, some
   people, cough OSX cough, don't implement it) */
#if defined(__MACH__)
#	include <mach/clock.h>
#	include <mach/mach.h>
#endif

void
clock_now(struct timespec *ts)
{
#if defined(__MACH__)
	/* this is not quite monotonic time, but hopefully it's good enough */
	clock_serv_t cclock;
	mach_timespec_t mts;
	host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);
	ts->tv_sec = mts.tv_sec;
	ts->tv_nsec = mts.tv_nsec;
#else
	clock_gettime(CLOCK_MONOTONIC, ts);
#endif
}

/* to call this you must have all of the caches locks held
   (cache_lock, lookup_lock and ctrl_lock)! */
static void
destroy_cache_node(struct cache_node *n)
{
	struct cache_incr_node *in, *nextin;
	int i;

	TAILQ_REMOVE(&(n->q->head), n, entry);
	n->q->size -= n->size;
	n->q = NULL;
	HASH_DEL(n->c->lookup, n);
	if (n->expiry.tv_sec != 0)
		RB_REMOVE(expiry_tree, &(n->c->expiry_head), n);

	for (i = 0; i < N_INCR_BKT; ++i) {
		enif_mutex_lock(n->c->incr_lock[i]);
		nextin = TAILQ_FIRST(&(n->c->incr_head[i]));
		while ((in = nextin)) {
			nextin = TAILQ_NEXT(in, entry);
			if (in->node == n) {
				TAILQ_REMOVE(&(n->c->incr_head[i]), in, entry);
				__sync_sub_and_fetch(&(n->c->incr_count), 1);
				in->node = 0;
				enif_free(in);
			}
		}
		enif_mutex_unlock(n->c->incr_lock[i]);
	}

	n->c = NULL;
	enif_free(n->key);
	n->key = NULL;
	enif_release_resource(n->val);
	n->val = NULL;
	enif_free(n);
}

static void *
cache_bg_thread(void *arg)
{
	struct cache *c = (struct cache *)arg;
	int i, dud;

	while (1) {
		enif_mutex_lock(c->ctrl_lock);

		/* if we've been told to die, quit this loop and start cleaning up */
		if (c->flags & FL_DYING) {
			enif_mutex_unlock(c->ctrl_lock);
			break;
		}

		/* sleep until there is work to do */
		enif_cond_wait(c->check_cond, c->ctrl_lock);

		__sync_add_and_fetch(&(c->wakeups), 1);
		dud = 1;

		/* we have to let go of ctrl_lock so we can take cache_lock then
		   ctrl_lock again to get them back in the right order */
		enif_mutex_unlock(c->ctrl_lock);
		enif_rwlock_rwlock(c->cache_lock);
		enif_mutex_lock(c->ctrl_lock);

		/* first process the promotion queue before we do any evicting */
		for (i = 0; i < N_INCR_BKT; ++i) {
			enif_mutex_lock(c->incr_lock[i]);
			while (!TAILQ_EMPTY(&(c->incr_head[i]))) {
				struct cache_incr_node *n;
				n = TAILQ_FIRST(&(c->incr_head[i]));
				TAILQ_REMOVE(&(c->incr_head[i]), n, entry);
				__sync_sub_and_fetch(&(c->incr_count), 1);

				dud = 0;

				/* let go of the ctrl_lock here, we don't need it when we aren't looking
				   at the incr_queue, and this way other threads can use it while we shuffle
				   queue nodes around */
				enif_mutex_unlock(c->incr_lock[i]);
				enif_mutex_unlock(c->ctrl_lock);

				if (n->node->q == &(c->q1)) {
					TAILQ_REMOVE(&(c->q1.head), n->node, entry);
					c->q1.size -= n->node->size;
					TAILQ_INSERT_HEAD(&(c->q2.head), n->node, entry);
					n->node->q = &(c->q2);
					c->q2.size += n->node->size;

				} else if (n->node->q == &(c->q2)) {
					TAILQ_REMOVE(&(c->q2.head), n->node, entry);
					TAILQ_INSERT_HEAD(&(c->q2.head), n->node, entry);
				}

				enif_free(n);

				/* take the ctrl_lock back again for the next loop around */
				enif_mutex_lock(c->ctrl_lock);
				enif_mutex_lock(c->incr_lock[i]);
			}
			enif_mutex_unlock(c->incr_lock[i]);
		}

		/* let go of the ctrl_lock here for two reasons:
		   1. avoid lock inversion, because if we have evictions to do we
		      will need to take lookup_lock, and we must take lookup_lock
		      before taking ctrl_lock
		   2. if we don't need to do evictions, we're done with the structures
		      that are behind ctrl_lock so we should give it up for others */
		enif_mutex_unlock(c->ctrl_lock);

		/* do timed evictions -- if anything has expired, nuke it */
		{
			struct cache_node *n;
			if ((n = RB_MIN(expiry_tree, &(c->expiry_head)))) {
				struct timespec now;
				clock_now(&now);
				while (n && n->expiry.tv_sec < now.tv_sec) {
					enif_mutex_lock(c->ctrl_lock);
					dud = 0;
					destroy_cache_node(n);
					enif_mutex_unlock(c->ctrl_lock);
					n = RB_MIN(expiry_tree, &(c->expiry_head));
				}
			}
		}

		/* now check if we need to do ordinary size limit evictions */
		if (c->q1.size + c->q2.size > c->max_size) {
			enif_rwlock_rwlock(c->lookup_lock);
			enif_mutex_lock(c->ctrl_lock);

			while ((c->q1.size + c->q2.size > c->max_size) &&
					(c->q1.size > c->min_q1_size)) {
				struct cache_node *n;
				n = TAILQ_LAST(&(c->q1.head), cache_q);
				destroy_cache_node(n);
			}

			while (c->q1.size + c->q2.size > c->max_size) {
				struct cache_node *n;
				n = TAILQ_LAST(&(c->q2.head), cache_q);
				destroy_cache_node(n);
			}

			dud = 0;

			enif_mutex_unlock(c->ctrl_lock);
			enif_rwlock_rwunlock(c->lookup_lock);
		}

		if (dud)
			__sync_add_and_fetch(&(c->dud_wakeups), 1);
		/* now let go of the cache_lock that we took right back at the start of
		   this iteration */
		enif_rwlock_rwunlock(c->cache_lock);
	}

	/* first remove us from the atom_tree, so we get no new operations coming in */
	enif_rwlock_rwlock(gbl->atom_lock);
	RB_REMOVE(atom_tree, &(gbl->atom_head), c->atom_node);
	enif_rwlock_rwunlock(gbl->atom_lock);
	enif_free(c->atom_node);

	/* now take all of our locks, to make sure any pending operations are done */
	enif_rwlock_rwlock(c->cache_lock);
	enif_rwlock_rwlock(c->lookup_lock);
	enif_mutex_lock(c->ctrl_lock);

	c->atom_node = NULL;

	/* free the actual cache queues */
	{
		struct cache_node *n, *nextn;
		nextn = TAILQ_FIRST(&(c->q1.head));
		while ((n = nextn)) {
			nextn = TAILQ_NEXT(n, entry);
			destroy_cache_node(n);
		}
		nextn = TAILQ_FIRST(&(c->q2.head));
		while ((n = nextn)) {
			nextn = TAILQ_NEXT(n, entry);
			destroy_cache_node(n);
		}
	}

	for (i = 0; i < N_INCR_BKT; ++i)
		enif_mutex_lock(c->incr_lock[i]);

	/* free the incr_queue */
	for (i = 0; i < N_INCR_BKT; ++i) {
		struct cache_incr_node *in, *nextin;
		nextin = TAILQ_FIRST(&(c->incr_head[i]));
		while ((in = nextin)) {
			nextin = TAILQ_NEXT(in, entry);
			TAILQ_REMOVE(&(c->incr_head[i]), in, entry);
			in->node = 0;
			enif_free(in);
		}
		enif_mutex_unlock(c->incr_lock[i]);
		enif_mutex_destroy(c->incr_lock[i]);
	}

	/* unlock and destroy! */
	enif_cond_destroy(c->check_cond);

	enif_mutex_unlock(c->ctrl_lock);
	enif_mutex_destroy(c->ctrl_lock);

	enif_rwlock_rwunlock(c->lookup_lock);
	enif_rwlock_destroy(c->lookup_lock);

	enif_rwlock_rwunlock(c->cache_lock);
	enif_rwlock_destroy(c->cache_lock);

	enif_free(c);

	return 0;
}

static struct cache *
get_cache(ERL_NIF_TERM atom)
{
	struct atom_node n, *res;
	struct cache *ret = NULL;

	memset(&n, 0, sizeof(n));
	n.atom = atom;

	enif_rwlock_rlock(gbl->atom_lock);
	res = RB_FIND(atom_tree, &(gbl->atom_head), &n);
	if (res)
		ret = res->cache;
	enif_rwlock_runlock(gbl->atom_lock);

	return ret;
}

static struct cache *
new_cache(ERL_NIF_TERM atom, int max_size, int min_q1_size)
{
	struct cache *c;
	struct atom_node *an;
	int i;

	c = enif_alloc(sizeof(*c));
	memset(c, 0, sizeof(*c));
	c->max_size = max_size;
	c->min_q1_size = min_q1_size;
	c->lookup_lock = enif_rwlock_create("cache->lookup_lock");
	c->cache_lock = enif_rwlock_create("cache->cache_lock");
	c->ctrl_lock = enif_mutex_create("cache->ctrl_lock");
	c->check_cond = enif_cond_create("cache->check_cond");
	TAILQ_INIT(&(c->q1.head));
	TAILQ_INIT(&(c->q2.head));
	for (i = 0; i < N_INCR_BKT; ++i) {
		TAILQ_INIT(&(c->incr_head[i]));
		c->incr_lock[i] = enif_mutex_create("cache->incr_lock");
	}
	RB_INIT(&(c->expiry_head));

	an = enif_alloc(sizeof(*an));
	memset(an, 0, sizeof(*an));
	an->atom = enif_make_copy(gbl->atom_env, atom);
	an->cache = c;

	c->atom_node = an;

	enif_rwlock_rwlock(gbl->atom_lock);
	RB_INSERT(atom_tree, &(gbl->atom_head), an);
	/* start the background thread for the cache. after this, the bg thread now
	   owns the cache and all its data and will free it at exit */
	enif_thread_create("cachethread", &(c->bg_thread), cache_bg_thread, c, NULL);
	enif_rwlock_rwunlock(gbl->atom_lock);

	return c;
}

/* destroy(Cache :: atom()) -- destroys and entire cache
   destroy(Cache :: atom(), Key :: binary()) -- removes an entry
   		from a cache */
static ERL_NIF_TERM
destroy(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM atom;
	struct cache *c;
	ErlNifBinary kbin;
	struct cache_node *n;

	if (!enif_is_atom(env, argv[0]))
		return enif_make_badarg(env);
	atom = argv[0];

	if ((c = get_cache(atom))) {
		if (argc == 2) {
			if (!enif_inspect_binary(env, argv[1], &kbin))
				return enif_make_badarg(env);

			enif_rwlock_rwlock(c->cache_lock);
			enif_rwlock_rwlock(c->lookup_lock);

			HASH_FIND(hh, c->lookup, kbin.data, kbin.size, n);
			if (!n) {
				enif_rwlock_rwunlock(c->lookup_lock);
				enif_rwlock_rwunlock(c->cache_lock);
				return enif_make_atom(env, "notfound");
			}

			enif_mutex_lock(c->ctrl_lock);

			destroy_cache_node(n);

			enif_mutex_unlock(c->ctrl_lock);
			enif_rwlock_rwunlock(c->lookup_lock);
			enif_rwlock_rwunlock(c->cache_lock);

			enif_consume_timeslice(env, 50);

			return enif_make_atom(env, "ok");

		} else {
			enif_mutex_lock(c->ctrl_lock);
			c->flags |= FL_DYING;
			enif_mutex_unlock(c->ctrl_lock);
			enif_cond_broadcast(c->check_cond);

			enif_thread_join(c->bg_thread, NULL);

			enif_consume_timeslice(env, 100);

			return enif_make_atom(env, "ok");
		}

		return enif_make_atom(env, "ok");
	}

	return enif_make_atom(env, "notfound");
}

/* create(Cache :: atom(), MaxSize :: integer(), MinQ1Size :: integer()) */
static ERL_NIF_TERM
create(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM atom;
	ErlNifUInt64 max_size, min_q1_size;
	struct cache *c;

	if (!enif_is_atom(env, argv[0]))
		return enif_make_badarg(env);
	atom = argv[0];

	if (!enif_get_uint64(env, argv[1], &max_size))
		return enif_make_badarg(env);
	if (!enif_get_uint64(env, argv[2], &min_q1_size))
		return enif_make_badarg(env);

	if ((c = get_cache(atom))) {
		ERL_NIF_TERM ret = enif_make_atom(env, "already_exists");
		enif_consume_timeslice(env, 5);

		enif_rwlock_rwlock(c->cache_lock);
		/* expansion is safe because we don't have to engage the background
		   thread and won't cause sudden eviction pressure
		   TODO: a nice way to shrink the cache without seizing it up */
		if (c->max_size < max_size && c->min_q1_size < min_q1_size) {
			c->max_size = max_size;
			c->min_q1_size = min_q1_size;
			enif_rwlock_rwunlock(c->cache_lock);

			ret = enif_make_atom(env, "ok");
			enif_consume_timeslice(env, 10);
		} else {
			enif_rwlock_rwunlock(c->cache_lock);
		}

		return ret;
	} else {
		c = new_cache(atom, max_size, min_q1_size);
		enif_consume_timeslice(env, 20);
		return enif_make_atom(env, "ok");
	}
}

static ERL_NIF_TERM
stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM atom;
	ERL_NIF_TERM ret, q1s, q2s, incrs, wakeups, duds;
	struct cache *c;

	if (!enif_is_atom(env, argv[0]))
		return enif_make_badarg(env);
	atom = argv[0];

	if ((c = get_cache(atom))) {
		enif_rwlock_rlock(c->cache_lock);
		q1s = enif_make_uint64(env, c->q1.size);
		q2s = enif_make_uint64(env, c->q2.size);
		incrs = enif_make_uint64(env, __sync_fetch_and_add(&(c->incr_count), 0));
		wakeups = enif_make_uint64(env, __sync_fetch_and_add(&(c->wakeups), 0));
		duds = enif_make_uint64(env, __sync_fetch_and_add(&(c->dud_wakeups), 0));
		enif_rwlock_runlock(c->cache_lock);
		ret = enif_make_tuple7(env,
			enif_make_uint64(env, c->hit),
			enif_make_uint64(env, c->miss),
			q1s, q2s, incrs, wakeups, duds);
		enif_consume_timeslice(env, 10);
		return ret;
	} else {
		return enif_make_atom(env, "notfound");
	}
}

static ERL_NIF_TERM
put(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM atom;
	ErlNifBinary kbin, vbin;
	struct cache *c;
	struct cache_node *n, *ng;
	ErlNifUInt64 lifetime = 0;

	if (!enif_is_atom(env, argv[0]))
		return enif_make_badarg(env);
	atom = argv[0];

	if (!enif_inspect_binary(env, argv[1], &kbin))
		return enif_make_badarg(env);
	if (!enif_inspect_binary(env, argv[2], &vbin))
		return enif_make_badarg(env);

	if ((c = get_cache(atom))) {
		enif_consume_timeslice(env, 1);

	} else {
		/* if we've been asked to put() in to a cache that doesn't exist yet
		   then we should create it! */
		ErlNifUInt64 max_size, min_q1_size;
		if (!enif_get_uint64(env, argv[3], &max_size))
			return enif_make_badarg(env);
		if (!enif_get_uint64(env, argv[4], &min_q1_size))
			return enif_make_badarg(env);
		c = new_cache(atom, max_size, min_q1_size);
		enif_consume_timeslice(env, 20);
	}

	if (argc > 5)
		if (!enif_get_uint64(env, argv[5], &lifetime))
			return enif_make_badarg(env);

	n = enif_alloc(sizeof(*n));
	memset(n, 0, sizeof(*n));
	n->c = c;
	n->vsize = vbin.size;
	n->ksize = kbin.size;
	n->size = vbin.size + kbin.size;
	n->key = enif_alloc(kbin.size);
	memcpy(n->key, kbin.data, kbin.size);
	n->val = enif_alloc_resource(value_type, vbin.size);
	memcpy(n->val, vbin.data, vbin.size);
	n->q = &(c->q1);
	if (lifetime) {
		clock_now(&(n->expiry));
		n->expiry.tv_sec += lifetime;
	}

	enif_rwlock_rwlock(c->cache_lock);
	enif_rwlock_rwlock(c->lookup_lock);
	HASH_FIND(hh, c->lookup, kbin.data, kbin.size, ng);
	if (ng) {
		enif_mutex_lock(c->ctrl_lock);
		destroy_cache_node(ng);
		enif_mutex_unlock(c->ctrl_lock);
	}
	TAILQ_INSERT_HEAD(&(c->q1.head), n, entry);
	c->q1.size += n->size;
	HASH_ADD_KEYPTR(hh, c->lookup, n->key, n->ksize, n);
	if (lifetime) {
		struct cache_node *rn;
		rn = RB_INSERT(expiry_tree, &(c->expiry_head), n);
		/* it's possible to get two timestamps that are the same, if this happens
		   just bump us forwards by 1 usec until we're unique */
		while (rn != NULL) {
			++(n->expiry.tv_nsec);
			rn = RB_INSERT(expiry_tree, &(c->expiry_head), n);
		}
	}
	enif_rwlock_rwunlock(c->lookup_lock);
	enif_rwlock_rwunlock(c->cache_lock);

	enif_cond_broadcast(c->check_cond);
	enif_consume_timeslice(env, 50);

	return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM
get(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM atom;
	ErlNifBinary kbin;
	struct cache *c;
	struct cache_node *n;
	struct cache_incr_node *in;
	struct timespec now;
	int incrqs, hashv, bkt;
	ERL_NIF_TERM ret;
	ErlNifTid tid;

	if (!enif_is_atom(env, argv[0]))
		return enif_make_badarg(env);
	atom = argv[0];

	if (!enif_inspect_binary(env, argv[1], &kbin))
		return enif_make_badarg(env);

	if ((c = get_cache(atom))) {
		enif_rwlock_rlock(c->lookup_lock);
		HASH_FIND(hh, c->lookup, kbin.data, kbin.size, n);
		if (!n) {
			enif_rwlock_runlock(c->lookup_lock);
			__sync_add_and_fetch(&c->miss, 1);
			enif_consume_timeslice(env, 10);
			return enif_make_atom(env, "notfound");
		}

		if (n->expiry.tv_sec != 0) {
			clock_now(&now);
			if (n->expiry.tv_sec < now.tv_sec) {
				enif_rwlock_runlock(c->lookup_lock);
				__sync_add_and_fetch(&c->miss, 1);
				enif_consume_timeslice(env, 10);
				return enif_make_atom(env, "notfound");
			}
		}

		in = enif_alloc(sizeof(*in));
		memset(in, 0, sizeof(*in));
		in->node = n;
		__sync_add_and_fetch(&c->hit, 1);

		tid = enif_thread_self();
		HASH_SFH(&tid, sizeof(ErlNifTid), N_INCR_BKT, hashv, bkt);
		enif_mutex_lock(c->incr_lock[bkt]);
		TAILQ_INSERT_TAIL(&(c->incr_head[bkt]), in, entry);
		enif_mutex_unlock(c->incr_lock[bkt]);
		incrqs = __sync_add_and_fetch(&(c->incr_count), 1);

		ret = enif_make_resource_binary(env, n->val, n->val, n->vsize);
		enif_rwlock_runlock(c->lookup_lock);

		if (incrqs > 1024)
			enif_cond_broadcast(c->check_cond);

		enif_consume_timeslice(env, 20);

		return ret;

	}

	return enif_make_atom(env, "notfound");
}

static int
load_cb(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	ErlNifResourceFlags tried;

	gbl = enif_alloc(sizeof(*gbl));
	memset(gbl, 0, sizeof(*gbl));
	RB_INIT(&(gbl->atom_head));
	gbl->atom_lock = enif_rwlock_create("gbl->atom_lock");
	gbl->atom_env = enif_alloc_env();

	value_type = enif_open_resource_type(env, NULL, "value", NULL,
		ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, &tried);

	return 0;
}

static void
unload_cb(ErlNifEnv *env, void *priv_data)
{
	struct atom_node *an;

	enif_rwlock_rwlock(gbl->atom_lock);

	/* when we unload, we want to tell all of the active caches to die,
	   then join() their bg_threads to wait until they're completely gone */
	while ((an = RB_MIN(atom_tree, &(gbl->atom_head)))) {
		struct cache *c = an->cache;
		enif_rwlock_rwunlock(gbl->atom_lock);

		enif_mutex_lock(c->ctrl_lock);
		c->flags |= FL_DYING;
		enif_mutex_unlock(c->ctrl_lock);
		enif_cond_broadcast(c->check_cond);

		enif_thread_join(c->bg_thread, NULL);

		enif_rwlock_rwlock(gbl->atom_lock);
	}

	enif_rwlock_rwunlock(gbl->atom_lock);
	enif_rwlock_destroy(gbl->atom_lock);
	enif_clear_env(gbl->atom_env);
	enif_free(gbl);

	gbl = NULL;
}

static ErlNifFunc nif_funcs[] =
{
	{"get", 2, get},
	{"put", 5, put},
	{"put", 6, put},
	{"create", 3, create},
	{"destroy", 1, destroy},
	{"destroy", 2, destroy},
	{"stats", 1, stats}
};

ERL_NIF_INIT(e2qc_nif, nif_funcs, load_cb, NULL, NULL, unload_cb)
