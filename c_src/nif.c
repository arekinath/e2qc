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

#include <math.h>

#include "queue.h"
#include "tree.h"
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
	UT_hash_handle hh;
	char *key;
	char *val;
	int size;
	int vsize;
	int ksize;
	struct cache *c;
	struct cache_queue *q;
};

struct cache_incr_node {
	TAILQ_ENTRY(cache_incr_node) entry;
	struct cache_node *node;
};

struct cache_queue {
	TAILQ_HEAD(cache_q, cache_node) head;
	int64_t size;
};

#define FL_DYING	1

/* can take:
	* cache_lock then lookup_lock
	* lookup_lock then ctrl_lock
*/
struct cache {
	int64_t max_size;
	int64_t min_q1_size;
	int64_t hit;
	int64_t miss;
	int flags;

	TAILQ_HEAD(cache_incr_q, cache_incr_node) incr_head;
	ErlNifMutex *ctrl_lock;
	ErlNifCond *check_cond;
	ErlNifTid bg_thread;

	struct cache_queue q1;
	struct cache_queue q2;
	ErlNifRWLock *cache_lock;

	struct cache_node *lookup;
	ErlNifRWLock *lookup_lock;
};

struct atom_node {
	RB_ENTRY(atom_node) entry;
	char *atom;
	struct cache *cache;
};

struct nif_globals {
	RB_HEAD(atom_tree, atom_node) atom_head;
	int atom_count;
	ErlNifRWLock *atom_lock;
};

static ErlNifResourceType *value_type;
static struct nif_globals *gbl;

static int
atom_tree_cmp(struct atom_node *a1, struct atom_node *a2)
{
	return strcmp(a1->atom, a2->atom);
}

RB_GENERATE(atom_tree, atom_node, entry, atom_tree_cmp);

static void
destroy_cache_node(struct cache_node *n)
{
	struct cache_incr_node *in, *nextin;

	TAILQ_REMOVE(&(n->q->head), n, entry);
	n->q->size -= n->size;
	n->q = NULL;
	HASH_DEL(n->c->lookup, n);

	nextin = TAILQ_FIRST(&(n->c->incr_head));
	while ((in = nextin)) {
		nextin = TAILQ_NEXT(in, entry);
		if (in->node == n) {
			TAILQ_REMOVE(&(n->c->incr_head), in, entry);
			in->node = 0;
			enif_free(in);
		}
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
	int lastloop = 0;
	enif_mutex_lock(c->ctrl_lock);
	while (1) {
		if (!lastloop)
			enif_cond_wait(c->check_cond, c->ctrl_lock);

		if (c->flags & FL_DYING) {
			break;
		}

		while (!TAILQ_EMPTY(&(c->incr_head))) {
			struct cache_incr_node *n;
			n = TAILQ_FIRST(&(c->incr_head));
			TAILQ_REMOVE(&(c->incr_head), n, entry);

			enif_mutex_unlock(c->ctrl_lock);
			enif_rwlock_rwlock(c->cache_lock);

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

			enif_rwlock_rwunlock(c->cache_lock);
			enif_mutex_lock(c->ctrl_lock);
			lastloop = 1;
		}

		enif_mutex_unlock(c->ctrl_lock);

		enif_rwlock_rwlock(c->cache_lock);
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

			enif_mutex_unlock(c->ctrl_lock);
			enif_rwlock_rwunlock(c->lookup_lock);
			lastloop = 1;
		}
		enif_rwlock_rwunlock(c->cache_lock);

		enif_mutex_lock(c->ctrl_lock);
	}

	enif_mutex_unlock(c->ctrl_lock);

	/* we can do all 3 here since we will never have to avoid
	   deadlock against ourselves and we're the only ones who do
	   ctrl_lock then cache_lock */
	enif_rwlock_rwlock(c->cache_lock);
	enif_rwlock_rwlock(c->lookup_lock);
	enif_mutex_lock(c->ctrl_lock);
	/* TODO: clean everything up */

	enif_mutex_unlock(c->ctrl_lock);
	enif_rwlock_rwunlock(c->lookup_lock);
	enif_rwlock_rwunlock(c->cache_lock);

	return 0;
}

static struct cache *
get_cache(char *atom)
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
new_cache(char *atom, int max_size, int min_q1_size)
{
	struct cache *c;
	struct atom_node *an;

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
	TAILQ_INIT(&(c->incr_head));

	an = enif_alloc(sizeof(*an));
	memset(an, 0, sizeof(*an));
	an->atom = atom;
	an->cache = c;

	enif_rwlock_rwlock(gbl->atom_lock);
	RB_INSERT(atom_tree, &(gbl->atom_head), an);
	enif_thread_create("cachethread", &(c->bg_thread), cache_bg_thread, c, NULL);
	enif_rwlock_rwunlock(gbl->atom_lock);

	return c;
}

static ERL_NIF_TERM
destroy(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	unsigned int alen;
	char *atom;
	struct cache *c;

	if (!enif_get_atom_length(env, argv[0], &alen, ERL_NIF_LATIN1))
		return enif_make_badarg(env);
	atom = enif_alloc(alen + 1);
	if (!enif_get_atom(env, argv[0], atom, alen + 1, ERL_NIF_LATIN1))
		goto badarg;

	if ((c = get_cache(atom))) {
		enif_free(atom);
		return enif_make_atom(env, "ok");
	} else {
		enif_free(atom);
		return enif_make_atom(env, "notfound");
	}

badarg:
	enif_free(atom);
	return enif_make_badarg(env);
}

static ERL_NIF_TERM
create(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	unsigned int alen;
	char *atom;
	int64_t max_size, min_q1_size;
	struct cache *c;

	if (!enif_get_atom_length(env, argv[0], &alen, ERL_NIF_LATIN1))
		return enif_make_badarg(env);
	atom = enif_alloc(alen + 1);
	if (!enif_get_atom(env, argv[0], atom, alen + 1, ERL_NIF_LATIN1))
		goto badarg;

	if (!enif_get_int64(env, argv[1], &max_size))
		goto badarg;
	if (!enif_get_int64(env, argv[2], &min_q1_size))
		goto badarg;

	if ((c = get_cache(atom))) {
		enif_free(atom);
		return enif_make_atom(env, "already_exists");
	} else {
		c = new_cache(atom, max_size, min_q1_size);
		return enif_make_atom(env, "ok");
	}

badarg:
	enif_free(atom);
	return enif_make_badarg(env);
}

static ERL_NIF_TERM
stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	unsigned int alen;
	char *atom;
	ERL_NIF_TERM ret, q1s, q2s;
	struct cache *c;

	if (!enif_get_atom_length(env, argv[0], &alen, ERL_NIF_LATIN1))
		return enif_make_badarg(env);
	atom = enif_alloc(alen + 1);
	if (!enif_get_atom(env, argv[0], atom, alen + 1, ERL_NIF_LATIN1))
		goto badarg;

	if ((c = get_cache(atom))) {
		enif_free(atom);
		enif_rwlock_rlock(c->cache_lock);
		q1s = enif_make_int64(env, c->q1.size);
		q2s = enif_make_int64(env, c->q2.size);
		enif_rwlock_runlock(c->cache_lock);
		enif_mutex_lock(c->ctrl_lock);
		ret = enif_make_tuple4(env,
			enif_make_int64(env, c->hit),
			enif_make_int64(env, c->miss),
			q1s, q2s);
		enif_mutex_unlock(c->ctrl_lock);
		return ret;
	} else {
		enif_free(atom);
		return enif_make_atom(env, "notfound");
	}

badarg:
	enif_free(atom);
	return enif_make_badarg(env);
}

static ERL_NIF_TERM
put(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	unsigned int alen;
	char *atom;
	ErlNifBinary kbin, vbin;
	struct cache *c;
	struct cache_node *n;

	if (!enif_get_atom_length(env, argv[0], &alen, ERL_NIF_LATIN1))
		return enif_make_badarg(env);
	atom = enif_alloc(alen + 1);
	if (!enif_get_atom(env, argv[0], atom, alen + 1, ERL_NIF_LATIN1))
		goto badarg;

	if (!enif_inspect_binary(env, argv[1], &kbin))
		goto badarg;
	if (!enif_inspect_binary(env, argv[2], &vbin))
		goto badarg;

	if ((c = get_cache(atom))) {
		enif_free(atom);
	} else {
		int64_t max_size, min_q1_size;
		if (!enif_get_int64(env, argv[3], &max_size))
			return enif_make_badarg(env);
		if (!enif_get_int64(env, argv[4], &min_q1_size))
			return enif_make_badarg(env);
		c = new_cache(atom, max_size, min_q1_size);
	}

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

	enif_rwlock_rwlock(c->cache_lock);
	enif_rwlock_rwlock(c->lookup_lock);
	TAILQ_INSERT_HEAD(&(c->q1.head), n, entry);
	c->q1.size += n->size;
	HASH_ADD_KEYPTR(hh, c->lookup, n->key, n->ksize, n);
	enif_rwlock_rwunlock(c->lookup_lock);
	enif_rwlock_rwunlock(c->cache_lock);

	enif_cond_broadcast(c->check_cond);

	return enif_make_atom(env, "ok");
badarg:
	enif_free(atom);
	return enif_make_badarg(env);
}

static ERL_NIF_TERM
get(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	unsigned int alen;
	char *atom;
	ErlNifBinary kbin;
	struct cache *c;
	struct cache_node *n;
	struct cache_incr_node *in;
	ERL_NIF_TERM ret;

	if (!enif_get_atom_length(env, argv[0], &alen, ERL_NIF_LATIN1))
		return enif_make_badarg(env);
	atom = enif_alloc(alen + 1);
	if (!enif_get_atom(env, argv[0], atom, alen + 1, ERL_NIF_LATIN1))
		goto badarg;

	if (!enif_inspect_binary(env, argv[1], &kbin))
		goto badarg;

	if ((c = get_cache(atom))) {
		enif_free(atom);

		enif_rwlock_rlock(c->lookup_lock);
		HASH_FIND(hh, c->lookup, kbin.data, kbin.size, n);
		if (!n) {
			enif_rwlock_runlock(c->lookup_lock);
			enif_mutex_lock(c->ctrl_lock);
			c->miss++;
			enif_mutex_unlock(c->ctrl_lock);
			return enif_make_atom(env, "notfound");
		}

		in = enif_alloc(sizeof(*in));
		memset(in, 0, sizeof(*in));
		in->node = n;

		enif_mutex_lock(c->ctrl_lock);
		TAILQ_INSERT_TAIL(&(c->incr_head), in, entry);
		c->hit++;
		enif_mutex_unlock(c->ctrl_lock);
		enif_cond_broadcast(c->check_cond);

		ret = enif_make_resource_binary(env, n->val, n->val, n->vsize);
		enif_rwlock_runlock(c->lookup_lock);

		return ret;

	} else {
		enif_free(atom);
		return enif_make_atom(env, "notfound");
	}

badarg:
	enif_free(atom);
	return enif_make_badarg(env);
}

static int
load_cb(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	ErlNifResourceFlags tried;

	gbl = enif_alloc(sizeof(*gbl));
	memset(gbl, 0, sizeof(*gbl));
	RB_INIT(&(gbl->atom_head));
	gbl->atom_lock = enif_rwlock_create("gbl->atom_lock");

	value_type = enif_open_resource_type(env, NULL, "value", NULL, ERL_NIF_RT_CREATE, &tried);

	return 0;
}

static ErlNifFunc nif_funcs[] =
{
	{"get", 2, get},
	{"put", 3, put},
	{"put", 5, put},
	{"create", 3, create},
	{"destroy", 1, destroy},
	{"destroy", 2, destroy},
	{"stats", 1, stats}
};

ERL_NIF_INIT(e2qc_nif, nif_funcs, load_cb, NULL, NULL, NULL)
