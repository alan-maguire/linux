// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include "btf.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

struct btf;

#define BTF_INVALID_ID	((__u32)-1)

enum btf_reconcile_state {
	BTF_UNNEEDED = 0,
	BTF_UNMAPPED = 1,
	BTF_MAPPED = 2,
	BTF_RECONCILED = 3
};

struct btf_reconcile_entry {
	__u32 parent_id;
	__u32 child_id;
	__u32 cand_id;
	enum btf_reconcile_state state;
};

struct btf_reconcile {
	struct btf *btf;
	const struct btf *base_btf;
	const struct btf *min_base_btf;
	struct btf_reconcile_entry *map;
	__u32 parent_id;
	__u32 child_id;
	__u32 diff_id;
	__u32 diff_str;
};

/* Find next type after *id in base BTF that matches kind of type t passed in.
 * Match fwd kinds to appropriate kind also.
 */
static int btf_reconcile_find_next(struct btf_reconcile *r, const struct btf_type *t,
				   __u32 *id, const struct btf_type **tp)
{
	__u32 nr_base_types = btf__type_cnt(r->base_btf);
	const struct btf_type *nt;
	int kind, tkind = btf_kind(t);
	int tkflag = btf_kflag(t);
	__u32 i;

	for (i = *id + 1; i < nr_base_types; i++) {
		nt = btf_type_by_id(r->base_btf, i);
		kind = btf_kind(nt);
		if (kind != tkind && kind != BTF_KIND_FWD)
			continue;
		if (tkind == BTF_KIND_FWD) {
			switch (kind) {
			case BTF_KIND_FWD:
				if (tkflag != btf_kflag(nt))
					continue;
				break;
			case BTF_KIND_STRUCT:
				if (tkflag)
					continue;
				break;
			case BTF_KIND_UNION:
				if (!tkflag)
					continue;
			default:
				break;
			}
		}
		*tp = nt;
		*id = i;
		return 0;
	}
	return -ENOENT;
}

static int btf_reconcile_int(struct btf_reconcile *r, const char *name,
			     const struct btf_type *t, const struct btf_type *bt)
{
	__u32 *info = (__u32 *)(t + 1);
	__u32 *binfo = (__u32 *)(bt + 1);

	if (t->size != bt->size) {
		pr_warn("INT types '%s' disagree on size; minimal base BTF says %d; base BTF says %d\n",
			name, t->size, bt->size);
		return -EINVAL;
	}
	if (BTF_INT_ENCODING(*info) != BTF_INT_ENCODING(*binfo)) {
		pr_warn("INT types '%s' disagree on encoding; minimal base BTF says '(%s/%s/%s); base BTF says '(%s/%s/%s)'\n",
			name,
			BTF_INT_ENCODING(*info) & BTF_INT_SIGNED ? "signed" : "unsigned",
			BTF_INT_ENCODING(*info) & BTF_INT_CHAR ? "char" : "nonchar",
			BTF_INT_ENCODING(*info) & BTF_INT_BOOL ? "bool" : "nonbool",
			BTF_INT_ENCODING(*binfo) & BTF_INT_SIGNED ? "signed" : "unsigned",
			BTF_INT_ENCODING(*binfo) & BTF_INT_CHAR ? "char" : "nonchar",
			BTF_INT_ENCODING(*binfo) & BTF_INT_BOOL ? "bool" : "nonbool");
		return -EINVAL;
	}
	if (BTF_INT_BITS(*info) != BTF_INT_BITS(*binfo)) {
		pr_warn("INT types '%s' disagree on bit size; minimal base BTF says %d; base BTF says %d\n",
			name, BTF_INT_BITS(*info), BTF_INT_BITS(*binfo));
		return -EINVAL;
	}
	return 0;
}

static int btf_reconcile_float(struct btf_reconcile *r, const char *name,
			       const struct btf_type *t, const struct btf_type *bt)
{

	if (t->size != bt->size) {
		pr_warn("float types '%s' disagree on size; minimal base BTF says %d; base BTF says %d\n",
			name, t->size, bt->size);
		return -EINVAL;
	}
	return 0;
}

/* ensure each enum value in type t has equivalent in base BTF and that values match */
static int btf_reconcile_enum(struct btf_reconcile *r, const char *name,
			      const struct btf_type *t, const struct btf_type *bt, bool verbose)
{
	struct btf_enum *v = (struct btf_enum *)(t + 1);
	struct btf_enum *bv = (struct btf_enum *)(bt + 1);
	bool found, match;
	int i, j;

	for (i = 0; i < btf_vlen(t); i++, v++) {
		found = match = false;

		if (!v->name_off)
			continue;
		for (j = 0; j < btf_vlen(bt); j++, bv++) {
			if (!bv->name_off)
				continue;
			if (strcmp(btf__name_by_offset(r->min_base_btf, v->name_off),
				   btf__name_by_offset(r->base_btf, bv->name_off)) != 0)
				continue;
			found = true;
			match = (v->val == bv->val);
			break;
		}
		if (!found) {
			if (verbose)
				pr_warn("ENUM types '%s' disagree; minimal base BTF has enum value '%s' (%d), base BTF does not have that value.\n",
					name, btf__name_by_offset(r->min_base_btf, v->name_off),
					v->val);
			return -EINVAL;
		}
		if (!match) {
			if (verbose)
				pr_warn("ENUM types '%s' disagree on enum value '%s'; minimal base BTF specifies value %d; base BTF specifies value %d\n",
					name, btf__name_by_offset(r->min_base_btf, v->name_off),
					v->val, bv->val);
			return -EINVAL;
		}
	}
	return 0;
}

/* ensure each enum64 value in type t has equivalent in base BTF and that values match */
static int btf_reconcile_enum64(struct btf_reconcile *r, const char *name,
			      const struct btf_type *t, const struct btf_type *bt, bool verbose)
{
	struct btf_enum64 *v = (struct btf_enum64 *)(t + 1);
	struct btf_enum64 *bv = (struct btf_enum64 *)(bt + 1);
	bool found, match;
	int i, j;

	for (i = 0; i < btf_vlen(t); i++, v++) {
		found = match = false;

		if (!v->name_off)
			continue;
		for (j = 0; j < btf_vlen(bt); j++, bv++) {
			if (!bv->name_off)
				continue;
			if (strcmp(btf__name_by_offset(r->min_base_btf, v->name_off),
				   btf__name_by_offset(r->base_btf, bv->name_off)) != 0)
				continue;
			found = true;
			match = (btf_enum64_value(v) == btf_enum64_value(bv));
			break;
		}
		if (!found) {
			if (verbose)
				pr_warn("ENUM64 types '%s' disagree; minimal base BTF has enum64 value '%s' (%lld), base BTF does not have that value.\n",
					name, btf__name_by_offset(r->min_base_btf, v->name_off),
					btf_enum64_value(v));
			return -EINVAL;
		}
		if (!match) {
			if (verbose)
				pr_warn("ENUM64 types '%s' disagree on enum value '%s'; minimal base BTF specifies value %lld; base BTF specifies value %lld\n",
					name, btf__name_by_offset(r->min_base_btf, v->name_off),
					btf_enum64_value(v), btf_enum64_value(bv));
			return -EINVAL;
		}
	}
	return 0;
}

/* check number of parameters, return and parameter types. */
static int btf_reconcile_func_proto(struct btf_reconcile *r, const struct btf_type *t,
				    const struct btf_type *bt, bool verbose)
{
	struct btf_param *p = (struct btf_param *)(t + 1);
	struct btf_param *bp = (struct btf_param *)(bt + 1);
	int i, vlen = btf_vlen(t);

	if (vlen != btf_vlen(bt)) {
		if (verbose)
			pr_warn("FUNC_PROTO types disagree on number of parameters; minimal base BTF specifies %d; base BTF specifies %d\n",
				vlen, btf_vlen(bt));
		return -EINVAL;
	}
	if (r->map[t->type].state >= BTF_MAPPED) {
		if (bt->type != r->map[t->type].cand_id) {
			if (verbose)
				pr_warn("FUNC_PROTO types disagree on return value type; minimal base BTF specifies value %d; base BTF specifies value %d\n",
					r->map[t->type].cand_id, bt->type);
			return -ENOENT;
		}
	}
	for (i = 0; i < vlen; i++, p++, bp++) {
		if (r->map[p->type].state >= BTF_MAPPED) {
			if (r->map[p->type].cand_id != bp->type) {
				if (verbose)
					pr_warn("FUNC_PROTO types disagree on parameter %d type; minimal base BTF specifies %d; base BF specifies %d\n",
						i, r->map[p->type].cand_id, bp->type);
				return -ENOENT;
			}
		}
	}
	return 0;
}

/* all minimal BTF members must be in base BTF equivalent. */
static int btf_reconcile_check_member(struct btf_reconcile *r, const char *name,
				      struct btf_member *m, const struct btf_type *bt,
				      bool verbose)
{
	struct btf_member *bm = (struct btf_member *)(bt + 1);
	const char *kindstr = btf_kind(bt) == BTF_KIND_STRUCT ? "STRUCT" : "UNION";
	const char *mname, *bmname;
	int i, bvlen = btf_vlen(bt);

	for (i = 0; i < bvlen; i++, bm++) {
		mname = btf__name_by_offset(r->min_base_btf, m->name_off);
		bmname = btf__name_by_offset(r->base_btf, bm->name_off);

		if (!mname || !bmname) {
			if (mname != bmname)
				continue;
		} else {
			if (strcmp(mname, bmname) != 0)
				continue;
		}
		if (bm->offset != m->offset)
			continue;
		if (r->map[m->type].state >= BTF_MAPPED) {
			if (bm->type != r->map[m->type].cand_id) {
				if (verbose)
					pr_warn("%s '%s' disagrees about member type for member '%s'; minimal base BTF says %d; base BTF says %d\n",
						kindstr, name, mname,
						r->map[m->type].cand_id, bm->type);
				return -EINVAL;
			}
			break;
		}
	}
	if (i == bvlen) {
		if (verbose)
			pr_warn("%s '%s' missing member '%s' found in minimal base BTF\n",
				kindstr, name, mname);
		return -EINVAL;
	}
	return 0;
}

static int btf_reconcile_struct_union(struct btf_reconcile *r, const char *name,
				      const struct btf_type *t, const struct btf_type *bt,
				      bool verbose)
{
	struct btf_member *m = (struct btf_member *)(t + 1);
	const char *kindstr = btf_kind(t) == BTF_KIND_STRUCT ? "STRUCT" : "UNION";
	int i, vlen = btf_vlen(t);

	/* must be at least as big */
	if (bt->size < t->size) {
		if (verbose)
			pr_warn("%s '%s' is disagrees about size with minimal base BTF (%d); base BTF is smaller (%d)\n",
				kindstr, name, t->size, bt->size);
		return -EINVAL;
	}
	/* must have at least as many elements */
	if (btf_vlen(bt) < vlen) {
		if (verbose)
			pr_warn("%s '%s' disagrees about number of members with minimal base BTF (%d); base BTF has less (%d)\n",
				kindstr, name, vlen, btf_vlen(bt));
		return -EINVAL;
	}

	for (i = 0; i < vlen; i++, m++) {
		if (btf_reconcile_check_member(r, name, m, bt, verbose))
			return -EINVAL;
	}
	return 0;
}

static int btf_reconcile_find_named_type(struct btf_reconcile *r, __u32 parent_id, __u32 id,
					 const char *name)
{
	const struct btf_type *t = btf_type_by_id(r->btf, id);
	bool is_fwd = btf_is_fwd(t) || (btf_is_any_enum(t) && btf_vlen(t) == 0);
	const struct btf_type *bt;
	__u32 base_id, i;
	int err = 0;

	if (r->map[id].state >= BTF_MAPPED)
		return 0;

	if (!name || !name[0]) {
		pr_warn("Unexpected anonymous type id [%d] in minimal base BTF.\n",
			id);
		return -EINVAL;
	}
	base_id = btf__find_by_name_kind(r->base_btf, name, btf_kind(t));
	if (base_id < 0) {
		if (is_fwd) {
			base_id = btf__find_by_name_kind(r->base_btf, name,
							 btf_kflag(t) ? BTF_KIND_UNION :
									BTF_KIND_STRUCT);
		}
		if (!base_id) {
			pr_warn("could not find '%s' in base BTF\n", name);
			return -ENOENT;
		}
	}
	r->map[id].parent_id = parent_id;
	r->map[id].cand_id = base_id;
	r->map[id].state = is_fwd ? BTF_RECONCILED : BTF_MAPPED;
	bt = btf_type_by_id(r->base_btf, base_id);
	if (!is_fwd) {
		switch (btf_kind(t)) {
		case BTF_KIND_INT:
			err = btf_reconcile_int(r, name, t, bt);
			if (!err)
				r->map[id].state = BTF_RECONCILED;
			break;
		case BTF_KIND_ENUM:
			err = btf_reconcile_enum(r, name, t, bt, true);
			if (!err)
				r->map[id].state = BTF_RECONCILED;
			break;
		case BTF_KIND_FLOAT:
			err = btf_reconcile_float(r, name, t, bt);
			if (!err)
				r->map[id].state = BTF_RECONCILED;
			break;
		case BTF_KIND_ENUM64:
			err = btf_reconcile_enum64(r, name, t, bt, true);
			if (!err)
				r->map[id].state = BTF_RECONCILED;
			break;
		default:
			/* skip reconciliation for struct, union etc. */
			break;
		}
		if (err)
			return err;
	}
	/* next find map entries for parent reference types */
	for (i = parent_id; i != BTF_INVALID_ID; i = r->map[i].parent_id) {
		const struct btf_type *pt;
		__u32 base_ref_id = 0;

		pt = btf_type_by_id(r->btf, i);

		/* find same kind that references base_id */
		bt = NULL;
		while (btf_reconcile_find_next(r, pt, &base_ref_id, &bt) != -ENOENT) {
			if (bt->type != base_id)
				continue;
			r->map[i].cand_id = base_ref_id;
			/* if we matched via a fwd/0-valued enum, mark as reconciled */
			r->map[i].state = is_fwd ? BTF_RECONCILED :
						   BTF_MAPPED;
			break;
		}
		if (r->map[i].state < BTF_MAPPED)
			return -ENOENT;
		base_id = base_ref_id;
	}

	return 0;
}

/* match unnamed types with base BTF types. */
static int btf_reconcile_find_unnamed_type(struct btf_reconcile *r, __u32 parent_id, __u32 id)
{
	const struct btf_type *t = btf_type_by_id(r->btf, id);
	const struct btf_type *bt = NULL;
	int vlen = btf_vlen(t);
	int kind = btf_kind(t);
	__u32 base_id = 0;
	int i;

	if (r->map[id].state >= BTF_MAPPED)
		return 0;

	switch (kind) {
	case BTF_KIND_ENUM: {
		struct btf_enum *v = btf_enum(t);

		for (i = 0; i < vlen; i++, v++) {
			if (v->name_off)
				break;
		}
		if (!v->name_off) {
			pr_warn("Empty anonymous ENUM [%d] in minimal base BTF; cannot resolve it.\n",
				id);
			return -EINVAL;
		}
		while (btf_reconcile_find_next(r, t, &base_id, &bt) != -ENOENT) {
			if (btf_reconcile_enum(r, "", t, bt, false) == 0)
				goto success;
		}
		break;
	}
	case BTF_KIND_ENUM64: {
		struct btf_enum64 *v = btf_enum64(t);

		for (i = 0; i < vlen; i++, v++) {
			if (v->name_off)
				break;
		}
		if (!v->name_off) {
			pr_warn("Empty anonymous ENUM64 [%d] in minimal base BTF; cannot resolve it.\n",
				id);
			return -EINVAL;
		}
		while (btf_reconcile_find_next(r, t, &base_id, &bt) != -ENOENT) {
			if (btf_reconcile_enum64(r, "", t, bt, false) == 0)
				goto success;
		}
		break;
	}
	case BTF_KIND_FUNC_PROTO:
		/* for func proto, match via parent (func) if present; if not,
		 * use param#, retval/param types.
		 */
		while (btf_reconcile_find_next(r, t, &base_id, &bt) != -ENOENT) {
			if (btf_vlen(bt) != vlen)
				continue;
			if (btf_reconcile_func_proto(r, t, bt, false) == 0)
				goto success;
		}
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		/* for struct/union, check members for correspondence */
		while (btf_reconcile_find_next(r, t, &base_id, &bt) != -ENOENT) {
			if (btf_reconcile_struct_union(r, "", t, bt, false) == 0)
				goto success;
		}
		break;
	default:
		pr_warn("Unexpected anon kind %d\n", kind);
		return -EINVAL;
	}
	pr_warn("Could not find equivalent to anon type id [%d] in base BTF\n",
		id);
	return -EINVAL;
success:
	r->map[id].parent_id = parent_id;
	r->map[id].cand_id = base_id;
	r->map[id].state = BTF_RECONCILED;

	return 0;
}

static int btf_reconcile_complete(struct btf_reconcile *r, __u32 type_id)
{
	const struct btf_type *t = btf_type_by_id(r->btf, type_id);
	const char *name = btf__name_by_offset(r->btf, t->name_off);
	const struct btf_type *bt;
	int err;

	switch (r->map[type_id].state) {
	case BTF_UNNEEDED:
	case BTF_RECONCILED:
		return 0;
	case BTF_UNMAPPED:
		pr_warn("'%s'[%d] is unmapped to base BTF\n", name, type_id);
		return -ENOENT;
	case BTF_MAPPED:
		bt = btf_type_by_id(r->base_btf, r->map[type_id].cand_id);
		switch (btf_kind(t)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			err = btf_reconcile_struct_union(r, name, t, bt, true);
			if (err)
				return err;
			r->map[type_id].state = BTF_RECONCILED;
			return 0;
		default:
			return 0;
		}
	default:
		pr_warn("'%s'[%d] has unexpected reconcile state %d\n", name, type_id,
			r->map[type_id].state);
		return -EINVAL;
	}
}

/* Find equivalent type referenced in split BTF in base BTF. */
static int btf_reconcile_find_type(__u32 *type_id, void *ctx)
{
	struct btf_reconcile *r = ctx;
	const struct btf_type *t;
	const char *name;
	__u32 id = *type_id;
	__u32 start_id = id;
	__u32 parent = BTF_INVALID_ID;
	__u32 child = 0;
	int err;

	/* only need map entries for min base BTF. */
	if (id > btf__type_cnt(r->min_base_btf))
		return 0;

	if (r->map[id].state >= BTF_MAPPED)
		return 0;

	if (!id) {
		r->map[id].cand_id = 0;
		r->map[id].state = BTF_RECONCILED;
		return 0;
	}
	r->map[id].state = BTF_UNMAPPED;
	do {
		t = btf_type_by_id(r->btf, id);
		name = btf__name_by_offset(r->btf, t->name_off);
		switch (btf_kind(t)) {
		case BTF_KIND_INT:
		case BTF_KIND_FLOAT:
			return btf_reconcile_find_named_type(r, parent, id, name);
		case BTF_KIND_ARRAY:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_FUNC_PROTO:
			/* If named, resolve parent prior to looking at child types to avoid
			 * type cycles.  If unnamed, resolve child types first as these
			 * will help disambiguate unnamed type.
			 */
			if (name && name[0]) {
				err = btf_reconcile_find_named_type(r, parent, id, name);
				if (err)
					return err;
			}
			err = btf_type_visit_type_ids((struct btf_type *)t,
						      btf_reconcile_find_type, r);
			if (err)
				return err;
			if (!name || !name[0])
				err = btf_reconcile_find_unnamed_type(r, parent, id);
			return err;
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			/* struct, union and enum[64] can be named or anon */
			if (name && name[0])
				return btf_reconcile_find_named_type(r, parent, id, name);
			return btf_reconcile_find_unnamed_type(r, parent, id);
		case BTF_KIND_FUNC:
		case BTF_KIND_TYPEDEF:
			/* named types with t->type references; reconcile named
			 * types and handle referenced types below.
			 */
			err = btf_reconcile_find_named_type(r, parent, id, name);
			if (err)
				return err;
			break;
		case BTF_KIND_PTR:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
			child = t->type;
			break;
		default:
			return 0;
		}
		/* reference type, so map reference also. */
		r->map[id].child_id = child;
		r->map[id].parent_id = parent;
		parent = id;
		id = child;
	} while (id != start_id && r->map[id].state < BTF_MAPPED);

	return 0;
}

static int btf_reconcile_rewrite_type_id(__u32 *type_id, void *ctx)
{
	struct btf_reconcile *r = ctx;
	const struct btf_type *t;
	__u32 id = *type_id;
	const char *name;

	/* split types need to map to new offset based on number of types in base BTF. */
	if (id >= btf__type_cnt(r->min_base_btf)) {
		*type_id = id + r->diff_id;
		return 0;
	}
	/* for a mapping to be valid, it needs to be either BTF_RECONCILED itself, or
	 * be BTF_MAPPED while having a child id that is BTF_RECONCILED.
	 */
	if (r->map[id].state) {
		if (r->map[id].state != BTF_RECONCILED) {

			for (; r->map[id].child_id != BTF_INVALID_ID; id = r->map[id].child_id) {
				if (r->map[id].state != BTF_MAPPED)
					break;
			}
		}
		if (r->map[id].state == BTF_RECONCILED) {
			*type_id = r->map[*type_id].cand_id;
			return 0;
		}
	}
	t = btf_type_by_id(r->btf, id);
	name = btf__name_by_offset(r->btf, t->name_off);

	switch (r->map[id].state) {
	case BTF_UNNEEDED:
		pr_warn("reference to type '%s'[%d] BTF reconcile algorithm thought was unneeded.\n",
			name, id);
		return -ENOENT;
	case BTF_UNMAPPED:
		pr_warn("could not find equivalent type id in base BTF for type '%s'\n", name);
		return -ENOENT;
	case BTF_MAPPED:
		pr_warn("could not reconcile type '%s'[%d] with type id [%d] in base BTF.\n",
			name, id, r->map[id].cand_id);
		return -ENOENT;
	default:
		pr_warn("unexpected map state %d for type '%s'[%d]\n",
			r->map[id].state, name, id);
		return -EINVAL;
	}
}

/* the string rewrite runs _after_ we have reparented split BTF to the base
 * BTF passed into btf__reconcile().
 */
static int btf_reconcile_rewrite_strs(__u32 *str_off, void *ctx)
{
	struct btf_reconcile *r = ctx;
	const char *s;
	int off;

	if (!*str_off)
		return 0;

	/* either string is in split or base BTF. Base BTF string
	 * references are still to minimal base BTF, so need to be
	 * updated with actual base BTF references.
	 */
	s = btf__str_by_offset(r->min_base_btf, *str_off);
	if (s) {
		off = btf__add_str(r->btf, s);
		if (off < 0)
			return off;
		*str_off = off;
	}
	return 0;
}

/* If successful, output of reconciliation is updated BTF with base BTF pointing at
 * base_btf, and type ids adjusted accordingly
 */
int btf__reconcile(struct btf *btf, const struct btf *base_btf)
{
	const struct btf *min_base_btf = btf__base_btf(btf);
	__u32 nr_min_base_types, nr_base_types, nr_split_types;
	struct btf_reconcile r = {};
	const struct btf_type *t;
	__u32 id, i;
	int err = 0;

	if (!base_btf || min_base_btf == base_btf)
		return 0;

	nr_min_base_types = btf__type_cnt(min_base_btf);
	nr_base_types = btf__type_cnt(base_btf);
	nr_split_types = btf__type_cnt(btf) - nr_min_base_types;
	r.map = calloc(nr_min_base_types, sizeof(struct btf_reconcile_entry));
	if (!r.map)
		return -ENOMEM;
	for (i = 1; i < nr_min_base_types; i++) {
		r.map[i].parent_id = BTF_INVALID_ID;
		r.map[i].child_id = BTF_INVALID_ID;
	}

	r.btf = btf;
	r.min_base_btf = min_base_btf;
	r.base_btf = base_btf;
	r.diff_id = btf__type_cnt(base_btf) - nr_min_base_types;

	/* build a map from base minimal references to base BTF ids; it is used to
	 * track the state of comparisons.
	 */
	for (i = 0, id = nr_min_base_types; i < nr_split_types; i++, id++) {
		t = btf_type_by_id(btf, id);

		err = btf_type_visit_type_ids((struct btf_type *)t, btf_reconcile_find_type, &r);
		if (err)
			goto err_out;
	}

	/* at this point we have mapped and resolved all types needed aside from named
	 * struct//union types.  Handle these now.
	 */
	for (id = 1; id < nr_min_base_types; id++) {
		err = btf_reconcile_complete(&r, id);
		if (err)
			goto err_out;
	}

	/* Next, rewrite type ids in split BTF, replacing split ids with updated
	 * ids based on number of types in base BTF, and base ids with reconciled
	 * ids from base_btf.
	 */
	for (i = 0, id = nr_min_base_types; i < nr_split_types; i++, id++) {
		t = btf__type_by_id(btf, id);
		err = btf_type_visit_type_ids((struct btf_type *)t,
					      btf_reconcile_rewrite_type_id, &r);
		if (err)
			goto err_out;
	}
	/* Now set base BTF to base_btf; this is done prior to string rewriting so
	 * that strings that are already in base_btf do not get added unnecessarily.
	 */
	err = btf_set_base_btf(r.btf, (struct btf *)r.base_btf, false);
	if (err)
		goto err_out;

	/* String offsets for split/base BTF need to be updated; do that now. */
	for (i = 0, id = nr_base_types; i < nr_split_types; i++, id++) {
		t = btf__type_by_id(btf, id);
		err = btf_type_visit_str_offs((struct btf_type *)t, btf_reconcile_rewrite_strs, &r);
		if (err)
			break;
	}
err_out:
	free(r.map);

	return err;
}
