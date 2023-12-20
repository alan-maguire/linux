// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_helpers.h"

void test_btf_dedup_base_minimal(void)
{
	struct btf *btf1 = NULL, *btf2 = NULL, *btf3, *btf4;
	LIBBPF_OPTS(btf_dedup_opts, opts);
	int err;

	btf1 = btf__new_empty();
	if (!ASSERT_OK_PTR(btf1, "empty_main_btf"))
		return;

	btf__add_int(btf1, "int", 4, BTF_INT_SIGNED);	/* [1] int */
	btf__add_ptr(btf1, 1);				/* [2] ptr to int */
	btf__add_struct(btf1, "s1", 4);			/* [3] struct s1 { */
	btf__add_field(btf1, "f1", 1, 0, 0);		/*      int f1; */
							/* } */
	btf__add_ptr(btf1, 3);				/* [4] ptr to struct s1 */
	btf__add_struct(btf1, "s2", 12);		/* [5] struct s2 { */
	btf__add_field(btf1, "f1", 1, 0, 0);		/*	int f1; */
	btf__add_field(btf1, "f2", 4, 32, 0);		/*	struct s1 *f2; */
							/* } */
	VALIDATE_RAW_BTF(
		btf1,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[4] PTR '(anon)' type_id=3",
		"[5] STRUCT 's2' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=4 bits_offset=32");

	btf2 = btf__new_empty_split(btf1);
	if (!ASSERT_OK_PTR(btf2, "empty_split_btf"))
		goto cleanup;

	btf__add_int(btf2, "int", 4, BTF_INT_SIGNED);	/* [6] int */
	btf__add_struct(btf2, "s1", 4);			/* [7] struct s1 { */
	btf__add_field(btf2, "f1", 6, 0, 0);		/*	int f1; */
							/* } */
	btf__add_ptr(btf2, 7);				/* [8] ptr to struct s1 */
	btf__add_struct(btf2, "s2", 12);		/* [9] struct s2 { */
	btf__add_field(btf2, "f1", 6, 0, 0);		/*      int f1; */
	btf__add_field(btf2, "f2", 8, 32, 0);		/*	struct s1 *f2; */
							/* } */
	/* add ptr to struct s2 */
	btf__add_ptr(btf2, 9);

	VALIDATE_RAW_BTF(
		btf2,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[4] PTR '(anon)' type_id=3",
		"[5] STRUCT 's2' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=4 bits_offset=32",
		"[6] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[7] STRUCT 's1' size=4 vlen=1\n"
		"\t'f1' type_id=6 bits_offset=0",
		"[8] PTR '(anon)' type_id=7",
		"[9] STRUCT 's2' size=12 vlen=2\n"
		"\t'f1' type_id=6 bits_offset=0\n"
		"\t'f2' type_id=8 bits_offset=32",
		"[10] PTR '(anon)' type_id=9");

	opts.gen_base_btf_minimal = true;
	err = btf__dedup(btf2, &opts);
	if (!ASSERT_OK(err, "btf_dedup"))
		goto cleanup;

	btf3 = (struct btf *)btf__base_btf(btf2);
	if (!ASSERT_OK_PTR(btf3, "base_minimal_btf"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		btf2,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] STRUCT 's1' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[3] PTR '(anon)' type_id=2",
		"[4] STRUCT 's2' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=3 bits_offset=32",
		"[5] PTR '(anon)' type_id=4");

	btf4 = btf__new_empty();
	if (!ASSERT_OK_PTR(btf4, "empty_new_base_btf"))
		return;

	/* add an "unsigned int" to shuffle the type ids in the base BTF for
	 * reconciliation.
	 */
	btf__add_int(btf4, "unsigned int", 4, 0);	/* [1] unsigned int */
	btf__add_int(btf4, "int", 4, BTF_INT_SIGNED);	/* [2] int */
	btf__add_ptr(btf4, 2);				/* [3] ptr to int */
	btf__add_struct(btf4, "s1", 4);			/* [4] struct s1 { */
	btf__add_field(btf4, "f1", 2, 0, 0);		/*      int f1; */
	btf__add_ptr(btf4, 4);				/* [5] ptr to struct s1 */
	btf__add_struct(btf4, "s2", 12);		/* [6] struct s2 { */
	btf__add_field(btf4, "f1", 2, 0, 0);		/*	int f1; */
	btf__add_field(btf4, "f2", 5, 32, 0);		/*	struct s1 *f2; */
							/* } */

	if (!ASSERT_OK(btf__reconcile(btf2, btf4), "reconcile"))
		goto cleanup;

	/* btf2 is now deduped and reconciled with btf4 */
	VALIDATE_RAW_BTF(
		btf2,
		"[1] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)",
		"[2] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[3] PTR '(anon)' type_id=2",
		"[4] STRUCT 's1' size=4 vlen=1\n"
		"\t'f1' type_id=2 bits_offset=0",
		"[5] PTR '(anon)' type_id=4",
		"[6] STRUCT 's2' size=12 vlen=2\n"
		"\t'f1' type_id=2 bits_offset=0\n"
		"\t'f2' type_id=5 bits_offset=32",
		"[7] PTR '(anon)' type_id=6");

cleanup:
	btf__free(btf2);
	btf__free(btf1);
}
