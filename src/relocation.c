#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>P
#include <bpf/hashmap.h>
#include <bpf/btf.h>
#include <bpf/libbpf_internal.h>
#include "bpftime_object.h"
#include "bpftime.h"
#include "bpftime_internal.h"

#define BPF_INSN_SZ (sizeof(struct bpf_insn))

static size_t btfgen_hash_fn(long key, void *ctx)
{
	return key;
}

static bool btfgen_equal_fn(long k1, long k2, void *ctx)
{
	return k1 == k2;
}

static struct bpf_core_cand_list *btfgen_find_cands(const struct btf *local_btf,
						    const struct btf *targ_btf,
						    __u32 local_id)
{
	const struct btf_type *local_type;
	struct bpf_core_cand_list *cands = NULL;
	struct bpf_core_cand local_cand = {};
	size_t local_essent_len;
	const char *local_name;
	int err;

	local_cand.btf = local_btf;
	local_cand.id = local_id;

	local_type = btf__type_by_id(local_btf, local_id);
	if (!local_type) {
		err = -EINVAL;
		goto err_out;
	}

	local_name = btf__name_by_offset(local_btf, local_type->name_off);
	if (!local_name) {
		err = -EINVAL;
		goto err_out;
	}
	local_essent_len = bpf_core_essential_name_len(local_name);

	cands = calloc(1, sizeof(*cands));
	if (!cands)
		return NULL;

	err = bpf_core_add_cands(&local_cand, local_essent_len, targ_btf,
				 "vmlinux", 1, cands);
	if (err)
		goto err_out;

	return cands;

err_out:
	bpf_core_free_cands(cands);
	errno = -err;
	return NULL;
}

/* Record relocation information for a single BPF object */
int ebpf_object_relocate_btf(struct btf *host_btf, const char *obj_path,
			     struct bpftime_object *bpftime_obj,
			     reloc_desc_appended appender)
{
	const struct btf_ext_info_sec *sec = NULL;
	const struct bpf_core_relo *relo = NULL;
	const struct btf_ext_info *seg = NULL;
	struct hashmap_entry *entry = NULL;
	struct hashmap *cand_cache = NULL;
	struct btf_ext *btf_ext = NULL;
	unsigned int relo_idx = 0;
	struct btf *btf = NULL;
	size_t i = 0;
	int err = -1;
	struct bpftime_prog *bpftime_prog = NULL;
	struct bpf_insn *insn = NULL, *prog_insn = NULL;
	int insn_idx = 0, insns_cnt = 0;

	btf = btf__parse(obj_path, &btf_ext);
	if (!btf) {
		err = -errno;
		printf("failed to parse BPF object '%s': %s\n", obj_path,
		       strerror(errno));
		return err;
	}

	if (!btf_ext) {
		printf("failed to parse BPF object '%s': section %s not found\n",
		       obj_path, BTF_EXT_ELF_SEC);
		err = -EINVAL;
		goto out;
	}

	if (btf_ext->core_relo_info.len == 0) {
		printf("failed to parse BPF object '%s', no inst to relocate\n",
		       obj_path);
		err = 0;
		goto out;
	}

	cand_cache = hashmap__new(btfgen_hash_fn, btfgen_equal_fn, NULL);
	if (IS_ERR(cand_cache)) {
		err = PTR_ERR(cand_cache);
		goto out;
	}

	seg = &btf_ext->core_relo_info;
	for_each_btf_ext_sec(seg, sec)
	{
		for_each_btf_ext_rec(seg, sec, relo_idx, relo)
		{
			struct bpf_core_spec specs_scratch[3] = {};
			struct bpf_core_relo_res targ_res = {};
			struct bpf_core_cand_list *cands = NULL;
			const char *sec_name =
				btf__name_by_offset(btf, sec->sec_name_off);
			printf("sec_name: %s\n", sec_name);
			if (relo->insn_off % BPF_INSN_SZ)
				return -EINVAL;
			insn_idx = relo->insn_off / BPF_INSN_SZ;

			bpftime_prog = bpftime_object_find_program_by_secname(
				bpftime_obj, sec_name);
			if (!bpftime_prog) {
				/* When __weak subprog is "overridden" by
				 * another instance of the subprog from a
				 * different object file, linker still appends
				 * all the .BTF.ext info that used to belong to
				 * that eliminated subprogram. This is similar
				 * to what x86-64 linker does for relocations.
				 * So just ignore such relocations just like we
				 * ignore subprog instructions when discovering
				 * subprograms.
				 */
				printf("sec '%s': skipping CO-RE relocation #%zd for insn #%d belonging to eliminated weak subprogram\n",
				       sec_name, i, insn_idx);
				continue;
			}
			prog_insn = (struct bpf_insn *)bpftime_prog->insns;
			insns_cnt = bpftime_prog->insn_cnt;
			insn_idx = relo->insn_off / sizeof(struct bpf_insn);

			appender(bpftime_obj, bpftime_prog, relo, insn_idx);
			/* adjust insn_idx from section frame of reference to
			 * the local program's frame of reference; (sub-)program
			 * code is not yet relocated, so it's enough to just
			 * subtract in-section offset
			 */
			// insn_idx = insn_idx - prog->sec_insn_off;
			if (insn_idx >= insns_cnt)
				return -EINVAL;
			insn = &prog_insn[insn_idx];

			if (relo->kind != BPF_CORE_TYPE_ID_LOCAL &&
			    !hashmap__find(cand_cache, relo->type_id, &cands)) {
				cands = btfgen_find_cands(btf, host_btf,
							  relo->type_id);
				if (!cands) {
					err = -errno;
					goto out;
				}

				err = hashmap__set(cand_cache, relo->type_id,
						   cands, NULL, NULL);
				if (err)
					goto out;
			}

			err = bpf_core_calc_relo_insn(sec_name, relo, relo_idx,
						      btf, cands, specs_scratch,
						      &targ_res);
			if (err)
				goto out;

			err = bpf_core_patch_insn(sec_name, insn, insn_idx,
						  relo, relo_idx, &targ_res);
			if (err) {
				printf("prog '%s': relo #%d: failed to patch insn #%u: %d\n",
				       sec_name, relo_idx, insn_idx, err);
				goto out;
			}
			/* specs_scratch[2] is the target spec */
		}
	}

out:
	btf__free(btf);
	btf_ext__free(btf_ext);

	if (!IS_ERR_OR_NULL(cand_cache)) {
		hashmap__for_each_entry(cand_cache, entry, i)
		{
			bpf_core_free_cands(entry->pvalue);
		}
		hashmap__free(cand_cache);
	}

	return err;
}
