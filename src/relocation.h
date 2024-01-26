#ifndef _BPFTIME_RELOCATION_H_
#define _BPFTIME_RELOCATION_H_

struct btf;
struct bpf_object;

/* Record relocation information for a single BPF object */
int ebpf_object_relocate_btf(struct btf *host_btf, const char *obj_path,
			     struct bpf_object *obj);

#endif // _BPFTIME_RELOCATION_H_
