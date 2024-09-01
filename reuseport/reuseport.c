//go:build ignore

#include "common.h"

#define IPPROTO_TCP	6

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") socket_map = {
    .type = BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 128,
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS,
};

static int global = 0;

//https://github.com/cilium/ebpf/blob/main/elf_sections.go
SEC("sk_reuseport")
enum sk_action select_socket(struct sk_reuseport_md *reuse){

    u32 main_key = 1; 
    u32 sub_key = 2;

    global += 1;

    if(global <= 5){
        if(bpf_sk_select_reuseport(reuse, &socket_map, &sub_key, 0) == 0){
            bpf_printk("found sub socket!\n");
            return SK_PASS;
        }
    }

    if(bpf_sk_select_reuseport(reuse, &socket_map, &main_key, 0) == 0){
        bpf_printk("found main socket!\n");
        return SK_PASS;
    }

    bpf_printk("dropped sock\n");
    return SK_DROP;
}