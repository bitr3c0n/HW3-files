#include <asm-generic/errno-base.h>  // EACCES definition
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h> 

char LICENSE[] SEC("license") = "GPL";

// HINT: https://github.com/iovisor/bcc/blob/master/libbpf-tools/filetop.bpf.c

// HINT: The hook you are looking for starts with "file_".
// There are more than one hooks that can be used for this task.
SEC("lsm/REPLACE_ME")
int BPF_PROG(my_file_checker, struct file *file) {

  // NOTE: You can change the function signature of BPF_PROG 
  // if your LSM hook takes more than one parameter

  if (1) {
    return -EACCES;
  }
  return 0;
}
