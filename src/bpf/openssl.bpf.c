#include "./.output/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define BUF_SIZE 4096

enum e_ssl_direction { SSL_WRITE, SSL_READ };

struct ssl_data_event {
  unsigned long ctx;
  int pid;
  char comm[TASK_COMM_LEN];
  int size;
  unsigned char buf[BUF_SIZE];
  enum e_ssl_direction direction;
};

struct ssl_close_event {
  unsigned long ctx;
  int pid;
  unsigned long one;
  unsigned long two;
  unsigned long three;
};

struct ssl_args {
  unsigned long ctx;
  void *buf;
};

struct ssl_data_event _ssl_data_event = {0};
struct ssl_close_event _ssl_close_event = {0};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, struct ssl_args);
} ssl_args_map SEC(".maps");

/* --------------------------------- helpers -------------------------------- */
int submit_data_event(enum e_ssl_direction direction, struct ssl_args *tmp,
                      int len) {

  if (tmp == NULL) {
    return 1;
  }
  bpf_printk("%p: submit", tmp->ctx);

  struct ssl_data_event *e = NULL;

  int read = 0;

  for (int i = 0; i < 100 && read != len; i++) {
    bpf_printk("%p: loop", tmp->ctx);
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e == NULL) {
      return 1;
    }

    e->direction = direction;
    e->ctx = tmp->ctx;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    int remain = len - read;
    bpf_printk("%p: %d - %d - %d", tmp->ctx, remain, len, read);
    if (remain > BUF_SIZE) {
      e->size = BUF_SIZE;
      bpf_probe_read(&e->buf, BUF_SIZE, tmp->buf + read);
      read += BUF_SIZE;
    } else if (remain > 0) {
      e->size = remain;
      bpf_probe_read(&e->buf, remain, tmp->buf + read);
      read += remain;
    }

    bpf_ringbuf_submit(e, 0);
  }

  if (read != len) {
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
      return 1;
    }

    e->direction = direction;
    e->ctx = tmp->ctx;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->size = 0;

    bpf_ringbuf_submit(e, 0);
  }

  return 0;
}

int submit_close_event(void *ssl) {
  if (ssl == NULL) {
    return 1;
  }

  struct ssl_close_event *e = NULL;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 1;
  }

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->ctx = (unsigned long)ssl;
  bpf_printk("%p: close", e->ctx);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

/* -------------------------------- ssl write ------------------------------- */
// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe")
int BPF_KPROBE(SSL_write, void *ssl, void *buf, int num) {
  struct ssl_args args = {.ctx = (unsigned long)ssl, .buf = buf};
  submit_data_event(SSL_WRITE, &args, num);

  return 0;
}

/* -------------------------------- ssl read -------------------------------- */
// int SSL_read(void *ssl, void *buf, int num);
SEC("uprobe")
int BPF_KPROBE(SSL_read, void *ssl, void *buf, int num) {
  struct ssl_args args = {.ctx = (unsigned long)ssl, .buf = buf};
  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  bpf_map_update_elem(&ssl_args_map, &pid, &args, BPF_ANY);

  return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(SSL_read_ret, int ret) {
  struct ssl_args *args = NULL;
  struct ssl_data_event *e = NULL;

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  args = bpf_map_lookup_elem(&ssl_args_map, &pid);
  if (!args) {
    return 0;
  }

  if (ret > 0) {
    submit_data_event(SSL_READ, args, ret);
  }

  bpf_map_delete_elem(&ssl_args_map, &pid);

  return 0;
}

/* -------------------------------- ssl close ------------------------------- */
// int SSL_shutdown(SSL *ssl);
SEC("uprobe")
int BPF_KPROBE(SSL_shutdown, void *ssl) {
  submit_close_event(ssl);

  return 0;
}

// int SSL_clear(SSL *ssl);
SEC("uprobe")
int BPF_KPROBE(SSL_clear, void *ssl) {
  submit_close_event(ssl);

  return 0;
}

// void SSL_free(SSL *ssl);
SEC("uprobe")
int BPF_KPROBE(SSL_free, void *ssl) {
  submit_close_event(ssl);

  return 0;
}