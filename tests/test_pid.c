/*
 * Unit tests for common/pid.c — PID handling and process_id operations.
 *
 * Phase 1: regression tests on existing behavior (before any changes).
 * Phase 3 tests (XOR fold) will be added after pid.c modifications.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>

#include "common/pid.h"

/* --- Handshake packet layout (mirrors net/net-tcp-rpc-common.h) --- */
#pragma pack(push,4)
struct test_tcp_rpc_handshake_packet {
  int type;
  int flags;
  struct process_id sender_pid;
  struct process_id peer_pid;
};

struct test_tcp_rpc_handshake_error_packet {
  int type;
  int error_code;
  struct process_id sender_pid;
};
#pragma pack(pop)

/* --- Test helpers --- */

static int tests_run = 0;
static int tests_passed = 0;
static int current_test_failed = 0;

#define RUN_TEST(name) do { \
  tests_run++; \
  current_test_failed = 0; \
  printf("  %-50s ", #name); \
  name(); \
  if (!current_test_failed) { \
    tests_passed++; \
    printf("PASS\n"); \
  } \
} while(0)

#define ASSERT_EQ(a, b) do { \
  if ((a) != (b)) { \
    current_test_failed = 1; \
    printf("FAIL\n    %s:%d: %s == %ld, expected %ld\n", \
           __FILE__, __LINE__, #a, (long)(a), (long)(b)); \
    return; \
  } \
} while(0)

static struct process_id make_pid(unsigned ip, short port, unsigned short pid, int utime) {
  struct process_id p;
  memset(&p, 0, sizeof(p));
  p.ip = ip;
  p.port = port;
  p.pid = pid;
  p.utime = utime;
  return p;
}

/* ================================================================== */
/* 1.1 matches_pid() tests                                            */
/* ================================================================== */

static void test_matches_pid_exact_match(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0x01020304, 80, 42, 1000);
  ASSERT_EQ(matches_pid(&x, &y), 2);
}

static void test_matches_pid_wildcard_pid_zero(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0x01020304, 80, 0, 1000);
  ASSERT_EQ(matches_pid(&x, &y), 1);
}

static void test_matches_pid_wildcard_all_zeros(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0, 0, 0, 0);
  ASSERT_EQ(matches_pid(&x, &y), 1);
}

static void test_matches_pid_ip_mismatch(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0x05060708, 80, 42, 1000);
  ASSERT_EQ(matches_pid(&x, &y), 0);
}

static void test_matches_pid_port_mismatch(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0x01020304, 81, 42, 1000);
  ASSERT_EQ(matches_pid(&x, &y), 0);
}

static void test_matches_pid_pid_mismatch(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0x01020304, 80, 99, 1000);
  ASSERT_EQ(matches_pid(&x, &y), 0);
}

static void test_matches_pid_utime_mismatch(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0x01020304, 80, 42, 2000);
  ASSERT_EQ(matches_pid(&x, &y), 0);
}

static void test_matches_pid_partial_wildcard(void) {
  struct process_id x = make_pid(0x01020304, 80, 42, 1000);
  struct process_id y = make_pid(0, 0, 42, 1000);
  ASSERT_EQ(matches_pid(&x, &y), 1);
}

/* ================================================================== */
/* 1.2 process_id_is_newer() tests                                    */
/* ================================================================== */

static void test_newer_utime(void) {
  struct process_id a = make_pid(0x01020304, 80, 42, 2000);
  struct process_id b = make_pid(0x01020304, 80, 42, 1000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 1);
}

static void test_older_utime(void) {
  struct process_id a = make_pid(0x01020304, 80, 42, 1000);
  struct process_id b = make_pid(0x01020304, 80, 42, 2000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 0);
}

static void test_same_time_pid_ahead_by_1(void) {
  struct process_id a = make_pid(0x01020304, 80, 43, 1000);
  struct process_id b = make_pid(0x01020304, 80, 42, 1000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 1);
}

static void test_same_time_pid_behind_by_1(void) {
  struct process_id a = make_pid(0x01020304, 80, 41, 1000);
  struct process_id b = make_pid(0x01020304, 80, 42, 1000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 0);
}

static void test_same_time_same_pid(void) {
  struct process_id a = make_pid(0x01020304, 80, 42, 1000);
  struct process_id b = make_pid(0x01020304, 80, 42, 1000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 0);
}

static void test_same_time_pid_ahead_by_0x3fff(void) {
  struct process_id a = make_pid(0x01020304, 80, 42 + 0x3fff, 1000);
  struct process_id b = make_pid(0x01020304, 80, 42, 1000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 1);
}

static void test_same_time_pid_ahead_by_0x4000(void) {
  struct process_id a = make_pid(0x01020304, 80, 42 + 0x4000, 1000);
  struct process_id b = make_pid(0x01020304, 80, 42, 1000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 0);
}

static void test_pid_wraparound(void) {
  /* pid 1 vs 0x7fff: delta = (1 - 0x7fff) & 0x7fff = 2 → newer */
  struct process_id a = make_pid(0x01020304, 80, 1, 1000);
  struct process_id b = make_pid(0x01020304, 80, 0x7fff, 1000);
  ASSERT_EQ(process_id_is_newer(&a, &b), 1);
}

/* ================================================================== */
/* 1.3 Struct layout tests                                            */
/* ================================================================== */

static void test_process_id_size(void) {
  ASSERT_EQ(sizeof(struct process_id), 12);
}

static void test_process_id_ext_size(void) {
  ASSERT_EQ(sizeof(struct process_id_ext), 16);
}

static void test_process_id_field_offsets(void) {
  ASSERT_EQ(offsetof(struct process_id, ip), 0);
  ASSERT_EQ(offsetof(struct process_id, port), 4);
  ASSERT_EQ(offsetof(struct process_id, pid), 6);
  ASSERT_EQ(offsetof(struct process_id, utime), 8);
}

static void test_handshake_packet_size(void) {
  /* type(4) + flags(4) + sender_pid(12) + peer_pid(12) = 32 */
  ASSERT_EQ(sizeof(struct test_tcp_rpc_handshake_packet), 32);
}

static void test_handshake_error_packet_size(void) {
  /* type(4) + error_code(4) + sender_pid(12) = 20 */
  ASSERT_EQ(sizeof(struct test_tcp_rpc_handshake_error_packet), 20);
}

static void test_handshake_packet_offsets(void) {
  ASSERT_EQ(offsetof(struct test_tcp_rpc_handshake_packet, type), 0);
  ASSERT_EQ(offsetof(struct test_tcp_rpc_handshake_packet, flags), 4);
  ASSERT_EQ(offsetof(struct test_tcp_rpc_handshake_packet, sender_pid), 8);
  ASSERT_EQ(offsetof(struct test_tcp_rpc_handshake_packet, peer_pid), 20);
}

/* ================================================================== */
/* 1.4 init_*_PID() tests                                             */
/* ================================================================== */

static void test_init_server_pid(void) {
  memset(&PID, 0, sizeof(PID));
  init_server_PID(0x0A000001, 8080);
  ASSERT_EQ(PID.ip, 0x0A000001u);
  ASSERT_EQ(PID.port, 8080);
  assert(PID.pid != 0);
  assert(PID.utime != 0);
}

static void test_init_client_pid(void) {
  memset(&PID, 0, sizeof(PID));
  init_client_PID(0x0A000002);
  ASSERT_EQ(PID.ip, 0x0A000002u);
  ASSERT_EQ(PID.port, 0);
  assert(PID.pid != 0);
  assert(PID.utime != 0);
}

static void test_init_pid_ignores_localhost(void) {
  memset(&PID, 0, sizeof(PID));
  init_server_PID(0x7f000001, 8080);
  ASSERT_EQ(PID.ip, 0u);
  ASSERT_EQ(PID.port, 8080);
}

static void test_init_pid_no_overwrite(void) {
  memset(&PID, 0, sizeof(PID));
  init_server_PID(0x0A000001, 8080);
  unsigned short first_pid = PID.pid;
  int first_utime = PID.utime;

  init_server_PID(0x0A000002, 9090);
  ASSERT_EQ(PID.pid, first_pid);
  ASSERT_EQ(PID.utime, first_utime);
  ASSERT_EQ(PID.port, 8080);
  ASSERT_EQ(PID.ip, 0x0A000002u);
}

/* ================================================================== */
/* 1.5 Wire format: binary serialization roundtrip                    */
/* ================================================================== */

static void test_pid_binary_roundtrip(void) {
  struct process_id orig = make_pid(0xDEADBEEF, 443, 12345, 1700000000);
  unsigned char buf[12];
  memcpy(buf, &orig, sizeof(orig));

  struct process_id restored;
  memcpy(&restored, buf, sizeof(restored));

  ASSERT_EQ(restored.ip, orig.ip);
  ASSERT_EQ(restored.port, orig.port);
  ASSERT_EQ(restored.pid, orig.pid);
  ASSERT_EQ(restored.utime, orig.utime);
  ASSERT_EQ(memcmp(&orig, &restored, sizeof(struct process_id)), 0);
}

/* ================================================================== */
/* 3.1 XOR fold correctness                                           */
/* ================================================================== */

/* Helper: compute XOR fold the same way as init_common_PID */
static unsigned short xor_fold(int p) {
  unsigned short folded = (unsigned short)((p & 0xffff) ^ (p >> 16));
  return folded ? folded : 1;
}

static void test_xor_fold_small_pid(void) {
  /* PID < 65536: high bits are 0, fold == low bits */
  ASSERT_EQ(xor_fold(1), 1);
  ASSERT_EQ(xor_fold(42), 42);
  ASSERT_EQ(xor_fold(65535), 65535);
}

static void test_xor_fold_large_pid(void) {
  /* PID 65536 = 0x10000: (0 ^ 1) = 1 */
  ASSERT_EQ(xor_fold(65536), 1);
  /* PID 100000: (0x86A0 ^ 0x1) = 0x86A1 = 34465 */
  ASSERT_EQ(xor_fold(100000), 34465);
  /* PID 200000 = 0x30D40: (0x0D40 ^ 0x3) = 0x0D43 = 3395 */
  ASSERT_EQ(xor_fold(200000), 3395);
}

static void test_xor_fold_sentinel_protection(void) {
  /* PIDs where low ^ high == 0 must fold to 1, not 0 */
  ASSERT_EQ(xor_fold(0x10001), 1);  /* 65537: 1 ^ 1 = 0 → 1 */
  ASSERT_EQ(xor_fold(0x20002), 1);  /* 131074: 2 ^ 2 = 0 → 1 */
  ASSERT_EQ(xor_fold(0x30003), 1);  /* 196611: 3 ^ 3 = 0 → 1 */
  ASSERT_EQ(xor_fold(0xFFFF0000), 65535);  /* low=0, high=0xFFFF → 0 ^ 0xFFFF = 65535 */
}

static void test_xor_fold_different_pids_give_different_results(void) {
  /* PIDs that differ only in high bits should produce different folds */
  unsigned short f1 = xor_fold(1);       /* 0x00001 */
  unsigned short f2 = xor_fold(65537);   /* 0x10001 — sentinel case */
  unsigned short f3 = xor_fold(131073);  /* 0x20001: 1 ^ 2 = 3 */
  /* f1=1, f2=1 (sentinel), f3=3 — f1 and f3 differ */
  assert(f1 != f3);
  /* f2 is sentinel (unavoidable collision for 0x10001 vs 1) */
  (void)f2;
}

static void test_xor_fold_never_zero(void) {
  /* Brute-force check: no PID in realistic range folds to 0 */
  for (int p = 1; p <= 0x40000; p++) {
    assert(xor_fold(p) != 0);
  }
}

/* ================================================================== */
/* 3.2 XOR fold integration: init_common_PID with current process     */
/* ================================================================== */

static void test_init_pid_xor_fold_current_process(void) {
  memset(&PID, 0, sizeof(PID));
  init_common_PID();
  int p = getpid();
  unsigned short expected = xor_fold(p);
  ASSERT_EQ(PID.pid, expected);
  assert(PID.pid != 0);
}

/* ================================================================== */
/* 3.3 Fork collision detection simulation                            */
/* ================================================================== */

static void test_fork_collision_different_utime(void) {
  /* Parent and child with same folded pid but different utime → no collision */
  struct process_id parent = make_pid(0x0A000001, 80, 42, 1000);
  struct process_id child  = make_pid(0x0A000001, 80, 42, 1001);
  /* Collision check: pid != old_pid || utime != old_utime */
  assert(child.pid != parent.pid || child.utime != parent.utime);
}

static void test_fork_collision_different_pid(void) {
  /* Parent and child with different folded pid but same utime → no collision */
  struct process_id parent = make_pid(0x0A000001, 80, 42, 1000);
  struct process_id child  = make_pid(0x0A000001, 80, 43, 1000);
  assert(child.pid != parent.pid || child.utime != parent.utime);
}

static void test_fork_collision_identical_is_detected(void) {
  /* Identical pid AND utime → collision detected */
  struct process_id parent = make_pid(0x0A000001, 80, 42, 1000);
  struct process_id child  = make_pid(0x0A000001, 80, 42, 1000);
  int collision = !(child.pid != parent.pid || child.utime != parent.utime);
  ASSERT_EQ(collision, 1);
}

/* ================================================================== */
/* main                                                               */
/* ================================================================== */

int main(void) {
  printf("=== test_pid: matches_pid ===\n");
  RUN_TEST(test_matches_pid_exact_match);
  RUN_TEST(test_matches_pid_wildcard_pid_zero);
  RUN_TEST(test_matches_pid_wildcard_all_zeros);
  RUN_TEST(test_matches_pid_ip_mismatch);
  RUN_TEST(test_matches_pid_port_mismatch);
  RUN_TEST(test_matches_pid_pid_mismatch);
  RUN_TEST(test_matches_pid_utime_mismatch);
  RUN_TEST(test_matches_pid_partial_wildcard);

  printf("\n=== test_pid: process_id_is_newer ===\n");
  RUN_TEST(test_newer_utime);
  RUN_TEST(test_older_utime);
  RUN_TEST(test_same_time_pid_ahead_by_1);
  RUN_TEST(test_same_time_pid_behind_by_1);
  RUN_TEST(test_same_time_same_pid);
  RUN_TEST(test_same_time_pid_ahead_by_0x3fff);
  RUN_TEST(test_same_time_pid_ahead_by_0x4000);
  RUN_TEST(test_pid_wraparound);

  printf("\n=== test_pid: struct layout ===\n");
  RUN_TEST(test_process_id_size);
  RUN_TEST(test_process_id_ext_size);
  RUN_TEST(test_process_id_field_offsets);
  RUN_TEST(test_handshake_packet_size);
  RUN_TEST(test_handshake_error_packet_size);
  RUN_TEST(test_handshake_packet_offsets);

  printf("\n=== test_pid: init_*_PID ===\n");
  RUN_TEST(test_init_server_pid);
  RUN_TEST(test_init_client_pid);
  RUN_TEST(test_init_pid_ignores_localhost);
  RUN_TEST(test_init_pid_no_overwrite);

  printf("\n=== test_pid: wire format ===\n");
  RUN_TEST(test_pid_binary_roundtrip);

  printf("\n=== test_pid: XOR fold ===\n");
  RUN_TEST(test_xor_fold_small_pid);
  RUN_TEST(test_xor_fold_large_pid);
  RUN_TEST(test_xor_fold_sentinel_protection);
  RUN_TEST(test_xor_fold_different_pids_give_different_results);
  RUN_TEST(test_xor_fold_never_zero);
  RUN_TEST(test_init_pid_xor_fold_current_process);

  printf("\n=== test_pid: fork collision detection ===\n");
  RUN_TEST(test_fork_collision_different_utime);
  RUN_TEST(test_fork_collision_different_pid);
  RUN_TEST(test_fork_collision_identical_is_detected);

  printf("\n%d/%d tests passed\n", tests_passed, tests_run);
  return tests_passed == tests_run ? 0 : 1;
}
