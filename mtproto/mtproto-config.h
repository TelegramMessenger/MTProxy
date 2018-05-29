/*
    This file is part of MTProto-Server

    MTProto-Server is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    MTProto-Server is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MTProto-Server.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2012-2018 Nikolai Durov
              2012-2014 Andrey Lopatin
              2014-2018 Telegram Messenger Inc
*/
#pragma once

#define MAX_CFG_CLUSTERS	1024
#define	MAX_CFG_TARGETS		4096
#define MAX_CLUSTER_TARGETS	1024

struct mf_cluster {
  int targets_num;  // 1 for old-fashioned
  int write_targets_num;
  int targets_allocated; // size of `cluster_targets` and `balance_hashes` arrays
  int flags;
  int cluster_id;   // datacenter # or 0
  conn_target_job_t *cluster_targets; // N entries
};

struct mf_group_stats {
  int tot_clusters;
};

struct mf_config {
  int tot_targets;
  int auth_clusters, default_cluster_id;
  int min_connections, max_connections;
  double timeout;
  int config_bytes, config_loaded_at;
  char *config_md5_hex;
  struct mf_group_stats auth_stats;
  int have_proxy;
  struct mf_cluster *default_cluster;
  conn_target_job_t targets[MAX_CFG_TARGETS];
  struct mf_cluster auth_cluster[MAX_CFG_CLUSTERS];
  //  struct mf_cluster *clusters_by_hash[MAX_CFG_CLUSTERS*2];
};

extern struct mf_config *CurConf;
extern char *config_filename;

extern struct conn_target_info default_cfg_ct;
extern int default_cfg_min_connections, default_cfg_max_connections;

// (re)load configuration file

int do_reload_config (int create_conn);

struct mf_cluster *mf_cluster_lookup (struct mf_config *MC, int cluster_id, int force);

