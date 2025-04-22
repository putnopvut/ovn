/* Copyright (c) 2025, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PORT_BINDING_PAIR_H
#define PORT_BINDING_PAIR_H 1

#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/shash.h"
#include "smap.h"

/* Port Binding pairing API. This file consists of utility functions
 * that can be used when pairing northbound port types (e.g.
 * Logical_Router_Port and Logical_Switch_Port) to southbound Port_Bindings.
 *
 * The basic flow of data is as such.
 * 1. A northbound type is converted into an ovn_unpaired_port_binding.
 * All ovn_unpaired_port_bindings are placed into an ovn_unpaired_datapath_map.
 * 2. The en_port_binding_pair node takes all of the maps in as input and
 * pairs them with southbound port bindings. This includes allocating
 * tunnel keys across all ports. The output of this node is
 * ovn_paired_port_bindings, which contains a list of all paired port bindings.
 * 3. A northbound type-aware node then takes the ovn_paired_port_bindings,
 * and decodes the generic paired port bindings back into a type-specific
 * version (e.g. ovn_paired_logical_router_port). Later nodes can then consume
 * these type-specific paired port binding types in order to perform
 * further processing.
 *
 * It is important to note that this code pairs northbound ports to southbound
 * port bindings, but it does not 100% sync them. The following fields are
 * synced between the northbound port and the southbound Port_Binding:
 * - logical_port
 * - tunnel_key
 * - external_ids
 *
 * Two later incremental engine nodes sync the rest of the fields on the Port
 * Binding. en_northd syncs the vast majority of the data. Then finally,
 * en_sync_to_sb syncs the nat_addresses of the Port_Binding.
 */

enum ovn_port_type {
    PB_SWITCH_PORT,
    PB_ROUTER_PORT,
    PB_CHASSISREDIRECT_PORT,
    PB_MIRROR_PORT,
    PB_MAX,
};

struct ovn_unpaired_port_binding {
    uint32_t requested_tunnel_key;
    struct smap external_ids;
    void *cookie;
    const char *name;
    enum ovn_port_type type;
    const struct sbrec_datapath_binding *sb_dp;
};

struct sbrec_port_binding;
struct ovn_unpaired_port_binding_map_callbacks {
    bool (*sb_is_valid)(const struct sbrec_port_binding *sp_pb,
                        const struct ovn_unpaired_port_binding *upb);
    void (*free_cookie)(void *cookie);
};

bool default_sb_is_valid(const struct sbrec_port_binding *sp_pb,
                         const struct ovn_unpaired_port_binding *upb);

struct ovn_unpaired_port_binding_map {
    struct shash ports;
    const struct ovn_unpaired_port_binding_map_callbacks *cb;
};

struct sbrec_port_binding;
struct ovn_paired_port_binding {
    struct ovs_list list_node;
    const void *cookie;
    enum ovn_port_type type;
    const struct sbrec_port_binding *sb_pb;
};

struct ovn_paired_port_bindings {
    struct ovs_list paired_pbs;
    struct hmap tunnel_key_maps;
};

struct ovn_unpaired_port_binding *ovn_unpaired_port_binding_alloc(
        uint32_t requested_tunnel_key, const char *name,
        enum ovn_port_type type,
        void *cookie,
        const struct sbrec_datapath_binding *sb_dp);

void ovn_unpaired_port_binding_destroy(struct ovn_unpaired_port_binding *pb);

void ovn_unpaired_port_binding_map_init(
    struct ovn_unpaired_port_binding_map *map,
    const struct ovn_unpaired_port_binding_map_callbacks *cb);
void ovn_unpaired_port_binding_map_destroy(
    struct ovn_unpaired_port_binding_map *map);

#endif /* PORT_BINDING_PAIR_H */
