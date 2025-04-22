/*
 * Copyright (c) 2025, Red Hat, Inc.
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

#include <config.h>

#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "util.h"

#include "inc-proc-eng.h"
#include "ovn-nb-idl.h"
#include "ovn-sb-idl.h"
#include "port-binding-pair.h"
#include "en-datapath-logical-switch.h"
#include "en-port-binding-logical-switch-port.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_port_binding_logical_switch_port);

struct logical_switch_port_cookie {
    const struct nbrec_logical_switch_port *nbsp;
    const struct ovn_synced_logical_switch *sw;
};

static struct logical_switch_port_cookie *
logical_switch_port_cookie_alloc(const struct nbrec_logical_switch_port *nbsp,
                                 const struct ovn_synced_logical_switch *sw)
{
    struct logical_switch_port_cookie *cookie = xmalloc(sizeof *cookie);
    *cookie = (struct logical_switch_port_cookie) {
        .nbsp = nbsp,
        .sw = sw,
    };
    return cookie;
}

static bool
switch_port_sb_is_valid(const struct sbrec_port_binding *sb_pb,
                        const struct ovn_unpaired_port_binding *upb)
{
    const struct logical_switch_port_cookie *cookie = upb->cookie;

    bool update_sbrec = false;
    if (lsp_is_type_changed(sb_pb, cookie->nbsp, &update_sbrec)
        && update_sbrec) {
        return false;
    }

    return true;
}

static void
logical_switch_port_cookie_free(void *cookie)
{
    struct logical_switch_port_cookie *lsp_cookie = cookie;
    free(lsp_cookie);
}

static struct ovn_unpaired_port_binding_map_callbacks switch_port_callbacks = {
    .sb_is_valid = switch_port_sb_is_valid,
    .free_cookie = logical_switch_port_cookie_free,
};

void *
en_port_binding_logical_switch_port_init(struct engine_node *node OVS_UNUSED,
                                         struct engine_arg *args OVS_UNUSED)
{
    struct ovn_unpaired_port_binding_map *map = xmalloc(sizeof *map);
    ovn_unpaired_port_binding_map_init(map, &switch_port_callbacks);
    return map;
}

enum engine_node_state
en_port_binding_logical_switch_port_run(struct engine_node *node, void *data)
{
    const struct ovn_synced_logical_switch_map *ls_map =
        engine_get_input_data("datapath_synced_logical_switch", node);

    struct ovn_unpaired_port_binding_map *map = data;

    ovn_unpaired_port_binding_map_destroy(map);
    ovn_unpaired_port_binding_map_init(map, &switch_port_callbacks);

    const struct ovn_synced_logical_switch *paired_ls;
    HMAP_FOR_EACH (paired_ls, hmap_node, &ls_map->synced_switches) {
        const struct nbrec_logical_switch_port *nbsp;
        for (size_t i = 0; i < paired_ls->nb->n_ports; i++) {
            nbsp = paired_ls->nb->ports[i];
            uint32_t requested_tunnel_key = smap_get_int(&nbsp->options,
                                                         "requested-tnl-key",
                                                         0);
            struct logical_switch_port_cookie *cookie =
                logical_switch_port_cookie_alloc(nbsp, paired_ls);
            struct ovn_unpaired_port_binding *upb;
            upb = ovn_unpaired_port_binding_alloc(requested_tunnel_key,
                                                  nbsp->name,
                                                  PB_SWITCH_PORT,
                                                  cookie,
                                                  paired_ls->sb);
            smap_clone(&upb->external_ids, &nbsp->external_ids);
            const char *name = smap_get(&nbsp->external_ids,
                                        "neutron:port_name");
            if (name && name[0]) {
                smap_add(&upb->external_ids, "name", name);
            }
            if (!shash_add_once(&map->ports, nbsp->name, upb)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "duplicate logical port %s", nbsp->name);
            }
        }
    }
    return EN_UPDATED;
}

void
en_port_binding_logical_switch_port_cleanup(void *data)
{
    struct ovn_unpaired_port_binding_map *map = data;
    ovn_unpaired_port_binding_map_destroy(map);
}

static void
paired_logical_switch_port_map_init(
    struct ovn_paired_logical_switch_port_map *switch_port_map)
{
    *switch_port_map = (struct ovn_paired_logical_switch_port_map) {
        .paired_switch_ports =
            SHASH_INITIALIZER(&switch_port_map->paired_switch_ports),
    };
}

static void
paired_logical_switch_port_map_destroy(
    struct ovn_paired_logical_switch_port_map *switch_port_map)
{
    shash_destroy_free_data(&switch_port_map->paired_switch_ports);
}

void *
en_port_binding_paired_logical_switch_port_init(
    struct engine_node *node OVS_UNUSED, struct engine_arg *args OVS_UNUSED)
{
    struct ovn_paired_logical_switch_port_map *switch_port_map;
    switch_port_map = xmalloc(sizeof *switch_port_map);
    paired_logical_switch_port_map_init(switch_port_map);

    return switch_port_map;
}

enum engine_node_state
en_port_binding_paired_logical_switch_port_run(struct engine_node *node,
                                               void *data)
{
    const struct ovn_paired_port_bindings *pbs =
        engine_get_input_data("port_binding_pair", node);
    struct ovn_paired_logical_switch_port_map *switch_port_map = data;

    paired_logical_switch_port_map_destroy(switch_port_map);
    paired_logical_switch_port_map_init(switch_port_map);

    struct ovn_paired_port_binding *spb;
    LIST_FOR_EACH (spb, list_node, &pbs->paired_pbs) {
        if (spb->type !=  PB_SWITCH_PORT) {
            continue;
        }
        const struct logical_switch_port_cookie *cookie = spb->cookie;
        struct ovn_paired_logical_switch_port *lsw = xmalloc(sizeof *lsw);
        *lsw = (struct ovn_paired_logical_switch_port) {
            .nb = cookie->nbsp,
            .sw = cookie->sw,
            .sb = spb->sb_pb,
        };
        shash_add(&switch_port_map->paired_switch_ports, lsw->nb->name, lsw);

        /* This deals with a special case where a logical switch port is
         * removed and added back very quickly. The sequence of events is as
         * follows:
         * 1) NB Logical_Switch_Port "lsp" is added to the NB DB.
         * 2) en-port-binding-pair creates a corresponding SB Port_Binding.
         * 3) The user binds the port to a hypervisor.
         * 4) ovn-controller on the hypervisor sets the SB Port_Binding "up"
         *    column to "true".
         * 5) ovn-northd sets the Logical_Switch_Port "up" column to "true".
         * 6) A user deletes and then re-adds "lsp" back to the NB
         *    Logical_Switch_Port column very quickly, so quickly that we
         *    do not detect the deletion at all.
         * 7) The new northbound Logical_Switch_Port has its "up" column
         *    empty (i.e. not "true") since it is new.
         * 8) The pairing code matches the new Logical_Switch_Port with the
         *    existing Port_Binding for "lsp" since the pairing code matches
         *    using the name of the Logical_Switch_Port.
         *
         * At this point, the SB Port_Binding's "up" column is set "true",
         * but the NB Logical_Switch_Port's "up" column is not. We need to
         * ensure the NB Logical_Switch_Port's "up" column is set to "true"
         * as well.
         *
         * In most cases, setting the NB Logical_Switch_Port "up" column to
         * true is accomplished when changes on the SB Port_Binding are
         * detected. But in this rare case, there is no SB Port_Binding
         * change, so the "up" column is unserviced.
         */
        lsp_set_up(lsw->sb, lsw->nb);
    }

    return EN_UPDATED;
}

void en_port_binding_paired_logical_switch_port_cleanup(void *data)
{
    struct ovn_paired_logical_switch_port_map *map = data;
    paired_logical_switch_port_map_destroy(map);
}
