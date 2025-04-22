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

#ifndef EN_PORT_BINDING_CHASSISREDIRECT_PORT_H
#define EN_PORT_BINDING_CHASSISREDIRECT_PORT_H

#include "lib/inc-proc-eng.h"
#include "datapath-sync.h"
#include "openvswitch/shash.h"

void *en_port_binding_chassisredirect_port_init(struct engine_node *,
                                           struct engine_arg *);

enum engine_node_state en_port_binding_chassisredirect_port_run(
    struct engine_node *, void *data);
void en_port_binding_chassisredirect_port_cleanup(void *data);

struct ovn_paired_chassisredirect_port {
    const char *name;
    union {
        const struct nbrec_logical_switch_port *primary_nbsp;
        const struct nbrec_logical_router_port *primary_nbrp;
    };
    enum ovn_datapath_type dp_type;
    const struct sbrec_port_binding *sb;
};

struct ovn_paired_chassisredirect_port_map {
    struct shash paired_chassisredirect_ports;
};

void *en_port_binding_paired_chassisredirect_port_init(struct engine_node *,
                                                       struct engine_arg *);
enum engine_node_state en_port_binding_paired_chassisredirect_port_run(
    struct engine_node *, void *data);
void en_port_binding_paired_chassisredirect_port_cleanup(void *data);
#endif /* EN_PORT_BINDING_CHASSISREDIRECT_PORT_H */
