/*
 * Copyright (c) 2026, Red Hat, Inc.
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

#ifndef EN_PORT_BINDING_SERVICE_H
#define EN_PORT_BINDING_SERVICE_H

#include "openvswitch/shash.h"

struct service_ports {
    /* All service ports that appear in the service chains */
    struct shash all_service_ports;
    /* All services that appear in the service chains */
    struct hmap all_service_dps;
};

struct engine_node;
struct engine_arg;
void *en_port_binding_service_init(struct engine_node *,
                                      struct engine_arg *);

enum engine_node_state en_port_binding_service_run(struct engine_node *,
                                                      void *data);
void en_port_binding_service_clear_tracked_data(void *data);
void en_port_binding_service_cleanup(void *data);

#endif /* EN_PORT_BINDING_SERVICE_H */
