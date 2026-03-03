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
#include <config.h>

#include "lflow-nat.h"
#include "en-datapath-nat-service.h"
#include "lflow-mgr.h"

static const struct ovn_stage OUR_STAGE = {
    .dp_type = DP_NAT_SERVICE, \
    .pipeline = P_IN, \
    .table= 8, \
    .name = "the_only_nat_stage", \
};


void
build_nat_service_lflows(const struct ovn_synced_nat_service_map *nat_services,
                         struct lflow_table *lflow_table)
{
    const struct ovn_synced_nat_service *ns;
    HMAP_FOR_EACH (ns, hmap_node, &nat_services->synced_nats) {
        ovn_lflow_add(lflow_table, ns, &OUR_STAGE, 0, "1", "output;", NULL);
    }
}
