.. NOTE(stephenfin): If making changes to this file, ensure that the line
   numbers found in 'Documentation/intro/what-is-ovs' are kept up-to-date.

==================
OVN/OVS Code Split
==================

This is a *rough* proof of concept for a separation of OVN from its parent
project, OVS. If you are interested in using OVN or OVS, please visit
the OpenvSwitch official github page at https://github.com/openvswitch/ovs.git

Please feel free to try this out. For the moment, specific issues with the
build are good to note, but it's not worth filing a bug report since this
entire tree will likely be thrown away and redone.

For now, the best feedback would be about the viability of the overall
approach. What was done well? What can be improved. Below, I've compiled a
list of issues that I know about.

Approach
--------

This repo was created by taking a clone of the OVS repo from the official
upstream repository and then pushing it into an empty new github project. This
was done to preserve the history of OVN files.

Next, a clone of the OVS master branch was added as a git subtree. This is the
ovs/ subdirectory in this repo.

Next, files and subdirectories that were clearly OVS-only were removed from the
repo. This includes the following directories:

- datapath
- datapath-windows
- include
- lib
- ofproto
- ovsdb
- utilities
- vswitchd
- vtep
- windows

Next, the ovn/ subdirectory had its contents moved to the top level, and the
ovn/ subdirectory was removed.

Next, the build was stabilized. This mostly included altering Makefiles so that
the project would build successfully.

Next, the ovn tests were verified to work. This mostly involved altering
expected paths for files so that the tests could succeed.

Finally, the ovs sandbox was verified to run properly. This again consisted of
altering paths in the ovs-sandbox in order to get everything running
successfully.

What all works in this repo
---------------------------

OVN can be built using the ``make`` command.

All tests that match the ``-k ovn`` keyword pass.
You can run the ovs-sandbox with OVN by running ``make sandbox SANDBOXFLAGS="--ovn"``

Installation of OVN using ``make install`` has not been tested, nor have any
additional build options. The build has only been tested on a Linux system, so
there may be build issues on BSD, Windows, or other systems currently supported
by OVS/OVN.

Instructions for building
-------------------------
Clone the ovn repo::

    git clone https://github.com/putnopvut/ovn.git

Run the bootsrap and configure scripts::

    ./boot.sh
    ./configure.sh

Touch the manpages.mk file (we'll discuss this later)::

    touch manpages.mk

Build ovn::

    make

Alternately, you can run OVN in a sandbox::

    make sandbox SANDBOXFLAGS="--ovn"

============
Further work
============

As has been stated, this is a rough proof of concept. While some of the work
will likely be reflected in the final product, there are a lot of areas that
need improvement. These are detailed further in the sections below

Obvious improvements
--------------------

At this point, the OVS subtree is completely untouched. In actuality, all OVN-
specific content from the OVS subtree will need to be removed. Similarly, there
is still some content in the OVN tree that can be removed. For instance, a great
deal of the tests/ directory can be pruned. Also, repeated files in the
Documentation/ directory can be removed.

Because repeated tests have not been removed, it results in some unexpected
behaviors. If you attempt to run a test, then it will run the test first
from within the ovs/tests/ directory, and then in the tests/ directory. This
will partly be fixed by removing repeated tests. However, this points to an
overarching issue where it would be best if we could completely ignore the
ovs/ subtree when running tests.

During the build process, you currently must ``touch manpages.mk``. If you do
not do this, then you will see the following errors when attempting to build::

    lib/daemon-syn.man not found in: . . .
    lib/vlog-syn.man not found in: . . .
    lib/ssl-syn.man not found in: . . .
    lib/ssl-bootstrap-syn.man not found in: . . .
    lib/ssl-connect-syn.man not found in: . . .
    lib/common-syn.man not found in: . . .
    ovsdb/ovsdb-schemas.man not found in: . . .
    lib/table.man not found in: . . .
    lib/daemon.man not found in: . . .
    lib/vlog.man not found in: . . .
    lib/ssl.man not found in: . . .
    lib/ssl-bootstrap.man not found in: . . .
    lib/ssl-connect.man not found in: . . .
    lib/common.man not found in: . . .
    lib/daemon-syn.man not found in: . . .
    lib/service-syn.man not found in: . . .
    lib/vlog-syn.man not found in: . . .
    lib/ssl-syn.man not found in: . . .
    lib/ssl-bootstrap-syn.man not found in: . . .
    lib/ssl-peer-ca-cert-syn.man not found in: . . .
    lib/ssl-connect-syn.man not found in: . . .
    lib/unixctl-syn.man not found in: . . .
    lib/common-syn.man not found in: . . .
    lib/daemon.man not found in: . . .
    lib/service.man not found in: . . .
    lib/vlog.man not found in: . . .
    lib/ssl.man not found in: . . .
    lib/ssl-bootstrap.man not found in: . . .
    lib/ssl-peer-ca-cert.man not found in: . . .
    lib/ssl-connect.man not found in: . . .
    lib/unixctl.man not found in: . . .
    lib/common.man not found in: . . .
    lib/vlog-unixctl.man not found in: . . .
    lib/memory-unixctl.man not found in: . . .
    lib/coverage-unixctl.man not found in: . . .
    lib/vlog-syn.man not found in: . . .
    lib/common-syn.man not found in: . . .
    ovsdb/ovsdb-schemas.man not found in: . . .
    lib/vlog.man not found in: . . .
    lib/common.man not found in: . . .
    make: *** [Makefile:4022: manpages.mk] Error 1

These errors are cryptic. Grepping for the referenced file names gives nothing
to go on, as far as I could see. For whatever reason, touching the manpages.mk
file makes these errors go away. Why? Hell if I know.

As has been mentioned, aside from ensuring tests pass and the the sandbox works,
other use cases are untested. For instance, it's highly likely that building
packages currently does not work.

Less Obvious Improvements
-------------------------

There are some files in the tree that are currently specific to OVS, but
removing them might not be the best choice. For instance, it might be a good
idea to revise the Vagrantfile so that it is focused on installing OVN
instead of installing OVS. Something similar could probably be done for files
in the poc/ and xenserver/ subdirectories.

Moving the contents of the ovn/ subdirectory to the top level makes sense
given the context of the new repo. However, some files that exist at the top
level now may make sense to shove into a subdirectory. For instance, the
ovsschema files for the north and southbound database are at the top level
now. It may make sense to put them in a subdirectory.

The way include paths are handled may be a bit more slapdash than necessary.
It would probably be best if OVN source files made it explicit when they were
including OVN headers vs OVS headers. For instance::

    #include "ovs/lib/smap.h"
    #include "ovs/include/openvswitch/hmap.h"

Currently, these are just done as::

    #include "smap.h"
    #include "openvswitch/hmap.h"

Doing this would require some changes to how IDL files are auto-generated
since they generate include directives with assumptions about the include
path.

I didn't quite 100% grok how auto-generation of the IDL files is done. In
order to build the north- and south-bound IDL C files, I ended up copying the
ovsdb automake.mk file from OVS into the lib/ directory for OVN and fixing
the paths. There is likely a much easier way to generate the IDL C files.

In a similar vein, there likely is a decent amount of Makefile instructions
that can be removed. I didn't bother removing stuff unless it was very clear
that it needed to be removed.

Running OVN in a sandbox currently works, but the way it works could be improved.
It would probably be better if OVN called into the OVS script to get the OVS
components started and then start the OVN components locally. Currently, the
script is copied wholesale.

The commits in this repo are a mess. They are not grouped very well and they
have minimal commit messages. It would be a good idea to rebase all of the commits
so that they are arranged logically and have good explanations.
