bin_PROGRAMS += controller/ovn-pinctrl
controller_ovn_pinctrl_SOURCES = \
    controller/ovn-pinctrl.c \
    controller/pinctrl.c \
	controller/pinctrl.h \
	controller/bfd.c \
	controller/bfd.h \
	controller/binding.c \
	controller/binding.h \
	controller/chassis.c \
	controller/chassis.h \
	controller/encaps.c \
	controller/encaps.h \
	controller/ha-chassis.c \
	controller/ha-chassis.h \
	controller/ip-mcast.c \
	controller/ip-mcast.h \
	controller/lflow.c \
	controller/lflow.h \
	controller/lport.c \
	controller/lport.h \
	controller/ofctrl.c \
	controller/ofctrl.h \
	controller/patch.c \
	controller/patch.h \
	controller/controller-utils.c \
	controller/ovn-controller.h \
	controller/physical.c \
	controller/physical.h
controller_ovn_pinctrl_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la
man_MANS += controller/ovn-pinctrl.8
EXTRA_DIST += controller/ovn-pinctrl.8.xml
CLEANFILES += controller/ovn-pinctrl.8

bin_PROGRAMS += controller/ovn-controller
controller_ovn_controller_SOURCES = \
	controller/bfd.c \
	controller/bfd.h \
	controller/binding.c \
	controller/binding.h \
	controller/chassis.c \
	controller/chassis.h \
	controller/encaps.c \
	controller/encaps.h \
	controller/ha-chassis.c \
	controller/ha-chassis.h \
	controller/ip-mcast.c \
	controller/ip-mcast.h \
	controller/lflow.c \
	controller/lflow.h \
	controller/lport.c \
	controller/lport.h \
	controller/ofctrl.c \
	controller/ofctrl.h \
	controller/patch.c \
	controller/patch.h \
	controller/ovn-controller.c \
	controller/controller-utils.c \
	controller/ovn-controller.h \
	controller/physical.c \
	controller/physical.h
controller_ovn_controller_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la
man_MANS += controller/ovn-controller.8
EXTRA_DIST += controller/ovn-controller.8.xml
CLEANFILES += controller/ovn-controller.8
