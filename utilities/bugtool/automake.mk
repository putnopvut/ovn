if HAVE_PYTHON
bugtool_plugins = \
	utilities/bugtool/plugins/network-status/ovn.xml

bugtool_scripts = \
	utilities/bugtool/ovn-bugtool-nbctl-show \
	utilities/bugtool/ovn-bugtool-sbctl-show \
	utilities/bugtool/ovn-bugtool-sbctl-lflow-list
endif
