INSTALL_TOOLS += $(TOOLBIN)/yq
$(TOOLBIN)/yq:
	cd $(TOOLS_DIR); ./install_yq.sh
	$(call post-install-check)

INSTALL_TOOLS += $(TOOLBIN)/helm
$(TOOLBIN)/helm:
	cd $(TOOLS_DIR); ./install_helm.sh
	$(call post-install-check)



.PHONY: install-tools
install-tools: $(INSTALL_TOOLS)

.PHONY: uninstall-tools
uninstall-tools:
	rm -rf $(INSTALL_TOOLS)



