.PHONY: apps mongodb gateways push

CHARTS_TMP := _tmp


gateways:
	@helm package gateways -d $(CHARTS_TMP)


apps:
	@helm package apps -d $(CHARTS_TMP)


mongodb:
	@helm package mongodb -d $(CHARTS_TMP)


push: apps mongodb gateways
	@$(foreach file, $(wildcard $(CHARTS_TMP)/*.tgz), helm push $(file) oci://us-central1-docker.pkg.dev/secure-code-dev/zyloch/charts;)
