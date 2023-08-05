RUN=./scripts/run.sh
MAKE_CONTAINER=$(RUN) make --no-print-directory -e -f Makefile.core.mk

%:
	@$(MAKE_CONTAINER) $@

default:
	@$(MAKE_CONTAINER)

shell:
	@$(RUN) bash

.PHONY: default shell
