include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/common_plat/validation

ALL_API_VALIDATION_DIR = ${top_builddir}/test/common_plat/validation/api

SUBDIRS =

if test_vald
TESTS = validation/api/pktio/pktio_run.sh \
	$(ALL_API_VALIDATION_DIR)/buffer/buffer_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/classification/classification_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/crypto/crypto_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/packet/packet_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/pool/pool_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/queue/queue_main$(EXEEXT)

SUBDIRS += validation/api/pktio

endif

TEST_EXTENSIONS = .sh

dist_check_SCRIPTS = run-test tests-validation.env $(LOG_COMPILER)

test_SCRIPTS = $(dist_check_SCRIPTS)

tests-validation.env:
	echo "TESTS=\"$(TESTS)\""    > $@
	echo "$(TESTS_ENVIRONMENT)" >> $@
	echo "$(LOG_COMPILER)"      >> $@

if test_installdir
installcheck-local:
	$(DESTDIR)/$(testdir)/run-test
endif

