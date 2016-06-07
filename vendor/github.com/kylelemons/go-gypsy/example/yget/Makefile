include $(GOROOT)/src/Make.inc

TARG=yget
DEP=
GOFILES=\
	main.go\

pkgdir=$(GOROOT)/pkg/$(GOOS)_$(GOARCH)
PREREQ+=$(foreach PKG,$(DEP),$(pkgdir)/$(PKG).a)

include $(GOROOT)/src/Make.cmd
