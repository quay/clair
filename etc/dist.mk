# The "dist" target builds a dist archive at git revision "VERSION".
.PHONY: dist
dist: clair-$(VERSION).tar.gz

# Clair-%.tar.gz builds a dist archive using the state of the tree at the commit
# indicated by the pattern.
clair-%.tar.gz: vendor/modules.txt
	tarball=$(subst .gz,,$@)
	prefix=$(subst .tar.gz,/,$@)
	$(git_archive) --format tar\
		--prefix "$$prefix"\
		--output "$$tarball"\
		$*
	dt=$$(tar --list --file "$$tarball" --utc --full-time "$${prefix}go.mod" | awk '{print $$4 "T" $$5 "Z"}')
	tar --append --file "$$tarball"\
		--transform "s,^,$${prefix},"\
		--mtime "$$(date -Iseconds --date $$dt)"\
		--sort name\
		--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime\
		vendor
	gzip -n -q -f "$$tarball"
rm_pat += clair-*.tar.gz
