#include "kvm/symbol.h"

#include "kvm/kvm.h"

#include <linux/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <bfd.h>

bfd *abfd = NULL;
asymbol **syms = NULL;
asection *section = NULL;
int nr_syms;

int symbol_init(struct kvm *kvm)
{
	const char* source = kvm->vmlinux;
	long symtab_size;

	int ret = 0;

	if (!kvm->vmlinux) {
		if (kvm->cfg.kernel_symbols == NULL )
			return 0;
		else
			source=kvm->cfg.kernel_symbols;
	}
	
	bfd_init();

	abfd = bfd_openr(source, NULL);
	if (abfd == NULL) {
		bfd_error_type err = bfd_get_error();

		switch (err) {
		case bfd_error_no_memory:
			ret = -ENOMEM;
			break;
		case bfd_error_invalid_target:
			ret = -EINVAL;
			break;
		default:
			ret = -EFAULT;
			break;
		}
	}

	if (!bfd_check_format(abfd, bfd_object)) {
		ret = -EFAULT;
		goto out_close;
	}
	
	symtab_size = bfd_get_symtab_upper_bound(abfd);
	if (!symtab_size) {
		ret = -EFAULT;
		goto out_close;
	}
	
	syms = malloc(symtab_size);
	if (!syms) {
		ret = -ENOMEM;
		goto out_close;
	}

	nr_syms = bfd_canonicalize_symtab(abfd, syms);

	section = bfd_get_section_by_name(abfd, ".text");
	if (!section) {
		ret = -EFAULT;
		free(syms);
		syms=NULL;
		goto out_close;
	}
	
	return ret;

out_close:
	bfd_close(abfd);
	abfd=NULL;
	return ret;
}
late_init(symbol_init);

static asymbol *lookup(asymbol **symbols, int nr_symbols, const char *symbol_name)
{
	int i, ret;

	ret = -ENOENT;

	for (i = 0; i < nr_symbols; i++) {
		asymbol *symbol = symbols[i];

		if (!strcmp(bfd_asymbol_name(symbol), symbol_name))
			return symbol;
	}

	return ERR_PTR(ret);
}

char *symbol_lookup(struct kvm *kvm, unsigned long addr, char *sym, size_t size)
{
	const char *filename;
	bfd_vma sym_offset;
	bfd_vma sym_start;

	unsigned int line;
	const char *func=NULL;
	
	asymbol *symbol;

	int  ret;

	ret = -ENOENT;

	if (!bfd_find_nearest_line(abfd, section, syms, addr, &filename, &func, &line))
		goto not_found;

	if (!func)
		goto not_found;

	symbol = lookup(syms, nr_syms, func);
	if (IS_ERR(symbol))
		goto not_found;

	sym_start = bfd_asymbol_value(symbol);

	sym_offset = addr - sym_start;

	//snprintf(sym, size, "%s+%llx (%s:%i)", func, (long long) sym_offset, filename, line);
	snprintf(sym, size, "%s+%llx", func, (long long) sym_offset);

	sym[size - 1] = '\0';

	return sym;

not_found:
	return ERR_PTR(ret);
}

int symbol_exit(struct kvm *kvm)
{
	bfd_boolean ret = TRUE;

	if (syms)
		free(syms);
	
	if (abfd)
		ret = bfd_close(abfd);

	if (ret == TRUE)
		return 0;

	return -EFAULT;
}
late_exit(symbol_exit);
