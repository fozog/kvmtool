#!/bin/bash

TMP=/tmp/generate_table.$$

#trap "rm $TMP; exit" EXIT

grep "__AARCH64_SYS_REG([^o]" include/asm/sys_regs.h | tr '\t' ' '| cut -d' ' -f2 > $TMP
set $(wc -l $TMP)
((COUNT=$1 +1))

echo "#include \"asm/sys_regs.h\""
echo "#include \"kvm/vcore_sys_regs.h\""
echo ""
echo "sys_reg_info_t sys_regs[$COUNT] ="
echo "{"

while read reg
do
	level=${reg#*_EL}
	if [ "$level" == "02" ]; then
		level=0
	elif [ "$level" == "12" ]; then
		level=1
	fi
	if [ "$reg" == "AARCH64_ALLINT" ]; then
		level=1
	elif [ "$reg" == "AARCH64_CurrentEL" ]; then
		level=0
	elif [ "$reg" == "AARCH64_DAIF" ]; then
		level=1
	elif [ "$reg" == "AARCH64_DIT" ]; then
		level=0
	elif [ "$reg" == "AARCH64_ELR_EL1" ]; then
		# workaround parsing issue
		level=1
	elif [ "$reg" == "AARCH64_ELR_EL12" ]; then
		# workaround parsing issue
		level=1
	elif [ "$reg" == "AARCH64_ELR_EL2" ]; then
		# workaround parsing issue
		level=2
	elif [ "$reg" == "AARCH64_ELR_EL3" ]; then
		# workaround parsing issue
		level=3
	elif [ "$reg" == "AARCH64_FPCR" ]; then
		level=0
	elif [ "$reg" == "AARCH64_FPSR" ]; then
		level=0
	elif [ "$reg" == "AARCH64_ICH_ELRSR_EL2" ]; then
		# workaround parsing issue
		level=2
	elif [ "$reg" == "AARCH64_NZCV" ]; then
		level=2
	elif [ "$reg" == "AARCH64_PAN" ]; then
		level=1
	elif [ "$reg" == "AARCH64_PM" ]; then
		level=1
	elif [ "$reg" == "AARCH64_RNDRRS" ]; then
		level=0
	elif [ "$reg" == "AARCH64_RNDR" ]; then
		level=0
	elif [ "$reg" == "AARCH64_SPSel" ]; then
		level=1
	elif [ "$reg" == "AARCH64_SPSR_abt" ]; then
		level=1
	elif [ "$reg" == "AARCH64_SPSR_fiq" ]; then
		level=1
	elif [ "$reg" == "AARCH64_SPSR_irq" ]; then
		level=1
	elif [ "$reg" == "AARCH64_SPSR_und" ]; then
		level=1
	elif [ "$reg" == "AARCH64_SSBS" ]; then
		level=0
	elif [ "$reg" == "AARCH64_SVCR" ]; then
		level=0
	elif [ "$reg" == "AARCH64_TCO" ]; then
		level=0
	elif [[ "$reg" == "AARCH64_TRC"* ]]; then
		level=1
	elif [ "$reg" == "AARCH64_UAO" ]; then
		level=1
	fi
	if [[ "$level" == "" || ! ("$level" ==  "0" || "$level" ==  "1" || "$level" ==  "2" || $level ==  "3" ) ]]; then
		echo "bad level $level for $reg"
	fi
	echo "{ .id=${reg}, .minimal_el=$level, .name=${reg}_NAME, .description=${reg}_DESC },"
done < $TMP
echo "};"
