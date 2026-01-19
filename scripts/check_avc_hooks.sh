#!/bin/bash
# Check which AVC-related kernel functions are available for probing

echo "========================================================================"
echo "Checking Available SELinux AVC Functions"
echo "========================================================================"
echo ""

echo "1. AVC Decision Functions:"
echo "   (These are the ideal hooks for capturing granted permissions)"
echo ""

DECISION_FUNCS=("slow_avc_audit" "avc_audit" "avc_has_perm_noaudit" "avc_has_perm")
for func in "${DECISION_FUNCS[@]}"; do
    if grep -q "T $func$" /proc/kallsyms 2>/dev/null; then
        echo "   ✓ $func - AVAILABLE (traceable)"
    elif grep -q "$func" /proc/kallsyms 2>/dev/null; then
        echo "   - $func - EXISTS (may be inlined/notrace)"
    else
        echo "   × $func - NOT FOUND"
    fi
done

echo ""
echo "2. AVC Lookup Functions:"
echo "   (These handle cache lookups)"
echo ""

LOOKUP_FUNCS=("avc_lookup" "avc_compute_av" "security_compute_av")
for func in "${LOOKUP_FUNCS[@]}"; do
    if grep -q "T $func$" /proc/kallsyms 2>/dev/null; then
        echo "   ✓ $func - AVAILABLE (traceable)"
    elif grep -q "$func" /proc/kallsyms 2>/dev/null; then
        echo "   - $func - EXISTS (may be inlined/notrace)"
    else
        echo "   × $func - NOT FOUND"
    fi
done

echo ""
echo "3. All AVC-related functions in kernel:"
echo ""
grep "avc" /proc/kallsyms | awk '{print "   " $2 " " $3}' | sort -u

echo ""
echo "========================================================================"
echo "Legend:"
echo "   ✓ AVAILABLE - Function exists and is traceable (type 'T')"
echo "   - EXISTS    - Function exists but may be inlined or marked notrace"
echo "   × NOT FOUND - Function does not exist in this kernel"
echo ""
echo "For eBPF kprobes, we need functions marked with 'T' (traceable)."
echo "========================================================================"
