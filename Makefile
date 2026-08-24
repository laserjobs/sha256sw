echo "Z3 version:"
z3 -version
echo "Checking full_64round_equiv.smt2..."
z3 formal/full_64round_equiv.smt2 2>&1
status=$$?
echo "Z3 exit code: $$status"
exit $$status
