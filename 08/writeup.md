
# Storming The Kingdom With `angr`
#### Tim Nosco
### Introduction

The problem I considered for this exercise was kingdom: a crafted non-stripped binary designed to test symbolic execution engines. The binary contains a series of "walls" that must be solved sequentially. To the best of my knowledge, no tool has been able to automatically solve the challenges starting with only the binary code. I used a combination of automation and static analysis to work through each wall.

### Survey

The first thing I did when auditing kingdom was to look at the decompilation. *Figure 1* shows the natural auditing start point, `main`.

```c
int main(int argc,char **argv){
  char cVar1;
  uint8_t uVar2;
  int iVar3;
  ulong uVar4;
  
  if (argc == 0xc) {
    fprintf(stderr,"Run Program Correctly Wall destroyed...please continue (%u/%u)\n",0,10);
    uVar2 = gcd_test(argv[1],argv[2]);
    if (uVar2 == 3) {
      fprintf(stderr,"GCD Wall destroyed - 2 achievments awarded...please continue (%u/%u)\n",2,10);
      uVar2 = malicious_aes_test(argv[3]);
      if (uVar2 == 3) {
        fprintf(stderr,
                "Malicious AES Wall destroyed - achievment awarded...please continue (%u/%u)\n",3,10
               );
...
```
*Figure 1.* The main function of kingdom.

Immediately apparent in `main` is the requirement that `argv` must have `0xc` many elements: `argc==0xc`. Running the program as in *Figure 2* causes us to get past this check.

```
% ./kingdom `python -c "print ' '.join(['a']*0xb)"`
Run Program Correctly Wall destroyed...please continue (0/10)
```
*Figure 2.* Passing achievements `0` of `10`.

### GCD

For this wall, I had to reason about the function symbol `gcd_test`. This function takes two arguments and converts them to integers. It asserts that neither are equal to `0x3a` and that the second is not equal to `0`.  Then `gcd_test` calls a new symbol, `gcd` on the converted arguments. If the return value of `gcd` is `0x3a`, we print the string "_GCD Wall destroyed ..._" from *Figure 1*.

```c
uint8_t gcd(uint8_t a,uint8_t b){
  if (b != 0) {
    a = gcd(b,a % b);
  }
  return a;
}
```
*Figure 3.* The function symbol `gcd`.

While I'm sure it should be fairly easy to come up with two numbers who share a `gcd` of `0x3a`, it was also quite easy to just have `angr` figure out this function for me.

```python
def wall1():
  #setup the arguments
  arg1, arg2 = [claripy.BVS("arg{}".format(i), 8) for i in (1,2)]
  s = p.factory.blank_state()
  #program asserts the args cannot be a trivial solution
  s.add_constraints(arg1!=0x3a, arg2!=0x3a)
  #lookup gcd address
  gcd_addr = p.loader.find_symbol('gcd').rebased_addr
  #make a gcd python callable function
  gcd = p.factory.callable(gcd_addr, base_state=s)
  logger.info("starting symbolic execution: gcd(%s, %s)",arg1,arg2)
  r = gcd(arg1,arg2)
  s = gcd.result_state
  #assert that the return value is what gcd_test requires
  s.add_constraints(r==0x3a)
  logger.info("evaluating arguments")
  #undo atoi by converting the arguments to strings
  return map(str,(s.solver.eval(arg1), s.solver.eval(arg2))
```
*Figure 4.* The `angr` solution to the gcd wall. After 15.798 cpu seconds, `angr` returns the results `174` and `116`.

In the function shown in *Figure 4*, I first define two 8-bit symbolic bit vectors called `arg1` and `arg2`. Then I create an empty state object from which I will begin symbolic execution. I assert that neither `arg1` nor `arg2` can be the trivial solution `0x3a`. Next, I find the `gcd` function in the kingdom binary and wrap it in a python callable object. `gcd(arg1,arg2)` kicks off the symbolic execution of `gcd`. When the symbolic execution completes, I extract the resulting state. `angr` builds this state by merging all returning paths through the program. Next, I assert that the return value of my `gcd` call must be `0x3a`. The last step is to ask the SMT solver -- `z3` in this case -- to find a satisfying `arg1` and `arg2` to the constraints defined in the symbolic state.

I was happy to see that `angr` could reason about this `gcd` function as a successful symbolic execution required `angr` to do frequent state merging and reason about symbolic termination. The reason I began symbolic execution at `gcd` instead of `gcd_test`, however, is because `angr` is not as good at reasoning about things like `atoi` and `strlen`. Both of these functions are used in `gcd_test` to convert the string arguments into integers for `gcd`. With these `SimProcedures` -- as `angr` calls them -- a common strategy is to evaluate the input arguments into concrete values, run the procedure, then continue simulating from the concrete state. This is not ideal for our analysis and given the choice between writing a fully symbolic `SimProcedure` or working backwards through `atoi`, I chose the latter. 

```
% ./kingdom 174 116 `python -c "print ' '.join(['a']*(0xb-2))"`
Run Program Correctly Wall destroyed...please continue (0/10)
174, 116, 58GCD Wall destroyed - 2 achievments awarded...please continue (2/10)
```
*Figure 5.* Passing `2` achievements of `10`.

### AES Key Expansion

For this next wall, I attempted to symbolically execute `malicious_aes_test`, called from `main` in *Figure 1*. This function requires the player to reverse a key that has undergone the AES key expansion procedure. I set up a script as in *Figure 6*.

```python
def wall2():
  #setup the key to expand
  logger.info("setting up sym args")
  key = claripy.BVS('key', 8*16)
  keyarr = [key.get_byte(i) for i in range(16)]
  #Make sure angr only uses 1 solver
  s = p.factory.blank_state(remove_options={angr.options.COMPOSITE_SOLVER})
  s.add_constraints(*[k!='\0' for k in keyarr])

  logger.info("starting symbolic execution on aes") 
  aes_addr = p.loader.find_symbol('malicious_aes_test').rebased_addr
  aes = p.factory.callable(aes_addr, base_state=s)
  #when calling the function, use the python list so angr makes a pointer
  r = aes(keyarr)
  s = aes.result_state
  s.add_constraints(r==3)
  
  # CONTINUED IN FIGURE 10.
```
*Figure 6*. Attempting to solve the _Malicious AES Wall_.

Unfortunately, this code did not pass the "Coffee Test". The "Coffee Test" describes when you begin a symbolic execution or SAT query, get up from the computer to get a cup of coffee and return to see whether your query has completed or not. If it has not completed, it is unlikely to complete in a reasonable amount of time.

To discover the issue, I enabled `DEBUG` logging on `angr`. I found that the symbolic execution would spend an extraordinary time in the solver after the block ending at address `0x00403855`. This block does quite a few things, but intuition (and a bit of nudging from my adviser) told me the issue would be symbolic look-ups into the AES substitution-box. This table has the symbol `Te4` in this binary. The problem instruction is replicated in *Figure 7*. Four instructions in the problem block take the same form.

```
0040378c 8b 04 85        MOV        EAX,[Te4 + RAX*0x4]
         a0 90 60 00
```
*Figure 7*. The symbolic addressing in `malicious_aes_test`.

So I needed a better way to do the symbolic execution for this instruction. Fortunately, `angr` allows me to overwrite any arbitrary part of the execution with my own python code. I had to sleep on the problem for a day to come up with how I could be more efficient than `angr`, though. The solution I thought of was to compare `angr`'s symbolic addressing to another symbolic execution engine named `cryptol`. I chose this platform because someone had already programmed the AES key expand algorithm in their domain specific language. `cryptol` was easily able to reverse the key expansion and did so in a matter of seconds. *Figure 8* demonstrates this experiment.

```cryptol
AES> :sat \key -> join (join (transpose (ExpandKey key).2)) == 0x048a97a0ac9a53b7d37fd65b15cf1362
  0x414348494556454d454e544157415244 = True
(Total Elapsed Time: 9.497s, using Z3)
```
*Figure 8*. Reversing AES key expansion. The solver returned in 9.497 cpu seconds.

By running `:s prover=offline`, I had `cryptol` dump the `smtlib2`. `cryptol` builds a `z3.Function` that accepts an 8-bit bit-vector as an argument and returns an 8-bit bit-vector. The benefit to building the sbox table this way is that `z3.Function`s support symbolic arguments. Apparently, it does this much more efficiently than `angr`. I should provide one final note on `cryptol` before I continue. The fact that `cryptol` can perform this reversal so quickly is not a fair comparison to `angr` because someone had to write `cryptol` code for the AES Key Expansion procedure. `angr` lifts binary code and does analysis on that. This almost always results in a significantly more complicated problem than hand-written formal verification code. In order to solve this AES wall with `cryptol`, I would have to re-write the entire AES Key Expansion procedure. For `angr`, on the other hand, I only need to overwrite the `MOV` in *Figure 7*.

```python
def Te4_lookup(s):
  #use the global list to save offset/result pairs
  t = s.globals.get('table_lookups',[])
  #do some logging
  count = len(t)
  logger.info("Te4 inject at %s:%s.", count/4, hex(s.addr)[2:].replace('L',''))
  #only 256 options for the offset (from AL)
  offset = s.regs.rax[7:0]
  #make a new bv and assert that it equals the collected AST (save space in the list)
  index = claripy.BVS("idx{}".format(count),8)
  s.add_constraints(index==offset)
  #make a new result array (just the same byte repeated 4 times)
  result = claripy.BVS("res{}".format(count),8)
  s.regs.rax = reduce(lambda a,x: a.concat(x), 
            repeat(result,3), 
            result).zero_extend(32)
  #save the tuple for later assertions (in a z3.Function)
  t.append((index,result))
  s.globals['table_lookups'] = t

#these instructions are a symbolic table read from Te4. they look like:
# 0040378c  8b 04 85      MOV  EAX,[Te4 + RAX*0x4]
#     a0 90 60 00
p.hook(0x0040378c, Te4_lookup, length=7)
p.hook(0x004037a5, Te4_lookup, length=7)
p.hook(0x004037bb, Te4_lookup, length=7)
p.hook(0x004037d1, Te4_lookup, length=7)
```
*Figure 9*. Overwriting the symbolic table look-ups.

Because `angr` does not directly support `z3.Function`s, I had to do something a little tricky. *Figure 9* shows that when I get to one of the problem instructions, I create a new, unconstrained, symbolic, 8-bit bit-vector named `result`. I set `rax`'s value to `result` repeated four times. Finally, I save the table `index` bit-vector and `result` bit-vector so that I can assert the table values later. Asserting them during symbolic execution causes `angr` to error because it does not know how to handle a `z3.Function` during it's simplification procedures. 

```python
  #now we are going to use the tuples generated by Te4_lookup
  # we will build a z3 function then use a symbolic index
  # this is much faster than state.memory.load with a symbolic addr
  z3_table = z3.Function("Te4", z3.BitVecSort(8), z3.BitVecSort(8))
  #there is only one solver because we specified no composite solver option
  z3_solver = s.solver._solver._get_solver()
  #extract the Te4 table from program memory and turn it into a z3 func
  Te4 = p.loader.find_symbol("Te4").rebased_addr
  for i in range(256):
    z3_solver.add(z3_table(i)==s.mem[Te4+i*4].uint8_t.concrete)
  #for each tuple saved in Te4_lookup, convert to z3 bv then 
  # assert that the index and result are related via the z3 function
  for e in s.globals['table_lookups']:
    idx, res = map(claripy.backends.z3.convert, e)
    z3_solver.add(z3_table(idx)==res)
  #ensure the problem is sat
  logger.info("Checking satisfiability")
  query = z3_solver.check()
  logger.info(query)
  assert(query==z3.sat)
  logger.info("Getting model")
  m = z3_solver.model()
  #make our function's input a z3 bv
  z3key = claripy.backends.z3.convert(key)
  def long_to_str(l):
    return hex(l)[2:].replace('L','').decode('hex')
  resolved_key = long_to_str(m[z3key].as_long())
  logger.info("KEY: %s", repr(resolved_key))
  # KEY: 'ACHIEVEMENTAWARD'
  return [resolved_key]
```
*Figure 10*.  Additional code for the `wall2` function defined in *Figure 6*.

In *Figure 10* I revisit `wall2` to assert information about pairs saved during `Te4_lookup`. First, with the help of some folks at angr.slack.com, I extract the `z3` solver object. Next, I define a `z3.Function` for all possible 8-bit inputs: our sbox table. Then for each `idx`, `res` combination saved during `Te4_lookup` I assert that `table[idx]==res`. Again, this works because `z3.Function`s allow a symbolic argument. Finally, I check if the solver's clauses are satisfiable and extract my key from the resulting model.

```
% python solve.py
INFO    | 2018-05-15 13:31:57,302 | solve.py | setting up sym args
INFO    | 2018-05-15 13:31:57,309 | solve.py | starting symbolic execution on aes
INFO    | 2018-05-15 13:32:01,868 | solve.py | Checking satisfiability
INFO    | 2018-05-15 13:32:06,739 | solve.py | sat
INFO    | 2018-05-15 13:32:06,740 | solve.py | Getting model
INFO    | 2018-05-15 13:32:06,740 | solve.py | KEY: 'ACHIEVEMENTAWARD'
% ./kingdom 174 116 ACHIEVEMENTAWARD `python -c "print ' '.join(['a']*(0xb-3))"`
Run Program Correctly Wall destroyed...please continue (0/10)
174, 116, 58GCD Wall destroyed - 2 achievments awarded...please continue (2/10)
Malicious AES Wall destroyed - achievment awarded...please continue (3/10)
Symbolic Termination Wall destroyed - achievment awarded...please continue (4/10)
Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (6/10)
Advanced_Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (8/10)
```
*Figure 11*.  `angr` passes the _Malicious AES Wall_ in 11.712 cpu seconds. This with the additional _a_'s brings us to `8` out of `10` achievements solved.

### Achievements 4 through 9

As demonstrated in *Figure 11*, my very simple fuzzing (all _a_'s) got us through some fairly tricky challenges. I did not test `angr`'s performance on these due to the significant time investment in the _Malicious AES Wall_. For the 9th achievement, I looked at the `exploitmealso` function symbol. To pass achievement `9` of `10`, `exploitmealso` must return `B`. It is immediately apparent to me that this function copies its arguments into a 1-byte buffer, and the return value is stored above this buffer on the stack. Without much more analysis, I tried passing a few `B`s and passed the wall.

```
% ./kingdom 174 116 ACHIEVEMENTAWARD `python -c "print ' '.join(['a']*5+['B'*5]+['a']*2)"`
Run Program Correctly Wall destroyed...please continue (0/10)
174, 116, 58GCD Wall destroyed - 2 achievments awarded...please continue (2/10)
Malicious AES Wall destroyed - achievment awarded...please continue (3/10)
Symbolic Termination Wall destroyed - achievment awarded...please continue (4/10)
Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (6/10)
Advanced_Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (8/10)
Exploit Chaining Wall destroyed - achievment awarded...please continue (9/10)
```
*Figure 12*. Passing achievements `9` of `10`.

### Program Synthesis

The last challenge of kingdom is to get z3 to write a program for me. The function symbol for this wall is `crc32_test` and it turns out it wants me to provide a program that generates the `crc32` table. *Figure 13* shows the four functions we have at our disposal. 

```c
void R1_shiftl_1(program_state *curr_state){
  curr_state->R1 = curr_state->R1 * 2;
}
void R1_shiftl_24(program_state *curr_state){
  curr_state->R1 = curr_state->R1 << 0x18;
}
void R2_equals_R1_and_0x80000000(program_state *curr_state){
  curr_state->R2 = curr_state->R1 & 0x80000000;
}
void if_R2_le_zero_R1_equals_R1_xor_R3_else_R1(program_state *curr_state){
  if (curr_state->R2 != 0) {
    curr_state->R1 = curr_state->R1 ^ curr_state->R3;
  }
}
```
*Figure 13*. The four basic blocks for our program.

I tried to point `angr` at `crc32_test` and unfortunately it couldn't even reason about a single symbolic byte. So instead I devised a scheme to glue the four basic blocks together myself. *Figure 14* shows my code to run a symbolic program. I start by setting up the four `uint32_t` values within the `program_state` struct.  For each 8-bit symbolic instruction, I call each of the 4 building block instructions. Every time I call a function, I merge the resulting state into `s` on the condition that the symbolic instruction is the building block function's assigned byte-code. Once all instructions are finished, I return the `R1` value in the `program_state`.

```python
def run_program(s, R1_start, instructions):
	#initialize the program_state struct
	s.mem[program_state_addr+0x0].uint32_t = R1_start
	s.mem[program_state_addr+0x4].uint32_t = 0
	s.mem[program_state_addr+0x8].uint32_t = 0x4c11db7
	s.mem[program_state_addr+0xc].uint32_t = 0
	#go through each instruction, trying each possible function
	for instr in instructions:
		logger.debug("On instruction: %s", instr)
		#set the functions' base_state to the currently collected state
		functions = [p.factory.callable(x,base_state=s) for x in addrs]
		for i, f in enumerate(functions):
			#run the function with the program_state's address as an arg
			f(program_state_addr)
			#merge the resulting state into the collector state
			# only use this state's values if the instruction at this
			# position was the one matching the current function
			s = s.merge(f.result_state, 
				merge_conditions=[[instr!=str(i)],[instr==str(i)]])[0]
	#return the value in R1
	return s.mem[program_state_addr].uint32_t.resolved
```
*Figure 14*. This function runs a set of symbolic instructions given a concrete starting state.

The function in *Figure 14* does something subtle but nice for my analysis. The state merging allows me to only inspect the `program_state` memory once all instructions are completed. *Figure 15* shows that I require no program run can modify the state that collects our program output assertions (held in `c_state`). This ensures that each `run_program` call is independent and _SIGNIFICANTLY_ faster than if a single, continuously updated state held the constraints for all runs.

```python
#c_state will collect all the goal constraints for our final eval
c_state = start_state.copy()
for R1_start, goal in rounds:
	logger.info("START: %x, GOAL: %x", R1_start, goal)
	#run the program being sure not to modify the starting state
	# but also using the same set of instructions as every other
	# starting R1 value
	r = run_program(start_state.copy(), R1_start, instructions)
	#assert the result must be our goal value
	c_state.add_constraints(r==goal)
```
*Figure 15*. Shows the code that calls `run_program`. After 175.19 cpu seconds, `angr` solved wall the program synthesis wall.

```
% time python wall7.py
INFO    | 2018-05-16 21:02:01,003 | wall7.py | START: 0, GOAL: 0
INFO    | 2018-05-16 21:02:06,897 | wall7.py | START: 48, GOAL: 128e9dcf
INFO    | 2018-05-16 21:02:28,353 | wall7.py | START: 58, GOAL: 5e9f46bf
INFO    | 2018-05-16 21:02:52,426 | wall7.py | START: c0, GOAL: 5d8a9099
INFO    | 2018-05-16 21:03:15,321 | wall7.py | START: ff, GOAL: b1f740b4
INFO    | 2018-05-16 21:03:38,293 | wall7.py | Asking z3 for a satisfying program.
INFO    | 2018-05-16 21:04:01,686 | wall7.py | GOT: 1203203203203203203203203
INFO    | 2018-05-16 21:04:01,687 | wall7.py | Running sanity check for program synthesis
INFO    | 2018-05-16 21:04:04,059 | wall7.py | R1:       0
INFO    | 2018-05-16 21:04:04,059 | wall7.py | Goal was: 0
INFO    | 2018-05-16 21:04:06,147 | wall7.py | R1:       128e9dcf
INFO    | 2018-05-16 21:04:06,148 | wall7.py | Goal was: 128e9dcf
INFO    | 2018-05-16 21:04:08,257 | wall7.py | R1:       5e9f46bf
INFO    | 2018-05-16 21:04:08,257 | wall7.py | Goal was: 5e9f46bf
INFO    | 2018-05-16 21:04:10,356 | wall7.py | R1:       5d8a9099
INFO    | 2018-05-16 21:04:10,356 | wall7.py | Goal was: 5d8a9099
INFO    | 2018-05-16 21:04:12,501 | wall7.py | R1:       b1f740b4
INFO    | 2018-05-16 21:04:12,501 | wall7.py | Goal was: b1f740b4
INFO    | 2018-05-16 21:04:12,501 | wall7.py | PROGRAM: 1203203203203203203203203
python wall7.py  134.62s user 0.86s system 100% cpu 2:15.19 total
% ./kingdom 174 116 ACHIEVEMENTAWARD a a a a a BBB 1203203203203203203203203 a
Run Program Correctly Wall destroyed...please continue (0/10)
174, 116, 58GCD Wall destroyed - 2 achievments awarded...please continue (2/10)
Malicious AES Wall destroyed - achievment awarded...please continue (3/10)
Symbolic Termination Wall destroyed - achievment awarded...please continue (4/10)
Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (6/10)
Advanced_Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (8/10)
Exploit Chaining Wall destroyed - achievment awarded...please continue (9/10)
Program Synthesis Wall destroyed - achievment awarded...please continue (10/10)
All walls destroyed - YOU WIN!
```
*Figure 16*.  `10` of `10` achievements passed!

### Conclusion

`angr` made the _Malicious AES Wall_ much easier than manually reversing the math done during key expansion. It solved _GCD_ quickly once I started past the `atoi` and `strlen` calls. I'm not sure I could have ever solved the program synthesis wall by myself and `angr` failed solving the wall by itself. Overall, the combination of manual analysis and automated analysis was more effective than either alone.
