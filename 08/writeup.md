
### Introduction. 

The problem I considered for this exercise was kingdom: a crafted non-stripped binary designed to test symbolic execution engines. The binary contains a series of "walls" that must be solved sequentially. To the best of my knowledge, no tool has been able to automatically solve the challenges starting with only the binary code. I used a combination of automation and static analysis to work through each wall.

### Survey. 

The first thing I did when auditing kingdom was to look at the decompilation. *Figure 1* shows the natural auditing start point, `main`.

```c
int main(int argc,char **argv)

{
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
        uVar2 = termination_test(argv[4]);
        if (uVar2 == 3) {
          fprintf(stderr,
                  "Symbolic Termination Wall destroyed - achievment awarded...please continue(%u/%u)\n"
                  ,4,10);
          uVar2 = control_flow_test(argv[5],argv[6]);
          if (uVar2 == 3) {
            fprintf(stderr,
                    "Control Flow Merging Wall destroyed - 2 achievments awarded...please continue(%u/%u)\n"
                    ,6,10);
            uVar2 = advanced_control_flow_test(argv[7],argv[8]);
            if (uVar2 == 3) {
              fprintf(stderr,
                      "Advanced_Control Flow Merging Wall destroyed - 2 achievmentsawarded...please continue (%u/%u)\n"
                      ,8,10);
              uVar4 = strlen(argv[9]);
              if (uVar4 < 3) {
                iVar3 = 2;
              }
              else {
                cVar1 = argv[9][2];
                argv[9][2] = 0;
                uVar2 = exploitmealso(argv[9]);
                if (uVar2 == 'B') {
                  argv[9][2] = cVar1;
                  fprintf(stderr,
                          "Exploit Chaining Wall destroyed - achievment awarded...please continue(%u/%u)\n"
                          ,9,10);
                  uVar2 = crc32_test(argv[10]);
                  if (uVar2 == 3) {
                    fprintf(stderr,
                            "Program Synthesis Wall destroyed - achievment awarded...pleasecontinue (%u/%u)\n"
                            ,10,10);
                    fwrite("All walls destroyed - YOU WIN!\n",1,0x1f,stderr);
                    exploitme(argv[0xb]);
                    iVar3 = 3;
                  }
                  else {
                    iVar3 = 2;
                  }
                }
                else {
                  iVar3 = 2;
                }
              }
            }
            else {
              if (uVar2 == 4) {
                exploitme(argv[0xb]);
              }
              iVar3 = 2;
            }
          }
          else {
            if (uVar2 == 4) {
              exploitme(argv[0xb]);
            }
            iVar3 = 2;
          }
        }
        else {
          if (uVar2 == 4) {
            exploitme(argv[0xb]);
          }
          iVar3 = 2;
        }
      }
      else {
        iVar3 = 2;
      }
    }
    else {
      iVar3 = 2;
    }
  }
  else {
    iVar3 = 2;
  }
  return iVar3;
}
```
*Figure 1.* The main function of kingdom.

Immediately apparent in `main` is the requirement that `argv` must have `0xc` many elements: `argc==0xc`. Running the program as in *Figure 2* causes us to get past this check.

```
% ./kingdomv2 `python -c "print ' '.join(['a']*0xb)"`
Run Program Correctly Wall destroyed...please continue (0/10)
```
*Figure 2.* Passing wall `0` of `10`.

### Wall 1.

For this wall, I had to reason about the function symbol `gcd_test`. This function takes two arguments and converts them to integers. It asserts that neither are equal to `0x3a` and that the second is not equal to `0`.  Then `gcd_test` calls a new symbol, `gcd` on the converted arguments. If the return value of `gcd` is `0x3a`, we print the string "_GCD Wall destroyed ..._" from *Figure 1*.

```c
uint8_t gcd(uint8_t a,uint8_t b)
{
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
  gcd = p.factory.callable(gcd_addr, base_state=s)
  logger.info("starting symbolic execution: gcd(%s, %s)",arg1,arg2)
  r = gcd(arg1,arg2)
  s = gcd.result_state
  s.add_constraints(r==0x3a)
  logger.info("evaluating arguments")
  return map(str,(s.solver.eval(arg1), s.solver.eval(arg2))
```
*Figure 4.* The `angr` solution to the gcd wall. After 15.798 cpu seconds, `angr` returns the results `174` and `116`.

In the function shown in *Figure 4*, I first define two 8-bit symbolic bit vectors called `arg1` and `arg2`. Then I create an empty state object from which I will begin symbolic execution. I assert that neither `arg1` nor `arg2` can be the trivial solution `0x3a`. Next, I find the `gcd` function in the kingdom binary and wrap it in a python callable object. `gcd(arg1,arg2)` kicks off the symbolic execution of `gcd`. When the symbolic execution completes, I extract the resulting state. `angr` builds this state by merging all returning paths through the program. Next, I assert that the return value of my `gcd` call must be `0x3a`. The last step is to ask the SMT solver -- `z3` in this case -- to find a satisfying `arg1` and `arg2` to the constraints defined in the symbolic state.

I was happy to see that `angr` could reason about this `gcd` function as a successful symbolic execution required `angr` to do frequent state merging and reason about symbolic termination. The reason I began symbolic execution at `gcd` instead of `gcd_test`, however, is because `angr` is not as good at reasoning about things like `atoi` and `strlen`. Both of these functions are used in `gcd_test` to convert the string arguments into integers for `gcd`. With these `SimProcedures` -- as `angr` calls them -- a common strategy is to evaluate the input arguments into concrete values, run the procedure, then continue simulating from the concrete state. This is not ideal for our analysis and given the choice between writing a fully symbolic `SimProcedure` or working backwards through `atoi`, I chose the latter. 
