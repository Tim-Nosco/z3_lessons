from shared import *

p = angr.Project('12_angr_veritesting')

s = p.factory.entry_state()
sm = p.factory.simgr(s, veritesting=True)

def goal(state):
	return "Good Job" in state.posix.dumps(1)
logger.info("Starting SYMEXEC")
sm.explore(find=goal)
logger.info("SM: %s", sm)

if sm.found:
	run_bin(p.filename, sm.found[0].posix.dumps(0))

hook(locals())

"""
undefined4 main(undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  int iVar2;
  int in_GS_OFFSET;
  int local_44;
  int local_40;
  char local_35 [33];
  int local_14;
  undefined *local_10;
  
  local_10 = &param_1;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  memset(local_35,0,0x21);
  printf("Enter the password: ");
  __isoc99_scanf("%32s",local_35);
  local_44 = 0;
  local_40 = 0;
  while (local_40 < 0x20) {
    cVar1 = local_35[local_40];
    iVar2 = complex_function(0x4b,local_40 + 0x5d);
    if ((int)cVar1 == iVar2) {
      local_44 = local_44 + 1;
    }
    local_40 = local_40 + 1;
  }
  if ((local_44 == 0x20) && ((char)local_14 == 0)) {
    puts("Good Job.");
  }
  else {
    puts("Try again.");
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
"""