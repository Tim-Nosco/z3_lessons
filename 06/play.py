from multiagent import *
# a = Agent("A",0,0,8,8,9,9)
# b = Agent("B",0,1,0,8,9,9)
# print Master(a,b).get_paths()

n = 20
Master(*[Agent(str(i),i,0,i,n-1,n,n) for i in range(n)]).get_paths()
