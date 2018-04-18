import logging
from z3 import *

logger = logging.getLogger('multiagent.py')
logger.setLevel(logging.DEBUG)
logging.basicConfig()

def chunks(l, n):
	#(list[int],int) -> list[list[int]]
	for i in range(0,len(l),n):
		yield l[i:i+n]

class Master:
	def __init__(self, *agents):
		self.agents = agents
		assert(len(agents)>0)
		nrow = agents[0].board.n
		ncol = agents[0].board.m
		bsize = agents[0].board.total
		assert(all(a.board.n==nrow and a.board.m==ncol for a in agents))
		self.solver = Solver()
		#set up the agent's constraints
		for a in agents:
			self.solver.add(a.ensure_path())
		#ensure no two agents use the same vertex
		for i in xrange(bsize):
			s = 0
			for a in agents:
				s += BV2Int(Extract(i,i,a.board.BV))
			self.solver.add(s<2)

	def get_paths(self):
		logger.info("Starting z3 call")
		if self.solver.check()==sat:
			logger.info("SAT")
			m = self.solver.model()
			for a in self.agents:
				board = bin(m[a.board.BV].as_long())[2:].zfill(a.board.total)[::-1]
				board = '\n'.join(chunks(board,a.board.n))
				logger.info("AGENT: %s:\n%s",a.name,board)
			return sat
		else:
			logger.info("UNSAT")
			return unsat

class Agent:
	def __init__(self, name, startr, startc,
							 goalr,  goalc,
							 nrows,  ncolumns):
		self.name  = name
		self.board = Board(name,nrows,ncolumns)
		self.start = lambda x,y: x==startr and y==startc
		self.goal  = lambda x,y: x==goalr  and y==goalc

	def ensure_path(self):
		#return a constraint that ensures this agent's path
		final = []
		for row in range(self.board.n):
			for column in range(self.board.m):
				b = self.board.get_bit(row,column)
				s = self.board.sum_of_adj(row, column)
				if self.start(row,column) or self.goal(row,column):
					final.append(b == 1)
					final.append(s == 1)
				else:
					final.append(Implies(b == 1, s == 2))
		return And(*final)

class Board:
	def __init__(self,name,nrows,ncolumns):
		self.n = nrows
		self.m = ncolumns
		self.total = nrows*ncolumns
		#bitvec to store all sat variables
		self.BV = BitVec("{}_BV".format(name), self.total)

	def location(self, row, column):
		return column+(self.m*row)

	def get_bit(self, row, column, default=BitVecVal(0, 1)):
		r = default
		if row >= 0 and row < self.n and column >= 0 and column < self.m:
			loc = self.location(row, column)
			r = Extract(loc, loc, self.BV)
		return r

	def sum_of_adj(self, row, column):
		bits = [self.get_bit(row-1, column),
				self.get_bit(row+1, column),
				self.get_bit(row, column-1),
				self.get_bit(row, column+1)]
		return sum(map(BV2Int, bits))