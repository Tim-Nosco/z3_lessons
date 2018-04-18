from z3 import *

class Master:
	def __init__(self, agents):
		assert(len(agents)>0)
		nrow = agents[0].board.n
		ncol = agents[0].board.m
		assert(all(a.board.n==nrow and a.board.m==ncol for a in agents))
		self.solver = Solver()
		for a in agents:
			self.solver.add(a.ensure_path())
		#ensure no two agents use the same vertex
		total = reduce(lambda acc,agent: acc & agent.board.BV, agents, 0)
		self.solver.add(total==0)


class Agent:
	def __init__(self, name, startr, startc,
							 goalr,  goalc,
							 nrows,  ncolumns):
		self.name  = name
		self.board = Board(name,nrows,ncolumns)
		self.start = lambda x,y: x==startr and y==startc
		self.goal  = lambda x,y: x==goalr  and y==goalc

	def ensure_path(self):
		#return a list of constraints that ensure this agent's path
		final = []
		for row in range self.n:
			for column in range self.m:
				allowed = 2
				if self.start(row,column) or self.goal(row,column):
					allowed = 1
				final.append(self.board.sum_of_adj(row,column) == allowed)
		return final

class Board:
	def __init__(self,name,nrows,ncolumns):
		self.n = nrows
		self.m = ncolumns
		self.total = n*m
		#bitvec to store all sat variables
		self.BV = BitVec("{}_BV".format(name), self.total)
		#make a row adjacency list
		self.rows = map(self.make_row, xrange(self.n))
		#make a column adjacency list
		self.columns = map(self.make_column, xrange(self.m))

	def make_row(self, row):
		return Extract(i+self.m, i, self.BV)

	def make_column(self, column):
		return reduce(lambda a, x: Concat(a, self.get_bit(x, column)),
							xrange(1, self.n),
							self.get_bit(0, column))

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
		return sum(ZeroExt(3, b) for b in bits)