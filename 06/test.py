import unittest
import multiagent
import logging
import z3

class TestBoard(unittest.TestCase):
	def test1(self):
		b = multiagent.Board('b1',3,3)
		s = b.sum_of_adj(1,1)
		logger.debug(s)
		smt = 	z3.BV2Int(z3.Extract(1, 1, b.BV)) +\
				z3.BV2Int(z3.Extract(7, 7, b.BV)) +\
				z3.BV2Int(z3.Extract(3, 3, b.BV)) +\
				z3.BV2Int(z3.Extract(5, 5, b.BV))

		self.assertTrue(z3.simplify(smt==s))

class TestAgent(unittest.TestCase):
	def test1(self):
		a = multiagent.Agent("a",0,0,1,2,3,3)
		logger.debug(a.ensure_path())

class TestMaster(unittest.TestCase):
	def test1(self):
		a = multiagent.Agent("a",0,0,1,2,3,3)
		m = multiagent.Master(a)
		self.assertEqual(m.get_paths(), z3.sat)
	def test2(self):
		a = multiagent.Agent("a",0,0,1,2,3,3)
		b = multiagent.Agent("b",1,0,2,2,3,3)
		m = multiagent.Master(a,b)
		self.assertEqual(m.get_paths(), z3.sat)
	def test3(self):
		a = multiagent.Agent("a",0,0,0,2,3,3)
		b = multiagent.Agent("b",1,0,1,2,3,3)
		c = multiagent.Agent("c",2,0,2,2,3,3)
		m = multiagent.Master(a,b,c)
		self.assertEqual(m.get_paths(), z3.sat)
	def test2(self):
		a = multiagent.Agent("a",0,0,2,2,3,3)
		b = multiagent.Agent("b",2,0,0,2,3,3)
		m = multiagent.Master(a,b)
		self.assertEqual(m.get_paths(), z3.unsat)

if __name__ == '__main__':
	logger = logging.getLogger("test.py")
	logger.setLevel(logging.INFO)
	logging.basicConfig()
	logging.getLogger("multiagent.py").setLevel(logging.WARNING)
	unittest.main()