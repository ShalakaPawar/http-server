import constraint

problem = constraint.Problem()

#input
N = int(input("Enter the value of N : "))

#Make N list
range_list = []
for i in range(1,N+1):
	range_list.append(i)
	
# make dictionary of size N
d = {}
for i in range(0, N):
	d[chr(i+65)] =  range_list

#constraint function
def condition(*argv):
	flag = True
	for i in range(0, len(argv)):
		fg = 1
		for j in range(i+1, len(argv)):
			if((argv[i] == argv[j]) or (abs(i - j) == abs(argv[i] - argv[j]))):
				fg = 0
				flag = False
				break
			if(fg == 0):
				break	 	
	
	if(flag == False):
		return flag
	else:
		return True	


ip = ""			
problem = constraint.Problem()

#problem.addvariable
for key, value in d.items():
	problem.addVariable(key, value)
	ip = ip + key

#problem.addconstraint
problem.addConstraint(condition,ip)

	
	
solutions = problem.getSolutions()

n = 0
print("\n")
for solution in solutions:
	n = n + 1
	print("Solution : ",n)
	print("Row        Column")
	i = 0
	for key, value in solution.items():
		print(i+1,"          ", value)
		i = i + 1
	print("\n")
	
	
	
	
	
		
			
			
			
			
