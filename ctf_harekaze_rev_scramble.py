import angr
import claripy


if __name__ == '__main__':
	proj = angr.Project('./scramble')

	# Lenght of the flag is 38
	flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(38)]
	flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\x00')])

	state = proj.factory.entry_state(args=['./scramble'], stdin=flag, add_options=angr.options.unicorn, remove_options={angr.options.LAZY_SOLVES})
	state.solver.add(flag_chars[0] == ord('H'))
	state.solver.add(flag_chars[1] == ord('a'))
	state.solver.add(flag_chars[2] == ord('r'))
	state.solver.add(flag_chars[3] == ord('e'))
	state.solver.add(flag_chars[4] == ord('k'))
	state.solver.add(flag_chars[5] == ord('a'))
	state.solver.add(flag_chars[6] == ord('z'))
	state.solver.add(flag_chars[7] == ord('e'))
	state.solver.add(flag_chars[8] == ord('C'))
	state.solver.add(flag_chars[9] == ord('T'))
	state.solver.add(flag_chars[10] == ord('F'))
	state.solver.add(flag_chars[11] == ord('{'))
	state.solver.add(flag_chars[-1] == ord('}'))

	for i in flag_chars[11:-1]:
		state.solver.add(i < 127, i > 32)

	sim = proj.factory.simulation_manager(state)
	to_find = 0x737 + proj.loader.main_object.min_addr
	to_avoid = 0x6FB + proj.loader.main_object.min_addr
	sim.explore(find=to_find, avoid=to_avoid)

	try:
		res = str()
		print(sim.found[0].solver.eval(flag))
		for i in flag_chars:
			res+= chr(sim.found[0].solver.eval(i))
		print(res)
	except Exception,e: print str(e)
