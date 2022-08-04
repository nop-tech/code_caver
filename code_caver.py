import pykd, sys, argparse 

prot_constants = [0x20, 0x40]	# Protection constants to check if the memory region is executable
running_addr = 0				# Used to skip the current code cave (recursion yay)


def analyze_cave(start_addr):
	global running_addr
	flag = True					# Used to find the end of the code cave
	counter = 0					# Used to move through the memory region
	while flag:
		out = pykd.dbgCommand('dd ({0} + 4 * 0n{1}) L4'.format(start_addr, counter))		# Display the memory region
		counter = counter + 1 																# Move forward in the memory region
		if not '00000000 00000000 00000000 00000000' in out:								# Checks if the region stores data
			flag = False																	# If it does, the flag will be inverted and the loop ends
			out = pykd.dbgCommand('dd ({0} + 4 * 0n{1}) L4'.format(start_addr, counter - 1))	# Obtain the end of the code cave
			running_addr = int(out.split('  ')[0], 16)										# Obtain the end addr of the code cave in order to move on to the next one
	code_cave_size = (counter + 1 ) * 4														# Calculate the code cave size using the counter
	pykd.dprintln('[!] Code cave found at address {0} with a size of {1} bytes'.format(start_addr, code_cave_size))


def vprot(addr):
	out = pykd.dbgCommand('!vprot {0}'.format(addr))
	out = out.split('Protect:           ')[1].split(' ')[0]			# Obtain the hex value of the protection value
	try:
		out = int(out, 16)											# Convert the string to int base 16
	except Exception as e:
		pykd.dprintln(e)
	
	if out in prot_constants:										# If the memory region is executable -> return the address
		analyze_cave(addr)


def analyze(input):
	out_arr = input.split('\n')
	for x in out_arr:
		if '00000000 00000000 00000000 00000000' in x:				# Check if the region is empty
			vprot(x.split('  ')[0])							# If it is, move to vprot() in order to analyze it further		

			
def looper(start, end):												# This method is used in order to skip a code cave if one is found
	global running_addr												# So that the script does not analyze the same cave multiple times
	for address in range(start, end, 0xA):
		if running_addr != 0:
			tmp = running_addr
			running_addr = 0
			looper(tmp, end)
			return
		out = pykd.dbgCommand('dd {0} L100'.format(hex(address)))
		analyze(out)


def print_welcome_message():
	pykd.dprintln('''
		            ▄▄                                                        
                        ▀███                                                        
                          ██                                                        
 ▄██▀██   ▄██▀██▄    ▄█▀▀███   ▄▄█▀██       ▄██▀██  ▄█▀██▄ ▀██▀   ▀██▀  ▄▄█▀██ ▀███▄███ 
██▀  ██  ██▀   ▀██ ▄██    ██  ▄█▀   ██     ██▀  ██ ██   ██   ██   ▄█   ▄█▀   ██  ██▀ ▀▀ 
██       ██     ██ ███    ██  ██▀▀▀▀▀▀     ██       ▄█████    ██ ▄█    ██▀▀▀▀▀▀  ██     
██▄    ▄ ██▄   ▄██ ▀██    ██  ██▄    ▄     ██▄     ▄█   ██     ███     ██▄    ▄  ██     
 █████▀   ▀█████▀   ▀████▀███▄ ▀█████▀      █████▀ ▀████▀██▄    █       ▀█████▀  ████▄   
                                                                                  
                                                                                  
 											written by nop
 											-> https://nop-blog.tech/
 											-> https://github.com/nop-tech/
 											-> https://twitter.com/thenopcode
		''')


def main():
	parser = argparse.ArgumentParser(description='Search for code coves in loaded modules / the binary')
	parser.add_argument('start', metavar='startvalue', type=str, help='Enter the start address of the module')
	parser.add_argument('end', metavar='endvalue', type=str, help='Enter the end address of the module')

	args = parser.parse_args()

	print_welcome_message()

	start = 0
	end = 0

	try:
		start = int(args.start, 16)
		end = int(args.end, 16)
	except Exception as e:
		pykd.dprintln(e)
		sys.exit(0)


	pykd.dprintln('[*] Scanning for code caves in the address range {0} to {1}\n'.format(hex(start), hex(end)))

	looper(start, end)

	pykd.dprintln('\n[*] DONE\n\n')

if __name__ == '__main__':
	main()
