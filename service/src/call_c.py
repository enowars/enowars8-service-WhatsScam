import subprocess
import datetime
import logging
#from gmpy2 import is_prime

#done in dockerfile
def compile_c_program():
    result = subprocess.run(["gcc", "-o", "src/key_gen", "src/key_gen.c", "-lgmp"], capture_output=True, text=True)
    if result.returncode == 0:
        print("Compilation successful.")
    else:
        print(f"Compilation failed:\n{result.stderr}")
        exit(1)

def run_c_program():
    command = "./src/key_gen"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if stderr:
        print(f"Errors encountered:\n{stderr.decode('utf-8')}")
        return None, None

    output = stdout.decode('utf-8').strip().split('\n')
    output = list(output)
    return output[0],output[1]

def get_prime_from_c():
    while True:
        p, q = run_c_program()
        p = int(p)
        q = int(q)
        return p,q




