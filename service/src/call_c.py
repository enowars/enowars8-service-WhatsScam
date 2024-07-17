import subprocess

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




