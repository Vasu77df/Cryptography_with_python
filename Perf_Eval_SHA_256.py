
import timeit

setup_code = '''
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
'''

evaluation_code = '''
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(bytes(256*1000*1000))
digest.finalize()
'''

if __name__ == "__main__":
    execution_time = timeit.timeit(setup=setup_code, stmt=evaluation_code, number=10)
    performance = 256/execution_time
    print("The speed is {} MB/s".format(performance))
