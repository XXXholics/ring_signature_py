import random, sys

# checks if g is a primitive root of p, returns boolean
def is_primitive_root(g, p):
    n = p - 1
    factors = []
    i = 2
    while i * i <= n:
        if n % i == 0:
            factors.append(i)
            while n % i == 0:
                n //= i
        i += 1
    if n > 1:
        factors.append(n)

    for factor in factors:
        if pow(g, (p-1) // factor, p) == 1:
            return False
    return True

# function to create s (secret key) and v (public key) with given g (generator) and p (prime mod)  
def generate_keys(g, p):

    # full prime check is expensive
    if (p < 3):
        return "The second argument, p, must be greater than 2"
    
    # checks if g is a primitive root of p
    if not (is_primitive_root(p, g)):
        return "g must be a primitive root of p"

    # secret key s
    s = random.randint(1, p-2)

    # public key = g^s mod p
    v = pow(g, s, p)

    return s, v

# function to generate n random secret and public keys
def generate_n_random_keys(g, p, n):
    keys_list = []
    for _ in range(n):
        x_temp, y_temp = generate_keys(g, p)
        keys_list.append([x_temp, y_temp])
    return keys_list

# driver code
if len(sys.argv) == 4:
    g = int(sys.argv[1])
    p = int(sys.argv[2])
    n = int(sys.argv[3])
    print(generate_n_random_keys(g, p, n))
else:
    print("Try executing program like this: python generate_keys.py <g> <p> <n>\nwhere g is a generator, p a large prime and n the number of key pairs required")