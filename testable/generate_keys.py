import random, sys

# function to create s (secret key) and v (public key) with given g (generator) and p (prime mod)  
def generate_keys(g, p):

    # full prime check is expensive
    if (p < 3):
        return "The second argument, p, must be greater than 2!"

    # secret key s
    s = random.randint(1, p-2)

    # public key = g^s mod p
    v = pow(g, s, p)

    return s, v


# driver code
if len(sys.argv) == 3:
    g = int(sys.argv[1])
    p = int(sys.argv[2])
    print(generate_keys(g, p))
else:
    print("Execute the code like this: python generate_keys.py <g> <p>\nwhere g is a generator and p a large prime")