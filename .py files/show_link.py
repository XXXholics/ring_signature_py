import random, sys
from hashlib import sha256, sha3_256

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

# returns the index of public key y in keys_list
def get_real_key_position(keys_list, y):
    public_key_list = [key[1] for key in keys_list]
    return public_key_list.index(y)

def sign(msg, Y, g, r, p, keys_list, x_real, y_real):
    idx = (get_real_key_position(total_keys_list, y_real) + 1) % len(total_keys_list)
    e_list = [None for _ in range(len(keys_list))]
    sig_list = [None for _ in range(len(keys_list))]
    h = int(sha3_256(str(Y).encode()).hexdigest(), 16)
    y_wave = pow(h, x_real, p)
    e_initial = int(sha256((str(Y) + str(y_wave) +str(msg) + str(pow(g,r,p)) + str(pow(h,r,p))).encode()).hexdigest(), 16)
    e_list[idx] = e_initial
    while keys_list[idx][1] != y_real:
        e_last_one = e_list[idx]
        _, random_sig = generate_keys(g, p)
        sig_list[idx] = random_sig
        temp_y = keys_list[idx][1]
        calculation = (pow(g, random_sig, p)*pow(temp_y, e_last_one, p)) % p
        calculation_1 = (pow(h, random_sig, p)*pow(y_wave, e_last_one, p)) % p
        temp_e = int(sha256((str(Y) + str(y_wave) +str(msg) + str(calculation) + str(calculation_1)).encode()).hexdigest(), 16)
        idx = (idx + 1) % len(total_keys_list)
        e_list[idx] = temp_e
        
    # q is the order for p, see paper page 6, part 4, the first sentence. 
    q = p - 1
    s_real = (r - x_real * e_list[idx]) % q
    sig_list[idx] = s_real
    public_key_list = [key[1] for key in keys_list] 
    total_res = {
        'e1': e_list[0],
        'sig_list': sig_list,
        'public_key_list': public_key_list,
        'tag': y_wave,
        'msg': msg,
        'e_list': e_list
    }
    return total_res

def verify(total_res):
    public_key_list = total_res['public_key_list']
    Y = ''.join([str(i) for i in public_key_list])
    h = int(sha3_256(str(Y).encode()).hexdigest(), 16)

    sig_list = total_res['sig_list']
    temp_e_V = e1 = total_res['e1']
    msg = total_res['msg']
    tag = total_res['tag']
    
    for i in range(len(sig_list)):
        # print('temp_e_V:',  temp_e_V)
        temp_sig = sig_list[i]
        temp_y = public_key_list[i]
        calculation = (pow(g, temp_sig, p)*pow(temp_y, temp_e_V, p)) % p
        calculation_1 = (pow(h, temp_sig, p)*pow(tag, temp_e_V, p)) % p
        temp_e_V = int(sha256((str(Y) + str(tag) + str(msg) + str(calculation) + str(calculation_1)).encode()).hexdigest(), 16)
    
    # print(e1)
    # print(temp_e_V)
    # print(temp_e_V == e1) 

    if (temp_e_V == e1):
        print("Verified")
    else:
        print("Not verified")

# function to generate n random secret and public keys
def generate_n_random_keys(n):
    keys_list = []
    for _ in range(n):
        x_temp, y_temp = generate_keys(g, p)
        keys_list.append([x_temp, y_temp])
    return keys_list

# append secret key x and public key y to keys_list and shuffles they keys
def concat_and_shuffle_total_keys(keys_list, x, y):
    keys_list.append([x, y])
    random.shuffle(keys_list)
    return keys_list

# concatenate all the public keys into a string
def get_Y(keys_list):
    public_key_list = [key[1] for key in keys_list]
    Y = ''.join([str(i) for i in public_key_list])
    return Y

# generates and returns separated secret and public keys
def get_initial_random_r_and_R(g, p):
    r, R = generate_keys(g, p)
    return r, R

def display_tag_link(total_res):
    print("For the message:", total_res['msg'])
    print("Public keys list:\n", total_keys_list)
    print("Tag:", total_res['tag'], "\n")

# driver code  
if len(sys.argv) == 6:
    g = int(sys.argv[1])
    p = int(sys.argv[2])
    msg1 = sys.argv[3]
    msg2 = sys.argv[4]
    random_keys_count = int(sys.argv[5])
    random_keys_list = generate_n_random_keys(random_keys_count)
    x_real, y_real = generate_keys(g, p)
    total_keys_list = concat_and_shuffle_total_keys(random_keys_list, x_real, y_real)
    real_key_index = get_real_key_position(total_keys_list, y_real)
    Y = get_Y(total_keys_list)
    r, R = get_initial_random_r_and_R(g, p)

    # sign the first message and list the public keys and associated tag
    total_res = sign(msg1, Y, g, r, p, total_keys_list, x_real, y_real)
    display_tag_link(total_res)

    # sign the second message within the same group, show that the tag remains the same
    total_res = sign(msg2, Y, g, r, p, total_keys_list, x_real, y_real)
    display_tag_link(total_res)

    # put the signer in a new group, show that the tag remains the same
    random_keys_list = generate_n_random_keys(random_keys_count)
    total_keys_list = concat_and_shuffle_total_keys(random_keys_list, x_real, y_real)
    total_res = sign(msg2, Y, g, r, p, total_keys_list, x_real, y_real)
    display_tag_link(total_res)

    # use the same group but new real signer, show that the tag changes
    x_real, y_real = generate_keys(g, p)
    total_keys_list = concat_and_shuffle_total_keys(random_keys_list, x_real, y_real)
    total_res = sign(msg2, Y, g, r, p, total_keys_list, x_real, y_real)
    display_tag_link(total_res)
else:
    print("Try executing program like this: python show_link.py <g> <p> <m1> <m2> <n>\nwhere -s specifies sign mode, -v specifies sign and verify mode, g is a generator, p a large prime, m1 is the first message to be signed, m2 is the second message to be signed and n is the number of signers in the group")