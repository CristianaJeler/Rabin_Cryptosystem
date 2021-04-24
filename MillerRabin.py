from random import randint

MAX_K = 5


def miller_rabin(n):
    # write n-1 as n-1=2^s*t where t is odd
    s = 0
    while True:
        if ((n - 1) / (2 ** s)) % 2 == 0:
            s += 1
        else:
            break
    t = (n - 1) // 2 ** s

    generated_a_values = []
    k = 0

    while True:
        k += 1

        # choose randomly 1<a<n
        # we try to obtain a's that have not been already generated
        #    in the previous iterations
        a = randint(2, n - 1)
        while a in generated_a_values:
            a = randint(2, n - 1)
        generated_a_values.append(a)

        # the sequence containing elements:
        #       a^t, a^(2*t), ..., a^((2^s)*t)
        a_sequence = [int((a ** ((2 ** s_pow) * t)) % n) for s_pow in range(0, s + 1)]

        # if there is a value of 1 in the obtained sequence
        if 1 in a_sequence:
            # case when 1 is on the first position
            if a_sequence[0] == 1:
                # if the max number of repetitions has been reached
                # the number is probably prime
                if k == MAX_K:
                    return True
                # otherwise the number is possibly prime
                # and the algorithm goes to the next loop
                else:
                    continue
            else:
                # if the first 1 found in the sequence is preceded by a value of n-1
                if a_sequence[a_sequence.index(1) - 1] == n - 1:
                    # if the max number of repetitions has been reached
                    # the number is probably prime
                    if k == MAX_K:
                        return True
                    # otherwise the number is possibly prime
                    # and the algorithm goes to the next loop
                    else:
                        continue
        # if there is no value of 1 in the sequence,
        # then the number is composite for sure
        elif 1 not in a_sequence:
            return False